package main

import (
	"flag"
	"fmt"
	"go.yaml.in/yaml/v4"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// multiFlag is a flag.Value implementation that accumulates every occurrence
// of a flag into a string slice, enabling flags like -listen that may be
// specified more than once on the command line.
type multiFlag []string

func (m multiFlag) String() string {
	if len(m) == 0 {
		return "(none)"
	}
	out := ""
	for i, v := range m {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

type Config struct {
	MxAddr        string    `yaml:"mxaddr"`
	MxName        string    `yaml:"mxname"`
	Listeners     multiFlag `yaml:"listen"`
	AllowListPath string    `yaml:"allowlist"`
	Reconnect     int       `yaml:"reconnect"`
	CertPath      string    `yaml:"cert"`
	KeyPath       string    `yaml:"key"`
	Banner        string    `yaml:"banner"`
	QueueDir      string    `yaml:"queue"`
}

func readConfig(path string) (Config, error) {
	var cfg Config
	if path == "" {
		return cfg, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	loader, err := yaml.NewLoader(f, yaml.WithKnownFields())
	if err != nil {
		return cfg, err
	}
	err = loader.Load(&cfg)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

func main() {
	log.Printf("Starting %+v", os.Args)
	confPath := ""
	tmpFlagSet := flag.NewFlagSet("tmp", flag.ContinueOnError)
	tmpFlagSet.SetOutput(io.Discard)
	tmpFlagSet.StringVar(&confPath, "config", "",
		"Path to config file")
	tmpFlagSet.Parse(os.Args[1:])

	conf, err := readConfig(confPath)
	if err != nil {
		log.Fatalf("Unable to read configuration: %v", err)
	}

	flag.StringVar(&confPath, "config", "",
		"Path to config file")
	flag.StringVar(&conf.MxAddr, "mxaddr", conf.MxAddr,
		"Primary MX IP address and port (required)")
	flag.StringVar(&conf.MxName, "mxname", conf.MxName,
		"Primary MX name (for TLS validation) (required)")
	flag.Var(&conf.Listeners, "listen",
		"Listen on `addr:port`; use brackets for IPv6, e.g. [::1]:25\n\t"+
			"(repeatable; default: 0.0.0.0:25 and [::]:25)")
	flag.StringVar(&conf.AllowListPath, "allowlist",
		conf.AllowListPath, "Path to list of allowed recipients (required)")
	flag.IntVar(&conf.Reconnect, "reconnect", conf.Reconnect,
		"Queue retry `interval` in seconds when the queue is non-empty")
	flag.StringVar(&conf.CertPath, "cert", conf.CertPath,
		"`Path` to TLS certificate file (.crt) (required)")
	flag.StringVar(&conf.KeyPath, "key", conf.KeyPath,
		"`Path` to TLS private key file (.key) (required)")
	flag.StringVar(&conf.Banner, "banner", conf.Banner,
		"Hostname announced in the SMTP 220 greeting (required)")
	flag.StringVar(&conf.QueueDir, "queue", conf.QueueDir,
		"`Directory` used for queue storage")

	flag.Parse()

	log.Printf("Got config: %+v", conf)

	// == Validation ============================================================

	var errs []string
	errorf := func(format string, a ...any) {
		errs = append(errs, fmt.Sprintf(format, a...))
	}

	if conf.MxAddr == "" {
		errorf("-mxaddr is required")
	}
	if conf.MxName == "" {
		errorf("-mxname is required")
	}
	if conf.CertPath == "" {
		errorf("-cert is required")
	}
	if conf.KeyPath == "" {
		errorf("-key is required")
	}
	if conf.Banner == "" {
		errorf("-banner is required")
	}
	if conf.AllowListPath == "" {
		errorf("-allowlist is required")
	}

	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "error:", e)
		}
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	// == Defaults ==============================================================

	if len(conf.Listeners) == 0 {
		conf.Listeners = multiFlag{"0.0.0.0:25", "[::]:25"}
	}

	if conf.QueueDir == "" {
		conf.QueueDir = "/var/spool/proxmail"
	}

	// == Allow List ============================================================
	allowList, err := NewAllowList(conf.AllowListPath)
	if err != nil {
		log.Fatalf("allowlist: %v", err)
	}

	// == Message Queue =========================================================
	queue, err := NewQueue(conf.QueueDir)
	if err != nil {
		log.Fatalf("queue: %v", err)
	}

	// == Server ================================================================
	// NewServer performs all initialisation that can fail at startup: loading
	// the TLS keypair, creating the queue directory, and binding listeners.
	// Errors here are fatal and indicate misconfiguration.
	srv, err := NewServer(ServerConfig{
		Listeners: []string(conf.Listeners),
		AllowList: allowList,
		CertPath:  conf.CertPath,
		KeyPath:   conf.KeyPath,
		Banner:    conf.Banner,
		Queue:     queue,
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	// == Client ================================================================
	// NewClient validates its configuration but does not attempt a connection;
	// delivery failures are expected and handled inside Client.Run.
	cli, err := NewClient(ClientConfig{
		Queue:       queue,
		MXAddr:      conf.MxAddr,
		MXName:      conf.MxName,
		ImplicitTLS: false,
		RequireTLS:  true,
		TLSInsecure: false,
		RetryDelay:  time.Duration(conf.Reconnect) * time.Second,
	})
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	// == Start =================================================================

	go srv.Run()
	go cli.Run()

	log.Printf(
		"relay started — listeners: %s | backend: mxaddr=%q mxname=%q port=%d | queue: %s",
		conf.Listeners, conf.MxAddr, conf.MxName, conf.QueueDir,
	)

	// == Shutdown ==============================================================
	// TODO: propagate cancellation via context to srv.Run and cli.Run for
	// graceful in-flight draining before exit.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	s := <-quit
	log.Printf("received %v, shutting down", s)
}
