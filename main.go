package main

import (
	"flag"
	"fmt"
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

func main() {
	var (
		mxAddr        string
		mxName        string
		listeners     multiFlag
		allowListPath string
		reconnect     int
		certPath      string
		keyPath       string
		banner        string
		queueDir      string
	)

	flag.StringVar(&mxAddr, "mxaddr", "",
		"Primary MX IP address and port (required)")
	flag.StringVar(&mxName, "mxname", "",
		"Primary MX name (for TLS validation) (required)")
	flag.Var(&listeners, "listen",
		"Listen on `addr:port`; use brackets for IPv6, e.g. [::1]:25\n\t"+
			"(repeatable; default: 0.0.0.0:25 and [::]:25)")
	flag.StringVar(&allowListPath, "allowlist",
		"", "Path to list of allowed recipients (required)")
	flag.IntVar(&reconnect, "reconnect", 60,
		"Queue retry `interval` in seconds when the queue is non-empty")
	flag.StringVar(&certPath, "cert", "",
		"`Path` to TLS certificate file (.crt) (required)")
	flag.StringVar(&keyPath, "key", "",
		"`Path` to TLS private key file (.key) (required)")
	flag.StringVar(&banner, "banner", "",
		"Hostname announced in the SMTP 220 greeting (required)")
	flag.StringVar(&queueDir, "queue", "/var/spool/smtp-relay",
		"`Directory` used for queue storage")

	flag.Parse()

	// ── Validation ────────────────────────────────────────────────────────────

	var errs []string
	errorf := func(format string, a ...any) {
		errs = append(errs, fmt.Sprintf(format, a...))
	}

	if mxAddr == "" {
		errorf("-mxaddr is required")
	}
	if mxName == "" {
		errorf("-mxname is required")
	}
	if certPath == "" {
		errorf("-cert is required")
	}
	if keyPath == "" {
		errorf("-key is required")
	}
	if banner == "" {
		errorf("-banner is required")
	}
	if allowListPath == "" {
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

	// ── Defaults ──────────────────────────────────────────────────────────────

	if len(listeners) == 0 {
		listeners = multiFlag{"0.0.0.0:25", "[::]:25"}
	}

	// ── Allow List ────────────────────────────────────────────────────────────
	allowList, err := NewAllowList(allowListPath)
	if err != nil {
		log.Fatalf("allowlist: %v", err)
	}

	// ── Message Queue ─────────────────────────────────────────────────────────
	queue, err := NewQueue(queueDir)
	if err != nil {
		log.Fatalf("queue: %v", err)
	}

	// ── Server ────────────────────────────────────────────────────────────────
	// NewServer performs all initialisation that can fail at startup: loading
	// the TLS keypair, creating the queue directory, and binding listeners.
	// Errors here are fatal and indicate misconfiguration.
	srv, err := NewServer(ServerConfig{
		Listeners: []string(listeners),
		AllowList: allowList,
		CertPath:  certPath,
		KeyPath:   keyPath,
		Banner:    banner,
		Queue:     queue,
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	// ── Client ────────────────────────────────────────────────────────────────
	// NewClient validates its configuration but does not attempt a connection;
	// delivery failures are expected and handled inside Client.Run.
	cli, err := NewClient(ClientConfig{
		Queue:       queue,
		MXAddr:      mxAddr,
		MXName:      mxName,
		ImplicitTLS: false,
		RequireTLS:  false,
		TLSInsecure: false,
		RetryDelay:  time.Duration(reconnect) * time.Second,
	})
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	// ── Start ─────────────────────────────────────────────────────────────────

	go srv.Run()
	go cli.Run()

	log.Printf(
		"relay started — listeners: %s | backend: mxaddr=%q mxname=%q port=%d | queue: %s",
		listeners, mxAddr, mxName, queueDir,
	)

	// ── Shutdown ──────────────────────────────────────────────────────────────
	// TODO: propagate cancellation via context to srv.Run and cli.Run for
	// graceful in-flight draining before exit.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	s := <-quit
	log.Printf("received %v, shutting down", s)
}
