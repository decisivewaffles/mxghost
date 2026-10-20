// Copyright (C) 2026 DecisiveWaffles <decisivewaffles@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"go.yaml.in/yaml/v4"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
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
	MxAddr             string    `yaml:"mxaddr"`
	MxName             string    `yaml:"mxname"`
	MxTimeout          int       `yaml:"mxtimeout"`
	MxStartTLSOptional bool      `yaml:"mxstarttlsoptional"`
	MxSkipTLSVerify    bool      `yaml:"mxskiptlsverify"`
	Listeners          multiFlag `yaml:"listen"`
	AllowListPath      string    `yaml:"allowlist"`
	Reconnect          int       `yaml:"reconnect"`
	RwTimeout          int       `yaml:"rwtimeout"`
	CertPath           string    `yaml:"cert"`
	KeyPath            string    `yaml:"key"`
	Banner             string    `yaml:"banner"`
	QueueDir           string    `yaml:"queue"`
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
	dropUnusedCapabilities()
	confPath := ""
	tmpFlagSet := flag.NewFlagSet("tmp", flag.ContinueOnError)
	tmpFlagSet.SetOutput(io.Discard)
	tmpFlagSet.StringVar(&confPath, "config", "",
		"Path to YAML config file")
	tmpFlagSet.Parse(os.Args[1:])

	conf, err := readConfig(confPath)
	if err != nil {
		log.Fatalf("Unable to read configuration: %v", err)
	}

	var flagListeners multiFlag
	flag.StringVar(&confPath, "config", "",
		"Path to config file")
	flag.StringVar(&conf.MxAddr, "mxaddr", conf.MxAddr,
		"Primary MX IP address and port (required)")
	flag.StringVar(&conf.MxName, "mxname", conf.MxName,
		"Primary MX name (for TLS validation) (required)")
	flag.IntVar(&conf.MxTimeout, "mxtimeout", conf.MxTimeout,
		"Primary MX connection timeout (seconds) before engaging store and forward")
	flag.BoolVar(&conf.MxStartTLSOptional, "mxstarttlsoptional", conf.MxStartTLSOptional,
		"Don't require STARTTLS when draining queue (optional)")
	flag.BoolVar(&conf.MxSkipTLSVerify, "mxskiptlsverify", conf.MxSkipTLSVerify,
		"Skip certificate validation when draining queue (optional)")
	flag.Var(&flagListeners, "listen",
		"Listen on `addr:port`; use brackets for IPv6, e.g. [::1]:25\n\t"+
			"(repeatable; default: 0.0.0.0:25 and [::]:25)\n\t"+
			"NOTE: ignored if env LISTEN_FDS is set (for socket activation)")
	flag.StringVar(&conf.AllowListPath, "allowlist",
		conf.AllowListPath, "Path to list of allowed recipients (required)")
	flag.IntVar(&conf.RwTimeout, "rwtimeout", conf.RwTimeout,
		"Read/write activity timeout (seconds) before closing connection")
	flag.IntVar(&conf.Reconnect, "reconnect", conf.Reconnect,
		"Queue retry `interval` (seconds) when the queue is non-empty (required)")
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
	if conf.QueueDir == "" {
		errorf("-queuedir is required")
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

	if conf.MxTimeout == 0 {
		conf.MxTimeout = 1
	}

	if len(flagListeners) > 0 {
		conf.Listeners = flagListeners
	}

	if len(conf.Listeners) == 0 {
		conf.Listeners = multiFlag{"0.0.0.0:25", "[::]:25"}
	}

	if conf.RwTimeout == 0 {
		conf.RwTimeout = 30
	}

	// == Bind to listening ports ===============================================
	listeners, err := bindListeners(conf.Listeners, conf.MxAddr, time.Duration(conf.MxTimeout)*time.Second, time.Duration(conf.RwTimeout)*time.Second)
	if err != nil {
		log.Fatalf("listeners: %v", err)
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
		Listeners: listeners,
		AllowList: allowList,
		CertPath:  conf.CertPath,
		KeyPath:   conf.KeyPath,
		Banner:    conf.Banner,
		Queue:     queue,
		RwTimeout: time.Duration(conf.RwTimeout) * time.Second,
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
		RequireTLS:  !conf.MxStartTLSOptional,
		TLSInsecure: conf.MxSkipTLSVerify,
		RetryDelay:  time.Duration(conf.Reconnect) * time.Second,
	})
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	// == Start =================================================================

	go srv.Run()
	go cli.Run()

	log.Printf(
		"relay started — backend: mxaddr=%q mxname=%q | queue: %s",
		conf.MxAddr, conf.MxName, conf.QueueDir,
	)

	// == Shutdown ==============================================================
	// TODO: propagate cancellation via context to srv.Run and cli.Run for
	// graceful in-flight draining before exit.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case s := <-quit:
			log.Printf("received %v, shutting down", s)
			return
		case <-hup:
			log.Printf("Got SIGHUP. Reloading allowlist. Reloading TLS certificate. Rescanning mail queue.")
			err := allowList.Reload()
			if err != nil {
				log.Printf("Unable to reload allowlist: %v", err)
			}
			err = srv.ReloadTLSCertificate()
			if err != nil {
				log.Printf("Unable to reload TLS certificate: %v", err)
			}
			queue.Rescan()
		}
	}
}

func listenerFromFD(fd int) (net.Listener, error) {
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd-%d", fd))
	if file == nil {
		return nil, fmt.Errorf("invalid file descriptor: %d", fd)
	}

	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}

	file.Close()
	return listener, nil
}

func bindListeners(listenaddrs []string, backendAddr string, ctTimeout, rwTimeout time.Duration) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0)

	listen_fds_str := os.Getenv("LISTEN_FDS")
	if len(listen_fds_str) > 0 {
		listen_fds, err := strconv.Atoi(listen_fds_str)
		if err != nil {
			return nil, fmt.Errorf("Got invalid value in LISTEN_FDS environment variable: %s", listen_fds_str)
		}
		log.Printf("Detected socket activation: %d sockets", listen_fds)
		listenFDStart := 3
		for fd := listenFDStart; fd < listenFDStart+listen_fds; fd++ {
			listener, err := listenerFromFD(fd)
			if err != nil {
				return nil, fmt.Errorf("Unable to listen on FD %v: %v", fd, err)
			}
			ctListener := NewCutThroughListener(listener, backendAddr, ctTimeout, rwTimeout)
			listeners = append(listeners, ctListener)
		}
	} else {
		for _, addr := range listenaddrs {
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				return nil, fmt.Errorf("Unable to listen on %s: %v", addr, err)
			}
			ctListener := NewCutThroughListener(listener, backendAddr, ctTimeout, rwTimeout)

			listeners = append(listeners, ctListener)
		}
	}
	log.Printf("Finished binding sockets")
	dropBindCapability()
	return listeners, nil
}
