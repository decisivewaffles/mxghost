// client.go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"time"
)

// ClientConfig is the complete configuration for the outbound SMTP delivery
// client.
type ClientConfig struct {
	Queue       *Queue        // shared mail queue
	MXAddr      string        // IP and optionally port of primary MX
	MXName      string        // hostname of primary MX for TLS validation
	ImplicitTLS bool          // true → wrap TCP in TLS immediately (SMTPS / port 465)
	RequireTLS  bool          // true → abort if STARTTLS is not advertised by backend
	TLSInsecure bool          // skip TLS certificate verification — testing only
	RetryDelay  time.Duration // base delay between attempts (default 60s)
	DialTimeout time.Duration // TCP / TLS dial timeout (default 30s)
	TxTimeout   time.Duration // wall-clock deadline for one complete SMTP transaction (default 5m)
}

// Client is the outbound SMTP delivery half of the relay.
type Client struct {
	cfg    ClientConfig
	tlsCfg *tls.Config
}

// NewClient validates cfg, applies defaults for any zero fields, and returns a
// ready Client.  Configuration errors are returned here so that Run() never
// needs to deal with them.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Queue == nil {
		return nil, fmt.Errorf("client: Queue must not be nil")
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 60 * time.Second
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	if cfg.TxTimeout == 0 {
		cfg.TxTimeout = 5 * time.Minute
	}

	tlsCfg := &tls.Config{
		ServerName:         cfg.MXName,
		InsecureSkipVerify: cfg.TLSInsecure,
		MinVersion:         tls.VersionTLS12,
	}

	return &Client{cfg: cfg, tlsCfg: tlsCfg}, nil
}

// Run loops forever, blocking on Queue.Read() between deliveries.
// It returns only when Queue.Read() itself returns a non-nil error, which
// signals an unrecoverable condition (e.g. queue shutdown).
// Intended to be called as a goroutine from main.
func (c *Client) Run() {
	log.Printf("client: started backend implicit-tls=%v require-tls=%v",
		c.cfg.ImplicitTLS, c.cfg.RequireTLS)

	for {
		// Read from queue
		// Note: This will return the same message until qi.Delete() is called
		qi, err := c.cfg.Queue.Read()
		if err != nil {
			log.Printf("client: queue read: %v — stopping", err)
			return
		}
		err = c.deliver(qi)
		if err != nil {
			log.Printf("client: send error: %v", err)
		}
	}
}

// Deliver one message from the queue to the primary MX
func (c *Client) deliver(qi *QueueItem) error {
	log.Printf("client id=%s: deliver()", qi.Message.ID)
	conn, err := c.dial()
	if err != nil {
		log.Printf("client: Unable to connect, waiting %d seconds", c.cfg.RetryDelay/time.Second)
		time.Sleep(c.cfg.RetryDelay / time.Second)
		return err
	}
	log.Printf("client id=%s: connected", qi.Message.ID)

	// Bound the entire SMTP exchange.  This covers banner + EHLO + STARTTLS +
	// MAIL + RCPT(s) + DATA transfer + QUIT.
	if err := conn.SetDeadline(time.Now().Add(c.cfg.TxTimeout)); err != nil {
		conn.Close()
		return fmt.Errorf("set deadline: %w", err)
	}
	// Send the PROXY header
	proxyHeader, err := ProxyProtocolHeader(qi.Message.ClientIP, qi.Message.ServerIP)
	if err != nil {
		conn.Close()
		return fmt.Errorf("proxy header generation failure: %w", err)
	}
	_, err = conn.Write(proxyHeader)
	if err != nil {
		conn.Close()
		return fmt.Errorf("proxy header send failure: %w", err)
	}
	log.Printf("client id=%s: PROXY PROTO SENT", qi.Message.ID)

	// NewClient reads the server banner (220).  On error the underlying conn
	// is already closed by the smtp package, but we Close() defensively.
	// host is just used for authentication, which we don't support.
	sc, err := smtp.NewClient(conn, "")
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer sc.Close() // safe to call after Quit(); double-close on net.Conn is harmless
	log.Printf("client id=%s: HANDSHAKE done", qi.Message.ID)

	// EHLO — must precede Extension() checks and STARTTLS.
	if err := sc.Hello(qi.Message.Helo); err != nil {
		log.Printf("client: EHLO failed: %w", err)
		qi.Fail()
		return fmt.Errorf("EHLO: %w", err)
	}

	log.Printf("client id=%s: EHLO done", qi.Message.ID)
	// STARTTLS — only considered on plain-TCP connections; implicit-TLS
	// connections are already encrypted at the transport layer.
	if !c.cfg.ImplicitTLS {
		advertised, _ := sc.Extension("STARTTLS")
		if !advertised && c.cfg.RequireTLS {
			return fmt.Errorf("backend does not advertise STARTTLS and RequireTLS=true")
		}
		if advertised {
			// StartTLS upgrades the connection and re-sends EHLO automatically.
			if err := sc.StartTLS(c.tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
		}
	}
	log.Printf("client id=%s: TLS done", qi.Message.ID)

	// MAIL FROM
	if err := sc.Mail(qi.Message.MailFrom); err != nil {
		qi.Fail()
		return fmt.Errorf("MAIL FROM <%s>: %w", qi.Message.MailFrom, err)
	}

	// RCPT TO — if any recipient is rejected we abort the whole transaction.
	for _, rcpt := range qi.Message.RcptTo {
		if err := sc.Rcpt(rcpt); err != nil {
			qi.Fail()
			return fmt.Errorf("RCPT TO <%s>: %w", rcpt, err)
		}
	}
	log.Printf("client id=%s: Starting DATA", qi.Message.ID)

	// DATA
	//
	// net/smtp's Data() returns a textproto.DotWriter which re-applies RFC 5321
	// dot-stuffing on the fly.  The body stored in the queue is raw — go-smtp
	// strips dot-stuffing on ingest — so we write the bytes verbatim and let
	// the DotWriter handle wire encoding.
	//
	// wc.Close() sends the terminating CRLF.CRLF and reads the server's 250
	// acknowledgment; any rejection here surfaces as *textproto.Error and is
	// handled by deliverWithRetry's error classifier.
	wc, err := sc.Data()
	if err != nil {
		qi.Fail()
		return fmt.Errorf("DATA command: %w", err)
	}
	if _, err := wc.Write(qi.Body); err != nil {
		qi.Fail()
		wc.Close() // best-effort; return the write error
		return fmt.Errorf("DATA write: %w", err)
	}
	if err := wc.Close(); err != nil {
		qi.Fail()
		return fmt.Errorf("DATA commit: %w", err)
	}

	log.Printf("client id=%s: Sent DATA", qi.Message.ID)

	// QUIT — a failure here does not undo delivery; the message was accepted
	// when DATA committed.  Log the error and report success to the caller.
	if err := sc.Quit(); err != nil {
		log.Printf("client: id=%s QUIT error (message was accepted): %v", qi.Message.ID, err)
	}

	log.Printf("client: Send complete")
	// Remove message from delivery queue
	qi.Delete()
	return nil
}

// dial establishes a TCP connection to the backend.
// For ImplicitTLS the connection is wrapped in TLS before returning;
// for plain connections STARTTLS is negotiated later in deliver().
func (c *Client) dial() (net.Conn, error) {
	d := &net.Dialer{Timeout: c.cfg.DialTimeout}

	if c.cfg.ImplicitTLS {
		conn, err := tls.DialWithDialer(d, "tcp", c.cfg.MXAddr, c.tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("tls dial %s: %w", c.cfg.MXAddr, err)
		}
		return conn, nil
	}

	conn, err := d.Dial("tcp", c.cfg.MXAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.cfg.MXAddr, err)
	}
	return conn, nil
}
