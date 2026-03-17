// server.go
//
// Targets github.com/emersion/go-smtp v0.21.x or later.
// If using an older version where Session.Rcpt only takes (string), drop opts.
package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
)

// == Server ====================================================================

// ServerConfig is the complete configuration for the SMTP ingestion server.
type ServerConfig struct {
	Listeners []net.Listener
	AllowList *AllowList
	CertPath  string
	KeyPath   string
	Banner    string // hostname in 220 greeting and EHLO reply
	Queue     *Queue
	Notify    chan struct{} // non-blocking send when a message is queued
}

// Server is the inbound SMTP half of the relay.
type Server struct {
	cfg       ServerConfig
	tlsConfig *tls.Config
}

// NewServer performs all initialisation that can fail at startup: loading the
// TLS keypair, creating the queue directory, and building the allow-list index.
// Any error indicates misconfiguration and should be treated as fatal by the
// caller.
func NewServer(cfg ServerConfig) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return &Server{cfg: cfg, tlsConfig: tlsCfg}, nil
}

// Run starts one listener goroutine per entry in cfg.Listeners and blocks
// until all of them have stopped. A failed individual listener is logged but
// does not affect the others.
func (s *Server) Run() {
	var wg sync.WaitGroup
	for _, listener := range s.cfg.Listeners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.serve(listener); err != nil {
				log.Printf("server: listener %s: %v", listener, err)
			}
		}()
	}
	wg.Wait()
}

func (s *Server) serve(listener net.Listener) error {
	gsrv := smtp.NewServer(&smtpBackend{srv: s})
	gsrv.Domain = s.cfg.Banner
	gsrv.TLSConfig = s.tlsConfig
	gsrv.AllowInsecureAuth = false
	gsrv.MaxMessageBytes = 40 * 1024 * 1024 // 40 MiB hard cap

	log.Printf("server: listening on %v", listener.Addr())
	return gsrv.Serve(listener)
}

// == smtp.Backend ==============================================================

type smtpBackend struct{ srv *Server }

func (b *smtpBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	log.Printf("server: connection %s -> %s as %s",
		c.Conn().RemoteAddr().String(),
		c.Conn().LocalAddr().String(),
		c.Hostname(),
	)
	return &smtpSession{
		bkd:      b,
		conn:     c,
		clientIP: c.Conn().RemoteAddr().String(),
		serverIP: c.Conn().LocalAddr().String(),
	}, nil
}

// == smtp.Session ==============================================================

type smtpSession struct {
	bkd      *smtpBackend
	conn     *smtp.Conn
	clientIP string
	serverIP string

	mailFrom string
	rcptTo   []string
}

func (s *smtpSession) Mail(from string, opts *smtp.MailOptions) error {
	s.mailFrom = from
	return nil
}

func (s *smtpSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	allow, err := s.bkd.srv.cfg.AllowList.Allow(to)
	if err != nil {
		log.Printf("server: allowlist lookup failure client=%s rcpt=<%s> error=%v",
			s.clientIP, to, err)
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 7, 0},
			Message:      "Unable to validate recipient address",
		}
	}
	if !allow {
		log.Printf("server: reject client=%s rcpt=<%s> reason=not-in-allowlist",
			s.clientIP, to)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "User unknown",
		}
	}
	s.rcptTo = append(s.rcptTo, to)
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	// STARTTLS (if it was negotiated) completes before the DATA command is
	// issued, so querying connection state here reflects the final negotiated
	// TLS parameters.  For plaintext sessions, cs.TLS.Version == 0.
	cs := s.conn
	ts, tlsUsed := cs.TLSConnectionState()

	var tlsVersion, tlsCipher string
	if tlsUsed {
		tlsVersion = tlsVersionName(ts.Version)
		tlsCipher = tls.CipherSuiteName(ts.CipherSuite)
	}

	body, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read DATA payload: %w", err)
	}

	msg := QueuedMessage{
		ID:         newMsgID(),
		Timestamp:  time.Now().UTC(),
		ClientIP:   s.clientIP,
		ServerIP:   s.serverIP,
		TLSUsed:    tlsUsed,
		TLSVersion: tlsVersion,
		TLSCipher:  tlsCipher,
		Helo:       cs.Hostname(),
		MailFrom:   s.mailFrom,
		RcptTo:     append([]string(nil), s.rcptTo...), // defensive copy
	}

	if err := s.bkd.srv.cfg.Queue.Write(msg, body); err != nil {
		log.Printf("server: enqueue id=%s client=%s: %v",
			msg.ID, s.clientIP, err)
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Temporary storage failure, please retry",
		}
	}

	log.Printf("server: accepted id=%s from=<%s> to=%v client=%s tls=%v cipher=%q",
		msg.ID, s.mailFrom, s.rcptTo, s.clientIP, tlsUsed, tlsCipher)
	return nil
}

func (s *smtpSession) Logout() error { return nil }

func (s *smtpSession) Reset() {}

// == Helpers ===================================================================

// newMsgID returns a time-ordered, collision-resistant message identifier
// suitable for use as a filename.
// Format: <unix-nanoseconds>-<12 random hex characters>
func newMsgID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is extraordinary; timestamp alone is the fallback.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(b))
}

// tlsVersionName maps a crypto/tls version constant to its canonical string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
