package main

// Implements a TCP cut through net.Listener wrapper. Bind to your local listener,
// and give it a backend target, and if it can connect within timeout, the connection
// is cut through directly after prepending HAProxy-type PROXY headers. If that fails
// then this will unblock Accept() called on it as a listener, and pass the connection
// to that handler.

// This is used to bypass internal store and forward processing as well as TLS handling
// when the backend is reachable.

import (
	"log"
	"net"
	"time"
)

// CutThroughListener wraps a net.Listener to implement cut-through connection logic.
type CutThroughListener struct {
	net.Listener
	backendAddr string
	ctTimeout   time.Duration
	rwTimeout   time.Duration

	// ctFailQueue stores connections that failed the cut-through (dial timeout)
	// so they can be returned by Accept().
	ctFailQueue chan net.Conn
	// acceptQueue is used to make the underlying net.Listener.Accept() selectable
	acceptQueue chan net.Conn
}

// NewCutThroughListener creates a new listener.
func NewCutThroughListener(listener net.Listener, backendAddr string, ctTimeout, rwTimeout time.Duration) *CutThroughListener {
	l := &CutThroughListener{
		Listener:    listener,
		backendAddr: backendAddr,
		ctTimeout:   ctTimeout,
		rwTimeout:   rwTimeout,
		ctFailQueue: make(chan net.Conn, 128),
		acceptQueue: make(chan net.Conn, 1),
	}
	go l.runAcceptQueue()
	return l
}

// Accept waits for and returns the next connection to the listener.
// It prioritizes connections from the underlying listener, but falls back
// to connections that timed out during the cut-through dial.
func (l *CutThroughListener) Accept() (net.Conn, error) {
	for {
		// Non-blocking check for timed-out connections first.
		// This ensures we don't starve existing clients if the listener is busy.
		select {
		case conn := <-l.ctFailQueue:
			return conn, nil
		default:
		}

		// Block until we get a new connection OR a timed-out connection becomes available.
		select {
		case conn := <-l.ctFailQueue:
			return conn, nil
		case rawConn := <-l.acceptQueue:
			// We received a raw connection. Attempt cut-through.
			go l.handleCutThrough(rawConn)
		}
	}
}

// runAcceptQueue calls Accept() and puts the result into acceptQueue
func (l *CutThroughListener) runAcceptQueue() {
	for {
		conn, err := l.Listener.Accept()
		log.Printf("cutthrough: client=%s Accept()", conn.RemoteAddr().String())
		if err != nil {
			log.Fatalf("Listener closed: %v", err)
		}
		l.acceptQueue <- conn
	}
}

// handleCutThrough attempts to dial the backend.
func (l *CutThroughListener) handleCutThrough(clientConn net.Conn) {
	// Attempt to connect to backend with timeout
	backendConn, err := net.DialTimeout("tcp", l.backendAddr, l.ctTimeout)

	if err == nil {
		log.Printf("cutthrough: client=%s Backend connected", clientConn.RemoteAddr().String())
		// Disable Nagle
		clientConn.(*net.TCPConn).SetNoDelay(true)
		backendConn.(*net.TCPConn).SetNoDelay(true)
		// SUCCESS: Cut-through worked.
		// Send the PROXY header
		clientAddr := clientConn.RemoteAddr().String()
		serverAddr := clientConn.LocalAddr().String()
		proxyHeader, err := ProxyProtocolHeader(clientAddr, serverAddr)
		if err != nil {
			clientConn.Close()
			log.Printf("cutthrough: proxy header generation failure: %w", err)
		}
		_, err = backendConn.Write(proxyHeader)
		if err != nil {
			clientConn.Close()
			log.Printf("cutthrough: proxy header send failure: %w", err)
		}
		// Pipe data.
		proxyConn(clientConn.(*net.TCPConn), backendConn.(*net.TCPConn), l.rwTimeout)
		log.Printf("cutthrough: client=%s Backend proxy closed", clientConn.RemoteAddr().String())
	} else {
		log.Printf("cutthrough: client=%s Backend unavailable", clientConn.RemoteAddr().String())
		// TIMEOUT or ERROR: Dial failed.
		// Pass the client connection to the Accept() caller.
		select {
		case l.ctFailQueue <- clientConn:
			// Queued for internal processing.
		default:
			// Queue full, drop connection.
			log.Printf("cutthrough: handleCutThrough(): ctFailQueue full!")
			clientConn.Close()
		}
	}
}
