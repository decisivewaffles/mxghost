package main

// Implements a TCP cut through net.Listener wrapper. Bind to your local listener,
// and give it a backend target, and if it can connect within timeout, the connection
// is cut through directly after prepending HAProxy-type PROXY headers. If that fails
// then this will unblock Accept() called on it as a listener, and pass the connection
// to that handler.

// This is used to bypass internal store and forward processing as well as TLS handling
// when the backend is reachable.

import (
	"errors"
	"io"
	"log"
	"net"
	"time"
)

// CutThroughListener wraps a net.Listener to implement cut-through connection logic.
type CutThroughListener struct {
	net.Listener
	backendAddr string
	timeout     time.Duration

	// queue stores connections that failed the cut-through (dial timeout)
	// so they can be returned by Accept().
	queue chan net.Conn
}

// NewCutThroughListener creates a new listener.
func NewCutThroughListener(listener net.Listener, backendAddr string, timeout time.Duration) *CutThroughListener {
	return &CutThroughListener{
		Listener:    listener,
		backendAddr: backendAddr,
		timeout:     timeout,
		queue:       make(chan net.Conn, 128),
	}
}

// Accept waits for and returns the next connection to the listener.
// It prioritizes connections from the underlying listener, but falls back
// to connections that timed out during the cut-through dial.
func (l *CutThroughListener) Accept() (net.Conn, error) {
	for {
		// Non-blocking check for queued (timed-out) connections first.
		// This ensures we don't starve existing clients if the listener is busy.
		select {
		case conn := <-l.queue:
			return conn, nil
		default:
		}

		// Block until we get a raw connection OR a queued connection becomes available.
		select {
		case conn := <-l.queue:
			return conn, nil
		case rawConn, ok := <-l.acceptChan():
			if !ok {
				// Underlying listener closed
				return nil, errors.New("listener closed")
			}
			// We received a raw connection. Attempt cut-through.
			go l.handleCutThrough(rawConn)
		}
	}
}

// acceptChan wraps the blocking Accept() call in a channel for select usage.
func (l *CutThroughListener) acceptChan() <-chan net.Conn {
	ch := make(chan net.Conn, 1)
	go func() {
		conn, err := l.Listener.Accept()
		if err != nil {
			// If accept fails, we close the listener logic
			l.Close()
			close(ch)
			return
		}
		ch <- conn
	}()
	return ch
}

// handleCutThrough attempts to dial the backend.
func (l *CutThroughListener) handleCutThrough(clientConn net.Conn) {
	// Attempt to connect to backend with timeout
	backendConn, err := net.DialTimeout("tcp", l.backendAddr, l.timeout)

	if err == nil {
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
		go proxy(clientConn, backendConn)
		go proxy(backendConn, clientConn)
		// Connections are closed by proxy via io.Copy reading EOF or error.
	} else {
		// TIMEOUT or ERROR: Dial failed.
		// Pass the client connection to the Accept() caller.
		select {
		case l.queue <- clientConn:
			// Successfully queued for Accept()
		default:
			// Queue full, drop connection.
			clientConn.Close()
		}
	}
}

// proxy copies data between two connections.
func proxy(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}
