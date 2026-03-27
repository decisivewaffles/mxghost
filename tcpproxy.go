package main

// Simple TCP <-> TCP pass through with timeout

import (
	"io"
	"log"
	"net"
	"time"
)

type activityConn struct {
	*net.TCPConn
	onActivity func()
}

func (c *activityConn) Read(b []byte) (int, error) {
	n, err := c.TCPConn.Read(b)
	if n > 0 {
		c.onActivity()
	}
	return n, err
}

func (c *activityConn) Write(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b)
	if n > 0 {
		c.onActivity()
	}
	return n, err
}

func proxyConn(client, backend *net.TCPConn, timeout time.Duration) {
	defer client.Close()
	defer backend.Close()

	// resetDeadline resets the deadline on BOTH connections
	resetDeadline := func() {
		deadline := time.Now().Add(timeout)
		client.SetDeadline(deadline)
		backend.SetDeadline(deadline)
	}

	resetDeadline() // set initial deadline

	clientWrapped := &activityConn{client, resetDeadline}
	backendWrapped := &activityConn{backend, resetDeadline}

	done := make(chan struct{}, 2)

	copy := func(dst *activityConn, src *activityConn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			nr, err := src.Read(buf)
			if nr > 0 {
				_, err := dst.Write(buf[:nr])
				if err != nil {
					log.Printf("write error: %v", err)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("read error: %v", err)
				}
				// Propagate EOF
				dst.TCPConn.CloseWrite()
				return
			}
		}
	}

	go copy(backendWrapped, clientWrapped) // client -> backend
	go copy(clientWrapped, backendWrapped) // backend -> client

	<-done

	// Close both so the other goroutine unblocks
	client.CloseRead()
	backend.CloseRead()

	<-done
}
