// Copyright (C) 2026 DecisiveWaffles <decisivewaffles@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// QueuedMessage is the metadata envelope for one queued mail item.
// Each queue file consists of exactly one compact JSON line containing this
// struct, a '\n', then the raw SMTP DATA payload for the remainder of the file.
type QueuedMessage struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ClientIP  string    `json:"client_ip"`
	ServerIP  string    `json:"server_ip"`
	Helo      string    `json:"helo"`
	MailFrom  string    `json:"mail_from"`
	RcptTo    []string  `json:"rcpt_to"`
}

type Queue struct {
	path   string
	notify chan struct{}
}

func NewQueue(path string) (*Queue, error) {
	_, err := os.ReadDir(path)
	if err != nil {
		if err := os.MkdirAll(path, 0o750); err != nil {
			return nil, fmt.Errorf("create queue dir %q: %w", path, err)
		}
	}
	return &Queue{
		path,
		make(chan struct{}, 1),
	}, nil
}

type QueueItem struct {
	path    string
	Message QueuedMessage
	Body    []byte
}

func (qi *QueueItem) Delete() error {
	return os.Remove(qi.path)
}

func (qi *QueueItem) Fail() error {
	return os.Rename(qi.path, qi.path+".failed")
}

// Blocking read of queue (does NOT remove message)
func (q *Queue) Read() (*QueueItem, error) {
	filename := ""
	for filename == "" {
		entries, err := os.ReadDir(q.path)
		if err != nil {
			return nil, err
		}
		filename = firstMsgFilename(entries)
		if filename == "" {
			<-q.notify
		}
	}

	path := filepath.Join(q.path, filename)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := bufio.NewReader(f)

	// First line is compact JSON terminated by '\n'.
	line, err := br.ReadString('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("read header line: %w", err)
	}

	var msg QueuedMessage
	if err := json.Unmarshal([]byte(strings.TrimRight(line, "\r\n")), &msg); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	body, err := io.ReadAll(br)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return &QueueItem{path, msg, body}, nil
}

func (q *Queue) Write(msg QueuedMessage, body []byte) error {
	final := filepath.Join(q.path, msg.ID+".msg")
	tmp := final + ".tmp"

	// Encode header before opening the file; any encoding error is programmer
	// error (bad struct tags etc.) and doesn't leave a temp file behind.
	var hdr bytes.Buffer
	enc := json.NewEncoder(&hdr)
	enc.SetEscapeHTML(false) // keep <user@domain> and & readable in raw files
	if err := enc.Encode(msg); err != nil {
		return fmt.Errorf("encode header: %w", err)
	}

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}

	// cleanup is called on every error path after the file is open.
	// It must not be called after f.Close() succeeds.
	cleanup := func() { f.Close(); os.Remove(tmp) }

	if _, err := f.Write(hdr.Bytes()); err != nil {
		cleanup()
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		cleanup()
		return fmt.Errorf("write body: %w", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}

	// Non-blocking send: the channel holds capacity 1.  If a signal is already
	// pending the client has not yet drained the queue, and the new item will
	// be found in the same sweep — a second signal would be redundant.
	select {
	case q.notify <- struct{}{}:
	default:
	}

	return nil
}

func (q *Queue) Rescan() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// == Helpers ===================================================================

func firstMsgFilename(entries []os.DirEntry) string {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".msg") {
			return entry.Name()
		}
	}
	return ""
}
