// Copyright (C) 2026 DecisiveWaffles <decisivewaffles@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

type AllowList struct {
	path    string
	address atomic.Value
	domain  atomic.Value
}

func NewAllowList(path string) (*AllowList, error) {
	al := &AllowList{
		path: path,
	}
	al.address.Store(make(map[string]bool))
	al.domain.Store(make(map[string]bool))
	return al, al.Reload()
}

func (al *AllowList) Reload() error {
	f, err := os.Open(al.path)
	if err != nil {
		return err
	}
	defer f.Close()

	address := make(map[string]bool)
	domain := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if len(line) < 1 || line[0] == '#' {
			continue
		}
		if strings.Contains(line, "@") {
			address[line] = true
		} else {
			domain[line] = true
		}
	}
	al.address.Store(address)
	al.domain.Store(domain)
	return nil
}

func (al *AllowList) Allow(rcpt string) (bool, error) {
	address := al.address.Load().(map[string]bool)
	domain := al.domain.Load().(map[string]bool)
	rcpt = strings.ToLower(rcpt)
	if address[rcpt] {
		return true, nil
	}
	_, rcptDomain, ok := strings.Cut(rcpt, "@")
	if !ok {
		return false, fmt.Errorf("Invalid recipient address: %s", rcpt)
	}
	return domain[rcptDomain], nil
}
