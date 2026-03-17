// allowlist.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type AllowList struct {
	path    string
	address map[string]bool
	domain  map[string]bool
}

func NewAllowList(path string) (*AllowList, error) {
	al := &AllowList{
		path:    path,
		address: make(map[string]bool),
		domain:  make(map[string]bool),
	}
	return al, al.Reload()
}

func (al *AllowList) Reload() error {
	f, err := os.Open(al.path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if len(line) < 1 || line[0] == '#' {
			continue
		}
		if strings.Contains(line, "@") {
			al.address[line] = true
		} else {
			al.domain[line] = true
		}
	}
	return nil
}

func (al *AllowList) Allow(rcpt string) (bool, error) {
	rcpt = strings.ToLower(rcpt)
	if al.address[rcpt] {
		return true, nil
	}
	_, domain, ok := strings.Cut(rcpt, "@")
	if !ok {
		return false, fmt.Errorf("Invalid recipient address: %s", rcpt)
	}
	return al.domain[domain], nil
}
