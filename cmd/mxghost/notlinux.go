// Copyright (C) 2026 DecisiveWaffles <decisivewaffles@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux
// +build !linux

package main

func emptyCapabilitiesSet(caps *cap.Set) bool {
	return true
}

func dropUnusedCapabilities() {
	return
}

func dropBindCapability() {
	return
}

