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

