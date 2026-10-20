// Copyright (C) 2026 DecisiveWaffles <decisivewaffles@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux
// +build linux

package main

import (
	"log"
        "kernel.org/pub/linux/libs/security/libcap/cap"
)

func emptyCapabilitiesSet(caps *cap.Set) bool {
        diff, _ := caps.Cf(cap.NewSet())
        return diff == 0
}

func dropUnusedCapabilities() {
        // Drop unneeded permissions
        log.Printf("capabilities: started with %s", cap.GetProc().String())
        caps := cap.GetProc()
        if emptyCapabilitiesSet(caps) {
                return
        }
        alarmAllowed, _ := caps.GetFlag(cap.Permitted, cap.WAKE_ALARM)
        bindAllowed, _ := caps.GetFlag(cap.Permitted, cap.NET_BIND_SERVICE)
        caps.Clear()
        if alarmAllowed {
                caps.SetFlag(cap.Effective, true, cap.WAKE_ALARM)
                caps.SetFlag(cap.Permitted, true, cap.WAKE_ALARM)
        }
        if bindAllowed {
                caps.SetFlag(cap.Effective, true, cap.NET_BIND_SERVICE)
                caps.SetFlag(cap.Permitted, true, cap.NET_BIND_SERVICE)
        }
        err := caps.SetProc()
        if err != nil {
                log.Printf("capabilities: Unable to drop: %v", err)
        } else {
                log.Printf("capabilities: currently \"%s\"", cap.GetProc().String())
        }
}

func dropBindCapability() {
        caps := cap.GetProc()
        if emptyCapabilitiesSet(caps) {
                return
        }
        alarmAllowed, _ := caps.GetFlag(cap.Permitted, cap.WAKE_ALARM)
        caps.Clear()
        if alarmAllowed {
                caps.SetFlag(cap.Effective, true, cap.WAKE_ALARM)
                caps.SetFlag(cap.Permitted, true, cap.WAKE_ALARM)
        }
        err := caps.SetProc()
        if err != nil {
                log.Printf("capabilities: Unable to minimize: %v", err)
        } else {
                log.Printf("capabilities: currently \"%s\"", cap.GetProc().String())
        }
}

