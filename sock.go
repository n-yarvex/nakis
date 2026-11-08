//go:build linux

package main

import "syscall"

func init() {
	setCongestion = func(fd uintptr, name string) error {
		return syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, name)
	}
}
