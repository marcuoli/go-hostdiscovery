//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package tcp

import (
	"errors"
	"syscall"
)

func socketStatus(err error) Status {
	switch {
	case errors.Is(err, syscall.ETIMEDOUT):
		return TimedOut
	case errors.Is(err, syscall.ECONNREFUSED):
		return Refused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return Unreachable
	default:
		return Failed
	}
}
