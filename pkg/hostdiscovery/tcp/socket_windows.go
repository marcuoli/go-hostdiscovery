package tcp

import (
	"errors"
	"syscall"
)

func socketStatus(err error) Status {
	// Winsock codes are not the POSIX compatibility errno values. In particular,
	// Windows 10060 does not implement net.Error.Timeout in the Go syscall layer.
	switch {
	case errors.Is(err, syscall.Errno(10060)):
		return TimedOut
	case errors.Is(err, syscall.Errno(10061)):
		return Refused
	case errors.Is(err, syscall.Errno(10065)), errors.Is(err, syscall.Errno(10051)):
		return Unreachable
	default:
		return Failed
	}
}
