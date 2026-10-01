//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package tcp

import (
	"fmt"
	"syscall"
	"testing"
)

func TestSocketErrors(t *testing.T) {
	for _, test := range []struct {
		errno syscall.Errno
		want  Status
	}{{syscall.ETIMEDOUT, TimedOut}, {syscall.ECONNREFUSED, Refused}, {syscall.EHOSTUNREACH, Unreachable}, {syscall.ENETUNREACH, Unreachable}, {syscall.EACCES, Failed}} {
		if got := Classify(fmt.Errorf("wrapped: %w", test.errno)); got != test.want {
			t.Errorf("errno=%d got=%q want=%q", test.errno, got, test.want)
		}
	}
}
