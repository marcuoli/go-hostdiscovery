package tcp

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestWindowsSocketErrors(t *testing.T) {
	for _, test := range []struct {
		errno syscall.Errno
		want  Status
	}{{10060, TimedOut}, {10061, Refused}, {10065, Unreachable}, {10051, Unreachable}, {10013, Failed}} {
		err := fmt.Errorf("wrapped: %w", &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connectex", Err: test.errno}})
		if got := Classify(err); got != test.want {
			t.Errorf("errno=%d got=%q want=%q", test.errno, got, test.want)
		}
	}
}
