package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDialContextReturnsUsableOriginalSocket(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Skipf("loopback unavailable: %v", err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			conn, result, err := DialContext(ctx, &net.Dialer{}, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, ok := conn.(*net.TCPConn); !ok {
				t.Fatalf("TCP/OOB socket type lost: %T", conn)
			}
			if result.Status != Connected || result.Address != listener.Addr().String() || result.Elapsed < 0 || result.RemoteAddress == "" || result.LocalAddress == "" {
				t.Fatalf("invalid result: %+v", result)
			}
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			_ = peer.SetDeadline(time.Now().Add(time.Second))
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("continue")); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 8)
			if _, err := io.ReadFull(peer, payload); err != nil || string(payload) != "continue" {
				t.Fatalf("socket not reusable: %q %v", payload, err)
			}
			if tcpListener, ok := listener.(*net.TCPListener); ok {
				_ = tcpListener.SetDeadline(time.Now().Add(20 * time.Millisecond))
				if extra, err := listener.Accept(); err == nil {
					extra.Close()
					t.Fatal("made a second probe connection")
				}
			}
		})
	}
}

func TestDialContextPreservesCancellationAndDeadline(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		want, status := error(context.Canceled), Cancelled
		if deadline {
			cancel()
			ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			want, status = context.DeadlineExceeded, TimedOut
		} else {
			cancel()
		}
		conn, result, err := DialContext(ctx, nil, "tcp", "127.0.0.1:1521")
		cancel()
		if conn != nil || result.Status != status || !errors.Is(err, want) {
			t.Fatalf("conn=%v result=%+v err=%v", conn, result, err)
		}
	}
}

func TestClassifyPreservesDistinctFailureCauses(t *testing.T) {
	for _, test := range []struct {
		cause error
		want  Status
	}{
		{nil, Connected}, {context.Canceled, Cancelled}, {context.DeadlineExceeded, TimedOut},
		{os.ErrDeadlineExceeded, TimedOut}, {&net.DNSError{Err: "no such host", Name: "oracle.invalid", IsNotFound: true}, ResolutionFailed},
		{&net.DNSError{Err: "i/o timeout", Name: "oracle.invalid", IsTimeout: true}, ResolutionFailed},
		{io.EOF, Failed}, {errors.New("connection refused timed out unreachable"), Failed},
	} {
		err := test.cause
		if err != nil {
			err = fmt.Errorf("outer: %w", &net.OpError{Op: "dial", Net: "tcp", Err: err})
		}
		if got := Classify(err); got != test.want {
			t.Errorf("%v: got %q want %q", err, got, test.want)
		}
	}
}

func TestDialContextReportsRefusalAndPreservesError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	conn, result, err := DialContext(t.Context(), &net.Dialer{Timeout: time.Second}, "tcp", address)
	var op *net.OpError
	if conn != nil || result.Status != Refused || !errors.As(err, &op) || result.Address != address {
		t.Fatalf("conn=%v result=%+v err=%v", conn, result, err)
	}
}

func TestDialContextRejectsNonTCPWithoutOpeningSocket(t *testing.T) {
	conn, result, err := DialContext(t.Context(), nil, "udp", "127.0.0.1:1521")
	var network net.UnknownNetworkError
	if conn != nil || result.Status != Failed || !errors.As(err, &network) {
		t.Fatalf("conn=%v result=%+v err=%v", conn, result, err)
	}
}

func TestDialContextPreservesDialerControlAndErrorIdentity(t *testing.T) {
	want := errors.New("caller control rejected connection")
	calls := 0
	dialer := &net.Dialer{Control: func(network, address string, _ syscall.RawConn) error {
		calls++
		if network != "tcp4" || address != "127.0.0.1:1521" {
			t.Errorf("changed endpoint: %q %q", network, address)
		}
		return want
	}}
	conn, result, err := DialContext(t.Context(), dialer, "tcp4", "127.0.0.1:1521")
	if conn != nil || calls != 1 || result.Status != Failed || !errors.Is(err, want) {
		t.Fatalf("conn=%v calls=%d result=%+v err=%v", conn, calls, result, err)
	}
}

func TestDialContextPreservesDNSFailureAndDialerTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 40 * time.Millisecond, Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	conn, result, err := DialContext(ctx, dialer, "tcp", "unresolvable.invalid:1521")
	var network net.Error
	if conn != nil || !errors.As(err, &network) || !network.Timeout() || result.Elapsed > time.Second || ctx.Err() != nil {
		t.Fatalf("dialer timeout changed: conn=%v result=%+v err=%v parent=%v", conn, result, err, ctx.Err())
	}
	if result.Status != ResolutionFailed && result.Status != TimedOut {
		t.Fatalf("unexpected timeout classification: %+v", result)
	}
}
