package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type Direction uint8

const (
	FromClient Direction = iota
	ToClient
)

type Result struct {
	Direction Direction
	Bytes     int64
}

// Bidirectional relays one TCP session without changing its upstream. It
// preserves TCP half-close semantics and refreshes per-direction idle
// deadlines on every read and write.
func Bidirectional(
	parent context.Context,
	client net.Conn,
	upstream net.Conn,
	idleTimeout time.Duration,
	record func(Result),
) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = upstream.Close()
	}()

	clientConn := deadlineConn{Conn: client, timeout: idleTimeout}
	upstreamConn := deadlineConn{Conn: upstream, timeout: idleTimeout}
	results := make(chan copyResult, 2)
	go copyStream(results, FromClient, upstreamConn, clientConn)
	go copyStream(results, ToClient, clientConn, upstreamConn)
	first := <-results
	recordResult(record, first)
	halfClose(first.direction, client, upstream)
	second := <-results
	recordResult(record, second)
	cancel()
	if significantCopyError(first.err) {
		return first.err
	}
	if significantCopyError(second.err) {
		return second.err
	}
	return nil
}

func IsTemporaryAcceptError(err error) bool {
	var temporary interface{ Temporary() bool }
	return errors.As(err, &temporary) && temporary.Temporary()
}

// WaitAcceptRetry applies the shared bounded exponential accept backoff. The
// boolean is false when the context was canceled while waiting.
func WaitAcceptRetry(ctx context.Context, previous time.Duration) (time.Duration, bool) {
	next := nextAcceptDelay(previous)
	timer := time.NewTimer(next)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return next, false
	case <-timer.C:
		return next, true
	}
}

func nextAcceptDelay(previous time.Duration) time.Duration {
	const (
		minimum = 5 * time.Millisecond
		maximum = time.Second
	)
	if previous <= 0 {
		return minimum
	}
	next := previous * 2
	if next > maximum {
		return maximum
	}
	return next
}

type copyResult struct {
	direction Direction
	bytes     int64
	err       error
}

func copyStream(results chan<- copyResult, direction Direction, destination io.Writer, source io.Reader) {
	count, err := io.Copy(destination, source)
	results <- copyResult{direction: direction, bytes: count, err: err}
}

func recordResult(record func(Result), result copyResult) {
	if record != nil {
		record(Result{Direction: result.direction, Bytes: result.bytes})
	}
}

func halfClose(direction Direction, client, upstream net.Conn) {
	if direction == FromClient {
		if connection, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = connection.CloseWrite()
		}
		if connection, ok := client.(interface{ CloseRead() error }); ok {
			_ = connection.CloseRead()
		}
		return
	}
	if connection, ok := client.(interface{ CloseWrite() error }); ok {
		_ = connection.CloseWrite()
	}
	if connection, ok := upstream.(interface{ CloseRead() error }); ok {
		_ = connection.CloseRead()
	}
}

func significantCopyError(err error) bool {
	return err != nil &&
		!errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, context.Canceled)
}

type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c deadlineConn) Read(data []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(data)
}

func (c deadlineConn) Write(data []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}
