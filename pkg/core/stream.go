package core

import (
	"context"
	"time"

	"github.com/lucas-clemente/quic-go"
)

// Handle stream close properly
// Ref: https://github.com/libp2p/go-libp2p-quic-transport/blob/master/stream.go
type wrappedQUICStream struct {
	isClient bool
	Stream   quic.Stream
}

func (s *wrappedQUICStream) StreamID() quic.StreamID {
	return s.Stream.StreamID()
}

func (s *wrappedQUICStream) Read(p []byte) (n int, err error) {
	return s.Stream.Read(p)
}

func (s *wrappedQUICStream) CancelRead(code quic.StreamErrorCode) {
	s.Stream.CancelRead(code)
}

func (s *wrappedQUICStream) SetReadDeadline(t time.Time) error {
	return s.Stream.SetReadDeadline(t)
}

func (s *wrappedQUICStream) Write(p []byte) (n int, err error) {
	return s.Stream.Write(p)
}

func (s *wrappedQUICStream) Close() error {
	if s.isClient {
		s.Stream.CancelWrite(0)
	}
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

func (s *wrappedQUICStream) CancelWrite(code quic.StreamErrorCode) {
	s.Stream.CancelWrite(code)
}

func (s *wrappedQUICStream) Context() context.Context {
	return s.Stream.Context()
}

func (s *wrappedQUICStream) SetWriteDeadline(t time.Time) error {
	return s.Stream.SetWriteDeadline(t)
}

func (s *wrappedQUICStream) SetDeadline(t time.Time) error {
	return s.Stream.SetDeadline(t)
}
