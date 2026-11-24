package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
)

const retryLogInterval = time.Minute

type retryLog struct {
	failures uint
	reason   string
	lastLog  time.Time
}

func (r *retryLog) failed(message string, err error, delay time.Duration) {
	r.failures++
	reason := retryReason(err)
	now := time.Now()
	if reason == r.reason && now.Sub(r.lastLog) < retryLogInterval {
		return
	}
	r.reason, r.lastLog = reason, now
	slog.Warn(message, "reason", reason, "retry_delay", delay, "consecutive_failures", r.failures)
}

func (r *retryLog) recovered(message string) {
	if r.failures > 0 {
		slog.Info(message, "consecutive_failures", r.failures)
		*r = retryLog{}
	}
}

// Return only fixed categories. Transport and RPC error text can include
// upstream URLs, server-provided details and local paths.
func retryReason(err error) string {
	switch {
	case errors.Is(err, errCAPinMismatch):
		return "CA_PIN_MISMATCH"
	case errors.Is(err, errALPNMismatch):
		return "ALPN_MISMATCH"
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	case errors.Is(err, context.Canceled):
		return "SESSION_CANCELED"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "STREAM_CLOSED"
	}
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return "TLS_CERTIFICATE_INVALID"
	}
	// Pin verification calls x509.Verify directly, which returns these errors unwrapped.
	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return "TLS_HOSTNAME_MISMATCH"
	}
	if _, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		return "TLS_CERTIFICATE_INVALID"
	}
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		return "TLS_CERTIFICATE_UNTRUSTED"
	}
	if op, ok := errors.AsType[*net.OpError](err); ok {
		if op.Op == "remote error" || op.Op == "local error" {
			return "TLS_HANDSHAKE_FAILED"
		}
		return "NETWORK_ERROR"
	}
	if _, ok := errors.AsType[*os.PathError](err); ok {
		return "LOCAL_IO_ERROR"
	}
	if rpc, ok := errors.AsType[*connect.Error](err); ok {
		if rpc.Code() == connect.CodeUnimplemented && rpc.Message() == "agent version unsupported" {
			return "VERSION_UNSUPPORTED"
		}
		return "RPC_" + strings.ToUpper(rpc.Code().String())
	}
	reason := err.Error()
	switch reason {
	case "HELLO_TIMEOUT", "HEARTBEAT_TIMEOUT", "INVALID_GATEWAY_HELLO", "INVALID_CONNECTION_LIMITS",
		"INVALID_RECONNECT", "INVALID_HEARTBEAT", "INVALID_TASK", "UNKNOWN_MESSAGE", "SEND_QUEUE_FULL",
		"CATALOG_QUEUE_FULL", "RECEIVE_LIMIT_EXCEEDED", "TASK_HISTORY_LIMIT_EXCEEDED", "INVALID_HOST_CERTIFICATE",
		"INVALID_HOST_IDENTITY", "INVALID_HOST_CA":
		return reason
	default:
		return "UNEXPECTED_ERROR"
	}
}
