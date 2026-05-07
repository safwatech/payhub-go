package payhub

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Sentinel errors. Subclassed via *APIError below; consumers can use
// errors.Is(err, ErrAuthentication) to branch on the class without
// caring about the embedded server-side message.
var (
	ErrAuthentication      = errors.New("payhub: authentication failed")
	ErrPermission          = errors.New("payhub: permission denied")
	ErrNotFound            = errors.New("payhub: not found")
	ErrValidation          = errors.New("payhub: validation failed")
	ErrIdempotencyConflict = errors.New("payhub: idempotency conflict")
	ErrRateLimited         = errors.New("payhub: rate limited")
	ErrGateway             = errors.New("payhub: upstream gateway error")
	ErrServer              = errors.New("payhub: server error")
	ErrTransport           = errors.New("payhub: transport error")
)

// APIError is the typed wrapper around the server's error envelope.
// Inspect Code (dot-path), HTTPStatus, Details, RequestID; check class
// with errors.Is(err, ErrXxx).
type APIError struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	HTTPStatus int            `json:"-"`
	Details    map[string]any `json:"details,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	RetryAfter int            `json:"-"` // seconds, when server set Retry-After
	sentinel   error
}

// Error implements error.
func (e *APIError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("payhub: %s (%s) [request_id=%s]", e.Message, e.Code, e.RequestID)
	}
	return fmt.Sprintf("payhub: %s (%s)", e.Message, e.Code)
}

// Is reports whether the API error matches the given sentinel.
func (e *APIError) Is(target error) bool { return e.sentinel == target }

// TransportError is returned for network / decode / timeout failures.
// errors.Is(err, ErrTransport) is true for any of these.
type TransportError struct {
	Kind  string // "timeout" | "connect" | "decode"
	Cause string
}

func (e *TransportError) Error() string { return fmt.Sprintf("payhub: %s: %s", e.Kind, e.Cause) }
func (e *TransportError) Is(target error) bool {
	return target == ErrTransport
}

func wrapTransport(err error) error {
	msg := err.Error()
	kind := "connect"
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout") {
		kind = "timeout"
	}
	return &TransportError{Kind: kind, Cause: msg}
}

func decodeAPIError(status int, headers http.Header, body []byte) *APIError {
	var env struct {
		Error struct {
			Code      string         `json:"code"`
			Message   string         `json:"message"`
			Details   map[string]any `json:"details"`
			RequestID string         `json:"request_id"`
		} `json:"error"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &env)
	}
	if env.Error.Code == "" {
		env.Error.Code = "hub.unknown"
		env.Error.Message = fmt.Sprintf("HTTP %d", status)
	}
	out := &APIError{
		Code:       env.Error.Code,
		Message:    env.Error.Message,
		HTTPStatus: status,
		Details:    env.Error.Details,
		RequestID:  env.Error.RequestID,
		sentinel:   classify(status, env.Error.Code),
	}
	if status == 429 {
		out.RetryAfter = int(parseRetryAfter(headers.Get("Retry-After")).Seconds())
	}
	return out
}

func classify(status int, code string) error {
	switch status {
	case 401:
		return ErrAuthentication
	case 403:
		return ErrPermission
	case 404:
		return ErrNotFound
	case 409:
		return ErrIdempotencyConflict
	case 422:
		return ErrValidation
	case 429:
		return ErrRateLimited
	}
	if status >= 500 && status < 600 {
		if strings.HasPrefix(code, "gateway.") {
			return ErrGateway
		}
		return ErrServer
	}
	return nil
}
