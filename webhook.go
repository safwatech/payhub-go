package payhub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WebhookSignatureError is the base for webhook verification failures.
var WebhookSignatureError = errors.New("payhub: webhook signature error")

// MalformedHeader fires when Hub-Signature is missing t= or v1=.
type MalformedHeader struct{ Reason string }

func (e *MalformedHeader) Error() string { return "payhub: malformed Hub-Signature: " + e.Reason }
func (e *MalformedHeader) Is(target error) bool {
	return target == WebhookSignatureError
}

// TimestampOutOfTolerance fires when |now - t| > tolerance.
type TimestampOutOfTolerance struct{ SkewSeconds int }

func (e *TimestampOutOfTolerance) Error() string {
	return fmt.Sprintf("payhub: webhook timestamp out of tolerance: %ds skew", e.SkewSeconds)
}
func (e *TimestampOutOfTolerance) Is(target error) bool {
	return target == WebhookSignatureError
}

// InvalidSignature fires when the HMAC doesn't match (or body isn't JSON).
type InvalidSignature struct{ Reason string }

func (e *InvalidSignature) Error() string { return "payhub: invalid webhook signature: " + e.Reason }
func (e *InvalidSignature) Is(target error) bool {
	return target == WebhookSignatureError
}

// WebhookEventPayload is the typed event body, returned on successful verify.
type WebhookEventPayload struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	PaymentID  string         `json:"payment_id"`
	PrevStatus *string        `json:"prev_status"`
	NewStatus  string         `json:"new_status"`
	Source     string         `json:"source"`
	Payload    map[string]any `json:"payload"`
	CreatedAt  string         `json:"created_at"`
}

// VerifyOptions tweak the verifier.
type VerifyOptions struct {
	ToleranceSeconds int
	Now              int64 // unix seconds; 0 means time.Now()
}

const defaultToleranceSeconds = 300

// VerifyWebhook checks a Hub-Signature header against secret + raw body
// and returns the typed event payload. Always raises on any failure mode
// — there is no boolean variant.
func VerifyWebhook(secret, body []byte, header string, opts ...VerifyOptions) (*WebhookEventPayload, error) {
	o := VerifyOptions{}
	if len(opts) > 0 {
		o = opts[0]
	}
	tolerance := o.ToleranceSeconds
	if tolerance == 0 {
		tolerance = defaultToleranceSeconds
	}
	now := o.Now
	if now == 0 {
		now = time.Now().Unix()
	}

	t, v1, err := parseSignatureHeader(header)
	if err != nil {
		return nil, err
	}

	skew := now - t
	if skew < 0 {
		skew = -skew
	}
	if int(skew) > tolerance {
		return nil, &TimestampOutOfTolerance{SkewSeconds: int(skew)}
	}

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(strconv.FormatInt(t, 10) + "."))
	_, _ = mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(v1)) {
		return nil, &InvalidSignature{Reason: "v1 does not match"}
	}

	if len(body) == 0 {
		return nil, &InvalidSignature{Reason: "empty body / not JSON"}
	}
	var ev WebhookEventPayload
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, &InvalidSignature{Reason: "body is not JSON: " + err.Error()}
	}
	return &ev, nil
}

func parseSignatureHeader(header string) (int64, string, error) {
	parts := map[string]string{}
	for _, seg := range strings.Split(header, ",") {
		eq := strings.Index(seg, "=")
		if eq <= 0 {
			continue
		}
		parts[strings.TrimSpace(seg[:eq])] = strings.TrimSpace(seg[eq+1:])
	}
	tRaw, okT := parts["t"]
	v1, okV := parts["v1"]
	if !okT || !okV {
		return 0, "", &MalformedHeader{Reason: "missing t= or v1="}
	}
	t, err := strconv.ParseInt(tRaw, 10, 64)
	if err != nil {
		return 0, "", &MalformedHeader{Reason: "t is not an integer: " + tRaw}
	}
	return t, v1, nil
}
