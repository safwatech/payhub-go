// Package payhub is the official PayHub SDK for Go.
//
// Surface mirrors the canonical PayHub SDK shape. Sync, context-first,
// errors as sentinel-comparable values via errors.Is plus a typed
// *APIError carrying the full server envelope. Webhook verification is
// in webhook.go.
package payhub

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Version of this SDK; bumped per /sdks/release-please-config.json.
const Version = "1.0.0"

const (
	defaultBaseURL = "https://app.payhub.ly"
	defaultTimeout = 30 * time.Second
	defaultRetries = 2
)

// Client is a PayHub HTTP client. Construct via New; share a single
// instance across goroutines — methods are safe for concurrent use.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	maxRetries int
	userAgent  string
}

// Options configure a Client.
type Options struct {
	BaseURL         string
	Timeout         time.Duration
	MaxRetries      int
	HTTPClient      *http.Client
	UserAgentSuffix string
}

// New constructs a Client. apiKey must start with "phk_".
func New(apiKey string, opts ...Options) (*Client, error) {
	if !strings.HasPrefix(apiKey, "phk_") {
		return nil, fmt.Errorf("payhub: api key must start with %q", "phk_")
	}
	o := Options{}
	if len(opts) > 0 {
		o = opts[0]
	}
	baseURL := o.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	retries := o.MaxRetries
	if retries == 0 {
		retries = defaultRetries
	}
	hc := o.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: timeout}
	}
	ua := fmt.Sprintf("payhub-go/%s (%s/%s)", Version, runtime.GOOS, runtime.Version())
	if o.UserAgentSuffix != "" {
		ua = ua + " " + o.UserAgentSuffix
	}
	return &Client{
		apiKey:     apiKey,
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: hc,
		maxRetries: retries,
		userAgent:  ua,
	}, nil
}

// Payments returns the payments resource.
func (c *Client) Payments() *PaymentsResource { return &PaymentsResource{c: c} }

// Health returns the health resource.
func (c *Client) Health() *HealthResource { return &HealthResource{c: c} }

// CreatePaymentRequest is the body of POST /v1/payments.
type CreatePaymentRequest struct {
	PSP              string         `json:"psp"`
	MerchantOrderRef string         `json:"merchant_order_ref"`
	AmountMinor      int64          `json:"amount_minor"`
	Currency         string         `json:"currency,omitempty"`
	Customer         map[string]any `json:"customer"`
	ReturnUrls       map[string]any `json:"return_urls,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	HostedCheckout   bool           `json:"hosted_checkout,omitempty"`
}

// Payment is the typed response from the v1 endpoints.
type Payment struct {
	ID                string     `json:"id"`
	Status            string     `json:"status"`
	PSP               string     `json:"psp"`
	PSPRef            *string    `json:"psp_ref"`
	NextAction        NextAction `json:"-"`
	AmountMinor       int64      `json:"amount_minor"`
	Currency          string     `json:"currency"`
	MerchantOrderRef  string     `json:"merchant_order_ref"`
	HostedCheckoutURL *string    `json:"hosted_checkout_url,omitempty"`
}

func (p *Payment) UnmarshalJSON(b []byte) error {
	type rawP struct {
		ID                string          `json:"id"`
		Status            string          `json:"status"`
		PSP               string          `json:"psp"`
		PSPRef            *string         `json:"psp_ref"`
		NextAction        json.RawMessage `json:"next_action"`
		AmountMinor       int64           `json:"amount_minor"`
		Currency          string          `json:"currency"`
		MerchantOrderRef  string          `json:"merchant_order_ref"`
		HostedCheckoutURL *string         `json:"hosted_checkout_url,omitempty"`
	}
	var r rawP
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	p.ID = r.ID
	p.Status = r.Status
	p.PSP = r.PSP
	p.PSPRef = r.PSPRef
	p.AmountMinor = r.AmountMinor
	p.Currency = r.Currency
	p.MerchantOrderRef = r.MerchantOrderRef
	p.HostedCheckoutURL = r.HostedCheckoutURL
	if len(r.NextAction) > 0 && string(r.NextAction) != "null" {
		na, err := decodeNextAction(r.NextAction)
		if err != nil {
			return err
		}
		p.NextAction = na
	}
	return nil
}

// Health is the response of GET /v1/health.
type Health struct {
	Status string   `json:"status"`
	PSPs   []string `json:"psps"`
}

// PaymentsResource hosts the /v1/payments methods.
type PaymentsResource struct{ c *Client }

// CallOption tweaks a single API call.
type CallOption func(*callOpts)

type callOpts struct {
	idempotencyKey string
}

// WithIdempotencyKey overrides the SDK-minted UUID4 idempotency key.
func WithIdempotencyKey(key string) CallOption { return func(o *callOpts) { o.idempotencyKey = key } }

// Create initiates a new payment.
func (r *PaymentsResource) Create(ctx context.Context, body CreatePaymentRequest, opts ...CallOption) (*Payment, error) {
	o := applyOpts(opts)
	key := o.idempotencyKey
	if key == "" {
		var err error
		key, err = uuid4()
		if err != nil {
			return nil, err
		}
	}
	var p Payment
	if err := r.c.do(ctx, http.MethodPost, "/v1/payments", body, key, true, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ConfirmOTP submits an OTP code for a Sadad payment in REQUIRES_ACTION state.
func (r *PaymentsResource) ConfirmOTP(ctx context.Context, paymentID, code string, opts ...CallOption) (*Payment, error) {
	o := applyOpts(opts)
	key := o.idempotencyKey
	if key == "" {
		var err error
		key, err = uuid4()
		if err != nil {
			return nil, err
		}
	}
	var p Payment
	body := map[string]string{"code": code}
	if err := r.c.do(ctx, http.MethodPost, "/v1/payments/"+paymentID+"/otp", body, key, true, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// RefundRequest is the body of POST /v1/payments/{id}/refund.
type RefundRequest struct {
	AmountMinor *int64  `json:"amount_minor,omitempty"`
	Reason      *string `json:"reason,omitempty"`
}

// Refund issues a (full or partial) refund on a SUCCEEDED payment.
func (r *PaymentsResource) Refund(ctx context.Context, paymentID string, body RefundRequest, opts ...CallOption) (*Payment, error) {
	o := applyOpts(opts)
	key := o.idempotencyKey
	if key == "" {
		var err error
		key, err = uuid4()
		if err != nil {
			return nil, err
		}
	}
	var p Payment
	if err := r.c.do(ctx, http.MethodPost, "/v1/payments/"+paymentID+"/refund", body, key, true, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Retrieve fetches the current state of a payment.
func (r *PaymentsResource) Retrieve(ctx context.Context, paymentID string) (*Payment, error) {
	var p Payment
	if err := r.c.do(ctx, http.MethodGet, "/v1/payments/"+paymentID, nil, "", true, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// HealthResource hosts /v1/health.
type HealthResource struct{ c *Client }

// Check returns the hub's reported PSP registry.
func (r *HealthResource) Check(ctx context.Context) (*Health, error) {
	var h Health
	if err := r.c.do(ctx, http.MethodGet, "/v1/health", nil, "", true, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func applyOpts(opts []CallOption) callOpts {
	o := callOpts{}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

func uuid4() (string, error) {
	var b [16]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return "", fmt.Errorf("payhub: rand: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:]), nil
}

func backoff(attempt int) time.Duration {
	base := time.Duration(500*(1<<attempt)) * time.Millisecond
	jitter := 0.8 + mathrand.Float64()*0.4
	return time.Duration(float64(base) * jitter)
}

func (c *Client) do(ctx context.Context, method, path string, body any, idempotencyKey string, retriable bool, dst any) error {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("payhub: marshal: %w", err)
		}
	}
	url := c.baseURL + path
	attempts := 1
	if retriable {
		attempts += c.maxRetries
	}
	if attempts < 1 {
		attempts = 1 // negative MaxRetries means "no retries", but always at least one attempt
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("payhub: build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if idempotencyKey != "" {
			req.Header.Set("Idempotency-Key", idempotencyKey)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = wrapTransport(err)
			if retriable && attempt+1 < attempts {
				time.Sleep(backoff(attempt))
				continue
			}
			return lastErr
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if dst == nil || len(respBody) == 0 {
				return nil
			}
			if err := json.Unmarshal(respBody, dst); err != nil {
				return &TransportError{Kind: "decode", Cause: err.Error()}
			}
			return nil
		}
		apiErr := decodeAPIError(resp.StatusCode, resp.Header, respBody)
		if retriable && (resp.StatusCode >= 500 || resp.StatusCode == 429) && attempt+1 < attempts {
			wait := backoff(attempt)
			if ra := parseRetryAfter(resp.Header.Get("Retry-After")); ra > 0 {
				wait = ra
			}
			time.Sleep(wait)
			lastErr = apiErr
			continue
		}
		return apiErr
	}
	return lastErr
}

func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if n, err := strconv.Atoi(h); err == nil {
		return time.Duration(n) * time.Second
	}
	return 0
}
