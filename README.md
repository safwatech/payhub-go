# payhub-go

Official PayHub SDK for Go. Sync, context-first, zero non-stdlib runtime
deps.

```
go get github.com/safwatech/payhub-go
```

> **PayHub API:** v1 · **Go:** ≥1.21 · **License:** MIT

## 1. Authenticate

```go
import payhub "github.com/safwatech/payhub-go"

client, err := payhub.New("phk_<id>.<secret>", payhub.Options{
    BaseURL: "https://app.payhub.ly",
})
if err != nil { /* bad api key */ }
```

## 2. Your first payment — Sadad OTP, end to end

```go
ctx := context.Background()

p, err := client.Payments().Create(ctx, payhub.CreatePaymentRequest{
    PSP:              "sadad",
    MerchantOrderRef: "ord-42",
    AmountMinor:      4500, // 4.5 LYD
    Customer: map[string]any{
        "msisdn":     "218910000001", // mandatory for Sadad
        "birth_year": 1990,            // mandatory for Sadad
    },
})
if err != nil { return err }

switch na := p.NextAction.(type) {
case payhub.OtpRequired:
    fmt.Printf("OTP sent to %s\n", na.MaskedDestination)
}

// Customer types the code into your form; you POST it back.
settled, err := client.Payments().ConfirmOTP(ctx, p.ID, "123456")
fmt.Println(settled.Status) // "succeeded" or "failed"
```

The SDK auto-mints a UUID4 idempotency key. Override with
`payhub.WithIdempotencyKey("your-key")`.

## 3. Webhook receiver (net/http)

> ⚠️ **Pass the raw request bytes, never a parsed struct.** Re-encoding
> JSON changes whitespace and breaks the HMAC. Use `io.ReadAll(r.Body)`.

```go
http.HandleFunc("/webhooks/payhub", func(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    sig := r.Header.Get("Hub-Signature")
    if sig == "" { http.Error(w, "missing signature", 400); return }

    ev, err := payhub.VerifyWebhook(
        []byte(os.Getenv("PAYHUB_WEBHOOK_SECRET")),
        body,
        sig,
    )
    if err != nil {
        if errors.Is(err, payhub.WebhookSignatureError) {
            http.Error(w, "invalid signature", 401); return
        }
        http.Error(w, err.Error(), 500); return
    }

    switch ev.Type {
    case "payment.succeeded": /* mark order paid */
    case "payment.failed", "payment.expired": /* unlock cart */
    case "payment.refunded": /* update accounting */
    }
    w.WriteHeader(200)
})
```

For Gin: `c.GetRawData()` returns the raw bytes.

## 4. Errors

API errors come back as `*payhub.APIError`. Use `errors.Is` against the
sentinel for class-level branching, or `errors.As` to extract the
envelope:

```go
_, err := client.Payments().Create(ctx, req)
switch {
case errors.Is(err, payhub.ErrAuthentication):
    /* 401 — bad API key, IP not allowlisted */
case errors.Is(err, payhub.ErrValidation):
    /* 422 — customer.msisdn missing for Sadad, etc. */
case errors.Is(err, payhub.ErrIdempotencyConflict):
    /* 409 — same key reused with a different body */
case errors.Is(err, payhub.ErrRateLimited):
    var ae *payhub.APIError
    errors.As(err, &ae)
    time.Sleep(time.Duration(ae.RetryAfter) * time.Second)
case errors.Is(err, payhub.ErrGateway):
    /* 502 from a gateway.<psp>.* code */
case errors.Is(err, payhub.ErrTransport):
    /* network / timeout / decode */
}
```

The webhook verifier uses three concrete types — all match
`errors.Is(err, payhub.WebhookSignatureError)`:

| Type | Reason |
| --- | --- |
| `*payhub.MalformedHeader` | `Hub-Signature` missing `t=` or `v1=` |
| `*payhub.TimestampOutOfTolerance` | exposes `.SkewSeconds` |
| `*payhub.InvalidSignature` | HMAC mismatch / non-JSON body |

## Configuration

```go
payhub.New("phk_…", payhub.Options{
    BaseURL:         "https://app.payhub.ly",
    Timeout:         30 * time.Second,
    MaxRetries:      2,                          // idempotent calls only
    HTTPClient:      myHTTPClient,               // injection seam
    UserAgentSuffix: "Acme/1.2",
})
```

## Versioning

Independent semver. Compatible with PayHub API v1.

## Development

```
go test ./...
go vet ./...
```

Tests load `../shared/test-vectors/webhook-signing.json` — the canonical
spec consumed by every PayHub SDK and by the server's own
`tests/unit/test_webhook_signing_vectors.py`.
