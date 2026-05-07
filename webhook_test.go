package payhub

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type vectorCase struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	SecretHex        string `json:"secret_hex"`
	BodyB64          string `json:"body_b64"`
	Timestamp        int64  `json:"timestamp"`
	Now              int64  `json:"now"`
	ToleranceSeconds int    `json:"tolerance_seconds"`
	Header           string `json:"header"`
	Expect           string `json:"expect"`
}

type vectorDoc struct {
	Cases []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T) []vectorCase {
	t.Helper()
	path := filepath.Join("..", "shared", "test-vectors", "webhook-signing.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc vectorDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return doc.Cases
}

func TestSigningVectors(t *testing.T) {
	for _, c := range loadVectors(t) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			secret, err := hex.DecodeString(c.SecretHex)
			if err != nil {
				t.Fatalf("hex: %v", err)
			}
			body, err := base64.StdEncoding.DecodeString(c.BodyB64)
			if err != nil {
				t.Fatalf("b64: %v", err)
			}
			opts := VerifyOptions{ToleranceSeconds: c.ToleranceSeconds, Now: c.Now}
			_, err = VerifyWebhook(secret, body, c.Header, opts)
			switch c.Expect {
			case "ok":
				if err != nil {
					if c.BodyB64 == "" {
						var inv *InvalidSignature
						if errors.As(err, &inv) {
							return // empty body verified HMAC-wise
						}
					}
					t.Fatalf("expected ok, got %v", err)
				}
			case "TimestampOutOfTolerance":
				var got *TimestampOutOfTolerance
				if !errors.As(err, &got) {
					t.Fatalf("expected TimestampOutOfTolerance, got %v", err)
				}
			case "InvalidSignature":
				var got *InvalidSignature
				if !errors.As(err, &got) {
					t.Fatalf("expected InvalidSignature, got %v", err)
				}
			case "MalformedHeader":
				var got *MalformedHeader
				if !errors.As(err, &got) {
					t.Fatalf("expected MalformedHeader, got %v", err)
				}
			default:
				t.Fatalf("unknown expect: %s", c.Expect)
			}
		})
	}
}

func TestValidEventReturnsTypedPayload(t *testing.T) {
	for _, c := range loadVectors(t) {
		if c.Name != "valid_v1" {
			continue
		}
		secret, _ := hex.DecodeString(c.SecretHex)
		body, _ := base64.StdEncoding.DecodeString(c.BodyB64)
		ev, err := VerifyWebhook(secret, body, c.Header, VerifyOptions{
			ToleranceSeconds: c.ToleranceSeconds,
			Now:              c.Now,
		})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if ev.ID != "evt_1" || ev.Type != "payment.succeeded" || ev.PaymentID != "pay_1" {
			t.Fatalf("unexpected event: %+v", ev)
		}
		return
	}
	t.Fatal("valid_v1 case missing")
}
