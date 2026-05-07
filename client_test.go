package payhub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func paymentBody() string {
	return `{"id":"pay_1","status":"requires_action","psp":"sadad","psp_ref":"TXN_1","next_action":{"type":"otp_required","psp_ref":"TXN_1","masked_destination":"2189...12"},"amount_minor":4500,"currency":"LYD","merchant_order_ref":"ord-1"}`
}

func TestCreateDecodesPayment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer phk_a.b" {
			t.Errorf("missing/wrong Authorization: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Idempotency-Key") == "" {
			t.Error("missing Idempotency-Key")
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(paymentBody()))
	}))
	defer srv.Close()
	c, err := New("phk_a.b", Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Payments().Create(context.Background(), CreatePaymentRequest{
		PSP: "sadad", MerchantOrderRef: "ord-1", AmountMinor: 4500,
		Customer: map[string]any{"msisdn": "218910000001", "birth_year": 1990},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "requires_action" {
		t.Errorf("status: %s", p.Status)
	}
	if _, ok := p.NextAction.(OtpRequired); !ok {
		t.Errorf("expected OtpRequired, got %T", p.NextAction)
	}
}

func TestRejectsBadAPIKey(t *testing.T) {
	if _, err := New("not-a-key"); err == nil {
		t.Fatal("expected error")
	}
}

func TestMaps401ToAuthentication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"code":"hub.unauthenticated","message":"no"}}`))
	}))
	defer srv.Close()
	c, _ := New("phk_a.b", Options{BaseURL: srv.URL, MaxRetries: -1})
	_, err := c.Health().Check(context.Background())
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
}

func TestMaps409ToIdempotencyConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"error":{"code":"hub.idempotency_conflict","message":"dup"}}`))
	}))
	defer srv.Close()
	c, _ := New("phk_a.b", Options{BaseURL: srv.URL, MaxRetries: -1})
	_, err := c.Payments().Create(context.Background(), CreatePaymentRequest{
		PSP: "sadad", MerchantOrderRef: "x", AmountMinor: 100,
		Customer: map[string]any{"msisdn": "218910000001", "birth_year": 1990},
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}
}

func TestRetriesOn503ThenSucceeds(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"code":"hub.unavailable","message":"x"}}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok","psps":["sadad"]}`))
	}))
	defer srv.Close()
	c, _ := New("phk_a.b", Options{BaseURL: srv.URL, MaxRetries: 2})
	h, err := c.Health().Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "ok" {
		t.Fatal("status")
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
}

func TestErrorEnvelopeFieldsExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(422)
		_, _ = w.Write([]byte(`{"error":{"code":"hub.invalid_amount","message":"bad","details":{"field":"amount_minor"},"request_id":"req_42"}}`))
	}))
	defer srv.Close()
	c, _ := New("phk_a.b", Options{BaseURL: srv.URL, MaxRetries: -1})
	_, err := c.Health().Check(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %v", err)
	}
	if apiErr.Code != "hub.invalid_amount" || apiErr.RequestID != "req_42" {
		t.Fatalf("envelope not propagated: %+v", apiErr)
	}
	if !strings.Contains(apiErr.Error(), "req_42") {
		t.Fatalf("Error() should include request_id: %s", apiErr.Error())
	}
	var b []byte
	b, _ = json.Marshal(apiErr.Details)
	if !strings.Contains(string(b), "amount_minor") {
		t.Fatalf("details lost: %s", b)
	}
}
