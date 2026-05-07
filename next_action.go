package payhub

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NextAction is the discriminated union returned in Payment.NextAction.
// Implementations are exported so callers type-switch on them.
type NextAction interface {
	isNextAction()
}

// OtpRequired (Sadad).
type OtpRequired struct {
	PSPRef            string `json:"psp_ref"`
	MaskedDestination string `json:"masked_destination"`
	ExpiresAt         string `json:"expires_at,omitempty"`
}

func (OtpRequired) isNextAction() {}

// Redirect (T-Lync).
type Redirect struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Fields    map[string]string `json:"fields"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}

func (Redirect) isNextAction() {}

// QR (Mobicash).
type QR struct {
	Reference string `json:"reference"`
	QRPayload string `json:"qr_payload"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func (QR) isNextAction() {}

// Lightbox (Moamalat).
type Lightbox struct {
	Params    map[string]string `json:"params"`
	ScriptURL string            `json:"script_url,omitempty"`
}

func (Lightbox) isNextAction() {}

func decodeNextAction(raw json.RawMessage) (NextAction, error) {
	var typed struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return nil, fmt.Errorf("payhub: next_action: %w", err)
	}
	switch typed.Type {
	case "otp_required":
		var v OtpRequired
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "redirect":
		var v Redirect
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		v.Method = strings.ToUpper(v.Method)
		if v.Method == "" {
			v.Method = "GET"
		}
		return v, nil
	case "qr":
		var v QR
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "lightbox":
		var v struct {
			Params map[string]string `json:"params"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		l := Lightbox{Params: v.Params}
		if u, ok := v.Params["lightbox_js_url"]; ok {
			l.ScriptURL = u
		}
		return l, nil
	default:
		return nil, fmt.Errorf("payhub: unknown next_action.type %q", typed.Type)
	}
}
