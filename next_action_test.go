package payhub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fixtureDoc struct {
	Fixtures []struct {
		Name       string          `json:"name"`
		ExpectKind string          `json:"expect_kind"`
		JSON       json.RawMessage `json:"json"`
	} `json:"fixtures"`
}

func TestDecodeNextAction(t *testing.T) {
	path := filepath.Join("..", "shared", "test-vectors", "next-action-fixtures.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc fixtureDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, f := range doc.Fixtures {
		f := f
		t.Run(f.Name, func(t *testing.T) {
			got, err := decodeNextAction(f.JSON)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			var name string
			switch got.(type) {
			case OtpRequired:
				name = "OtpRequired"
			case Redirect:
				name = "Redirect"
			case QR:
				name = "QR"
			case Lightbox:
				name = "Lightbox"
			default:
				t.Fatalf("unknown variant: %T", got)
			}
			if name != f.ExpectKind {
				t.Fatalf("expected %s, got %s", f.ExpectKind, name)
			}
		})
	}
}

func TestDecodeNextActionUnknownDiscriminator(t *testing.T) {
	_, err := decodeNextAction(json.RawMessage(`{"type":"bogus"}`))
	if err == nil {
		t.Fatal("expected error")
	}
}
