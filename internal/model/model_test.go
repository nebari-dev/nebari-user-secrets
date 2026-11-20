package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestSecretName(t *testing.T) {
	const uuid = "0b5a1c3e-7d2f-4a8b-9c61-3e5f7a9b1d20"
	tests := []struct {
		name string
		sub  string
	}{
		{"uuid sub", uuid},
		{"federated sub without import", "f:ldap:alice"},
		{"empty sub", ""},
		{"uppercase and punctuation", "F:Some_Component:Bob.Smith@example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SecretName(tt.sub)
			if !strings.HasPrefix(got, "us-") || len(got) != len("us-")+32 {
				t.Fatalf("SecretName(%q) = %q, want us- plus 32 chars", tt.sub, got)
			}
			hexPart := strings.TrimPrefix(got, "us-")
			if hexPart != strings.ToLower(hexPart) {
				t.Errorf("hex part %q is not lowercase", hexPart)
			}
			for _, c := range hexPart {
				if !strings.ContainsRune("0123456789abcdef", c) {
					t.Fatalf("non-hex character %q in %q", c, got)
				}
			}
			if errs := validation.IsDNS1123Label(got); len(errs) != 0 {
				t.Errorf("SecretName(%q) = %q is not a DNS-1123 label: %v", tt.sub, got, errs)
			}
			if SecretName(tt.sub) != got {
				t.Errorf("SecretName(%q) is not deterministic", tt.sub)
			}
			if want := got + "-status"; StatusSecretName(tt.sub) != want {
				t.Errorf("StatusSecretName(%q) = %q, want %q", tt.sub, StatusSecretName(tt.sub), want)
			}
			if errs := validation.IsDNS1123Label(StatusSecretName(tt.sub)); len(errs) != 0 {
				t.Errorf("status name not a DNS-1123 label: %v", errs)
			}
		})
	}

	if SecretName("alice") == SecretName("bob") {
		t.Error("different subs produced the same name")
	}
}

func TestValidators(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		secretName    bool
		suffix        bool
		deliveredName bool
	}{
		{"valid suffix", "VENDOR_API_KEY", true, true, false},
		{"lowercase", "ld_preload", true, false, false},
		{"equals sign", "A=B", false, false, false},
		{"path traversal", "../x", false, false, false},
		{"empty", "", false, false, false},
		{"leading digit", "1ABC", false, false, false},
		{"leading underscore", "_ABC", true, false, false},
		{"64 chars suffix", "A" + strings.Repeat("B", 63), true, true, false},
		{"65 chars suffix", "A" + strings.Repeat("B", 64), false, false, false},
		{"delivered name", "NEBARI_SECRET_VENDOR_API_KEY", true, true, true},
		{"delivered prefix only", "NEBARI_SECRET_", true, true, false},
		{"delivered lowercase tail", "NEBARI_SECRET_vendor", true, false, false},
		{"delivered trailing newline", "NEBARI_SECRET_VENDOR\n", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidSecretName(tt.input); got != tt.secretName {
				t.Errorf("ValidSecretName(%q) = %v, want %v", tt.input, got, tt.secretName)
			}
			if got := ValidSuffix(tt.input); got != tt.suffix {
				t.Errorf("ValidSuffix(%q) = %v, want %v", tt.input, got, tt.suffix)
			}
			if got := ValidDeliveredName(tt.input); got != tt.deliveredName {
				t.Errorf("ValidDeliveredName(%q) = %v, want %v", tt.input, got, tt.deliveredName)
			}
		})
	}
}

func TestDeliveredName(t *testing.T) {
	tests := []struct{ suffix, want string }{
		{"VENDOR_API_KEY", "NEBARI_SECRET_VENDOR_API_KEY"},
		{"A", "NEBARI_SECRET_A"},
	}
	for _, tt := range tests {
		t.Run(tt.suffix, func(t *testing.T) {
			got := DeliveredName(tt.suffix)
			if got != tt.want {
				t.Errorf("DeliveredName(%q) = %q, want %q", tt.suffix, got, tt.want)
			}
			if !ValidDeliveredName(got) {
				t.Errorf("%q should be a valid delivered name", got)
			}
		})
	}
}

func TestOwnerRecordJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	sealed := []byte{0x00, 0xff, '\n'}
	wrapped := []byte{0x01, 0x00, 0xfe, '\n'}
	in := OwnerRecord{
		SchemaVersion: 1,
		OwnerSub:      "f:ldap:alice",
		OwnerUsername: "alice",
		DataKey:       WrappedKey{KEKID: "kek-1", Ciphertext: wrapped},
		Secrets: []SecretEntry{{
			Name:      "vendor_key",
			Sealed:    sealed,
			Bindings:  []Binding{{App: "jupyter", Env: "VENDOR_API_KEY"}},
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}

	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schemaVersion", "ownerSub", "dataKey", "secrets"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("record JSON lacks key %q: %s", key, raw)
		}
	}
	var secrets []map[string]json.RawMessage
	if err := json.Unmarshal(generic["secrets"], &secrets); err != nil {
		t.Fatal(err)
	}
	if _, ok := secrets[0]["sealed"]; !ok {
		t.Errorf("secret entry JSON lacks key sealed: %s", raw)
	}

	var out OwnerRecord
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Secrets[0].Sealed, sealed) {
		t.Errorf("Sealed = %x, want %x", out.Secrets[0].Sealed, sealed)
	}
	if !bytes.Equal(out.DataKey.Ciphertext, wrapped) || out.DataKey.KEKID != "kek-1" {
		t.Errorf("DataKey = %+v, want round trip", out.DataKey)
	}
	if out.OwnerSub != in.OwnerSub || out.SchemaVersion != 1 {
		t.Errorf("record fields lost: %+v", out)
	}
}
