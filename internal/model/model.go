package model

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"
)

type AppID string // must exist in the app registry

type Binding struct {
	App AppID  `json:"app"`
	Env string `json:"env"` // suffix only; delivered as NEBARI_SECRET_<Env>
}

type Grant struct {
	Kind    string `json:"kind"` // "user" | "group"; unused in MVP
	Subject string `json:"subject"`
}

type SecretEntry struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Sealed      []byte    `json:"sealed"` // nonce || AES-256-GCM ciphertext and tag; base64 in JSON; plaintext <= 32 KiB
	Bindings    []Binding `json:"bindings,omitempty"`
	Grants      []Grant   `json:"grants,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type WrappedKey struct {
	KEKID      string `json:"kekId"`      // master key that wrapped it
	Ciphertext []byte `json:"ciphertext"` // the wrapped 256-bit data key; base64 in JSON
}

type OwnerRecord struct {
	SchemaVersion int           `json:"schemaVersion"` // 1
	OwnerSub      string        `json:"ownerSub"`
	OwnerUsername string        `json:"ownerUsername"`
	DataKey       WrappedKey    `json:"dataKey"`
	Secrets       []SecretEntry `json:"secrets"` // <= 50; encoded record <= 512 KiB
}

type DeliveryStatus struct {
	App         AppID     `json:"app"`
	LastOK      time.Time `json:"lastOk,omitempty"`
	LastCount   int       `json:"lastCount,omitempty"`
	LastFailure time.Time `json:"lastFailure,omitempty"`
	LastReason  string    `json:"lastReason,omitempty"`
}

type Principal struct {
	Kind     string // "user" in the MVP; "service-account" later
	Sub      string
	Username string // empty when the principal comes from a pod annotation
	Groups   []string
}

type PodIdentity struct{ Namespace, Name, UID, ServiceAccount string }

type PodClaim struct {
	Pod       PodIdentity
	App       AppID
	Principal Principal
}

type GuardMode string // "enforced" | "overridden"

type ResolvedSecret struct {
	Env   string
	Value []byte
}

// Management API wire types. These are the contract nebari-landing builds against.
type BindingView struct {
	App  AppID  `json:"app"`
	Env  string `json:"env"`  // suffix as stored
	Name string `json:"name"` // NEBARI_SECRET_<Env>
	Path string `json:"path"` // /var/run/nebari/secrets/NEBARI_SECRET_<Env>
}

type SecretSummary struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Bindings    []BindingView `json:"bindings"`
	UpdatedAt   time.Time     `json:"updatedAt"`
}

type Usage struct {
	Count    int `json:"count"`    // secrets stored
	MaxCount int `json:"maxCount"` // 50
	Bytes    int `json:"bytes"`    // size of the encoded record.json, the quantity the 512 KiB limit applies to
	MaxBytes int `json:"maxBytes"` // 524288
}

type OwnerView struct { // GET /api/v1/secrets
	Secrets    []SecretSummary  `json:"secrets"`
	Deliveries []DeliveryStatus `json:"deliveries"` // per app, not per secret: an app's last failure may concern no secret
	Usage      Usage            `json:"usage"`
}

type APIError struct { // body of every management API error
	Error  string `json:"error"`            // machine-readable code, listed under "Management API"
	Detail string `json:"detail,omitempty"` // human-readable; never contains a value
}

type Creator struct {
	Username   string // system:serviceaccount:<ns>:<name>
	Namespaces []string
	Apps       []AppID
}

var (
	secretNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	suffixRE        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	deliveredNameRE = regexp.MustCompile(`^NEBARI_SECRET_[A-Z][A-Z0-9_]{0,63}$`)
)

// deliveredPrefix is prepended to a binding's env suffix to form the name of
// the delivered file and environment variable.
const deliveredPrefix = "NEBARI_SECRET_"

// SecretName returns the name of the owner's Kubernetes Secret: "us-" plus the
// first 32 hex characters of the SHA-256 of the Keycloak sub. The sub itself
// cannot be used because federated users have ids such as f:<component>:<user>,
// which are not valid Secret names. The record's ownerSub is checked on read.
func SecretName(ownerSub string) string {
	sum := sha256.Sum256([]byte(ownerSub))
	return "us-" + hex.EncodeToString(sum[:])[:32]
}

// StatusSecretName returns the name of the owner's delivery status Secret.
func StatusSecretName(ownerSub string) string {
	return SecretName(ownerSub) + "-status"
}

// DeliveredName returns the delivered name for a binding env suffix.
func DeliveredName(suffix string) string {
	return deliveredPrefix + suffix
}

// ValidSecretName reports whether s is an acceptable user secret name.
func ValidSecretName(s string) bool { return secretNameRE.MatchString(s) }

// ValidSuffix reports whether s is an acceptable binding env suffix.
func ValidSuffix(s string) bool { return suffixRE.MatchString(s) }

// ValidDeliveredName reports whether s is an acceptable delivered name.
func ValidDeliveredName(s string) bool { return deliveredNameRE.MatchString(s) }
