package catalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const PayloadType = "application/vnd.allowops.catalog.v1+json"
const ClockSkew = 5 * time.Minute

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type SigningKey struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

type VerifyOptions struct {
	Now            time.Time
	HighestVersion int64
}

func KeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// PAE is DSSE's pre-authentication encoding. Lengths count bytes, not characters.
func PAE(payloadType string, payload []byte) []byte {
	header := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	return append([]byte(header), payload...)
}

func Sign(payload []byte, keys ...SigningKey) (*Envelope, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one signing key required")
	}
	e := &Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: []Signature{}}
	for _, key := range keys {
		if err := AddSignature(e, key); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func AddSignature(e *Envelope, key SigningKey) error {
	if e == nil || e.PayloadType != PayloadType {
		return fmt.Errorf("unsupported DSSE payload type")
	}
	if len(key.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key length")
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return fmt.Errorf("invalid DSSE payload: %w", err)
	}
	id := key.KeyID
	if id == "" {
		id = KeyID(key.PrivateKey.Public().(ed25519.PublicKey))
	}
	sig := ed25519.Sign(key.PrivateKey, PAE(e.PayloadType, payload))
	e.Signatures = append(e.Signatures, Signature{KeyID: id, Sig: base64.StdEncoding.EncodeToString(sig)})
	return nil
}

// Reject duplicate JSON members, unknown fields, and trailing documents.
func strictJSON(data []byte, out any) error {
	checker := json.NewDecoder(bytes.NewReader(data))
	checker.UseNumber()
	if err := checkJSONValue(checker); err != nil {
		return err
	}
	if _, err := checker.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func checkJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid JSON member %q", name)
			}
			seen[name] = true
			if err := checkJSONValue(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkJSONValue(d); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func ParseEnvelope(data []byte) (*Envelope, error) {
	var e *Envelope
	if err := strictJSON(data, &e); err != nil {
		return nil, err
	}
	if e == nil || e.PayloadType != PayloadType {
		return nil, fmt.Errorf("unsupported DSSE envelope or payload type")
	}
	if _, err := base64.StdEncoding.DecodeString(e.Payload); err != nil {
		return nil, fmt.Errorf("invalid DSSE payload encoding: %w", err)
	}
	return e, nil
}

func ParsePackage(data []byte) (*Package, error) {
	var p *Package
	if err := strictJSON(data, &p); err != nil {
		return nil, err
	}
	if err := validatePackage(p); err != nil {
		return nil, err
	}
	return p, nil
}

func validatePackage(p *Package) error {
	if p == nil {
		return fmt.Errorf("catalog package required")
	}
	if err := validateConfig(Config{CatalogID: p.CatalogID, SchemaVersion: p.SchemaVersion}); err != nil {
		return err
	}
	if p.Version <= 0 || p.CreatedAt.IsZero() || !p.ExpiresAt.After(p.CreatedAt) {
		return fmt.Errorf("invalid catalog version or validity interval")
	}
	if len(p.Actions) == 0 || len(p.Actions) != len(p.Digests) {
		return fmt.Errorf("action/digest count mismatch or empty catalog")
	}
	for name, a := range p.Actions {
		if name != a.Name {
			return fmt.Errorf("action key/name mismatch")
		}
		if _, err := validateAction(a, true); err != nil {
			return err
		}
		digest, err := ActionDigest(a)
		if err != nil {
			return err
		}
		if digest != p.Digests[name] {
			return fmt.Errorf("action %s digest mismatch", name)
		}
	}
	return nil
}

// Verify authenticates the bytes before interpreting their metadata or actions.
// HighestVersion is supplied by the host agent's separately protected persistent state (design P3).
func Verify(e *Envelope, trusted map[string]ed25519.PublicKey, opts VerifyOptions) (*Package, error) {
	if e == nil || e.PayloadType != PayloadType {
		return nil, fmt.Errorf("unsupported DSSE payload type")
	}
	if len(e.Signatures) == 0 {
		return nil, fmt.Errorf("DSSE envelope has no signatures")
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid DSSE payload: %w", err)
	}
	authenticated := false
	message := PAE(e.PayloadType, payload)
	for _, signature := range e.Signatures {
		sig, err := base64.StdEncoding.DecodeString(signature.Sig)
		if err != nil {
			continue
		}
		if signature.KeyID != "" {
			key := trusted[signature.KeyID]
			if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message, sig) {
				authenticated = true
				break
			}
		} else {
			for _, key := range trusted {
				if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message, sig) {
					authenticated = true
					break
				}
			}
			if authenticated {
				break
			}
		}
	}
	if !authenticated {
		return nil, fmt.Errorf("no valid signature from a trusted ed25519 key")
	}
	p, err := ParsePackage(payload)
	if err != nil {
		return nil, err
	}
	canonical, err := CanonicalJSON(p)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(payload, canonical) {
		return nil, fmt.Errorf("catalog payload must be canonical JSON")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Add(ClockSkew).Before(p.CreatedAt) {
		return nil, fmt.Errorf("catalog not yet valid (clock skew exceeds 5 minutes)")
	}
	if now.After(p.ExpiresAt.Add(ClockSkew)) {
		return nil, fmt.Errorf("catalog expired")
	}
	if p.Version < opts.HighestVersion {
		return nil, fmt.Errorf("catalog version rollback: %d < %d", p.Version, opts.HighestVersion)
	}
	return p, nil
}
