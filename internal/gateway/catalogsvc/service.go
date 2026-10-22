package catalogsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
)

type Service struct {
	Store                            *store.Store
	Trusted                          map[string]ed25519.PublicKey
	MaxEnvelopeBytes, MaxActionBytes int
	MaxReferenceBytes                int
}

// Publish accepts a completed upload. Verification precedes a single atomic
// publication transaction. Raw envelope bytes are never reconstructed.
func (s *Service) Publish(ctx context.Context, raw []byte) (*catalog.Package, error) {
	p, err := s.Verify(raw)
	if err != nil {
		return nil, err
	}
	names := slices.Sorted(slices.Values(actionNames(p)))
	digest := sha256.Sum256(raw)
	if err := s.Store.Publish(ctx, db.InsertCatalogParams{CatalogID: p.CatalogID, Version: p.Version, Dsse: raw, Digest: digest[:], ExpiresAt: store.Timestamp(p.ExpiresAt), ActionNames: names}); err != nil {
		return nil, err
	}
	return p, nil
}

func actionNames(p *catalog.Package) []string {
	names := make([]string, 0, len(p.Actions))
	for name := range p.Actions {
		names = append(names, name)
	}
	return names
}

// Verify is shared by completed P4B uploads and direct P4 publication.
func (s *Service) Verify(raw []byte) (*catalog.Package, error) {
	if len(raw) == 0 || len(raw) > s.MaxEnvelopeBytes {
		return nil, fmt.Errorf("DSSE size limit exceeded")
	}
	e, err := catalog.ParseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	p, err := catalog.Verify(e, s.Trusted, catalog.VerifyOptions{})
	if err != nil {
		return nil, err
	}
	maxReference := s.MaxReferenceBytes
	if maxReference == 0 {
		maxReference = (1 << 20) - (64 << 10) - 1024
	}
	if len(p.CatalogID) > maxReference {
		return nil, fmt.Errorf("catalog reference exceeds transport limit")
	}
	for _, action := range p.Actions {
		b, err := json.Marshal(action)
		if err != nil {
			return nil, err
		}
		if len(b) > s.MaxActionBytes {
			return nil, fmt.Errorf("action size limit exceeded")
		}
	}
	return p, nil
}
