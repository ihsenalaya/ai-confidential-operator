/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package approval holds the pure, dependency-free logic that binds a human
// AIChangeRequest decision to an Ed25519 signature. It reuses the project's
// Ed25519 primitives (pkg/crypto) — the same key mechanism used for audit-chain
// checkpoint anchoring — so a routing change can only move to Approved/Rejected
// when the decision is signed by a trusted key. The signature covers the request
// identity and the concrete reroute (source/target model), so it cannot be
// replayed onto another request or reused after the target model is altered.
//
// It is pure (no Kubernetes dependency) so it is trivially unit-testable; the
// admission webhook (internal/webhook/changerequest) wires it to the API server.
package approval

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	platformcrypto "github.com/ihsenalaya/ai-confidential-operator/pkg/crypto"
)

// Decision is the canonical, signable view of an AIChangeRequest approval. It
// deliberately excludes advisory/mutable fields (reason, savings, expiry) so the
// signature commits only to the security-relevant decision: who is affected and
// what reroute is authorised.
type Decision struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Action      string `json:"action"`
	SourceModel string `json:"sourceModel"`
	TargetModel string `json:"targetModel"`
	Approval    string `json:"approval"`
}

// CanonicalMessage returns the deterministic byte string that a reviewer signs
// and the webhook verifies. It uses the project's canonical JSON encoder so the
// bytes are stable across map ordering and Go/tooling versions.
func CanonicalMessage(d Decision) ([]byte, error) {
	msg, err := platformcrypto.CanonicalJSON(d)
	if err != nil {
		return nil, fmt.Errorf("canonicalize approval decision: %w", err)
	}
	return msg, nil
}

// Sign produces the hex-encoded Ed25519 signature a reviewer attaches to
// spec.approvalSignature. It is used by the signing CLI and by tests.
func Sign(priv ed25519.PrivateKey, d Decision) (string, error) {
	msg, err := CanonicalMessage(d)
	if err != nil {
		return "", err
	}
	return platformcrypto.Ed25519Sign(priv, msg), nil
}

// Verify reports whether sigHex is a valid signature of d under any of the
// trusted public keys. When keyID is non-empty, only the key registered under
// that id is considered. A verification error (bad hex, wrong length) is returned
// separately from a clean "no key matched" (false, nil) so callers can decide how
// to surface each.
func Verify(trusted KeySet, keyID string, d Decision, sigHex string) (bool, error) {
	if strings.TrimSpace(sigHex) == "" {
		return false, nil
	}
	msg, err := CanonicalMessage(d)
	if err != nil {
		return false, err
	}
	return VerifyCanonical(trusted, keyID, msg, sigHex)
}

// VerifyCanonical checks a pre-canonicalized payload against the trusted key set.
func VerifyCanonical(trusted KeySet, keyID string, msg []byte, sigHex string) (bool, error) {
	if strings.TrimSpace(sigHex) == "" {
		return false, nil
	}
	candidates := trusted.candidates(keyID)
	if len(candidates) == 0 {
		return false, nil
	}
	for _, pub := range candidates {
		ok, err := platformcrypto.Ed25519Verify(pub, msg, sigHex)
		if err != nil {
			// Malformed signature encoding: no trusted key can accept it.
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// KeySet is the collection of trusted approval public keys, optionally addressed
// by a stable key id for rotation. The zero value is an empty (feature-disabled)
// set.
type KeySet struct {
	byID  map[string]ed25519.PublicKey
	anyID []ed25519.PublicKey
}

// Empty reports whether the set holds no trusted keys, i.e. signed-approval
// enforcement is disabled.
func (k KeySet) Empty() bool { return len(k.anyID) == 0 }

func (k KeySet) candidates(keyID string) []ed25519.PublicKey {
	if strings.TrimSpace(keyID) != "" {
		if pub, ok := k.byID[keyID]; ok {
			return []ed25519.PublicKey{pub}
		}
		return nil
	}
	return k.anyID
}

// NewKeySet builds a KeySet from hex-encoded public keys. Entries may be a bare
// hex key or "id=hex" to register a rotatable key id. Blank entries are ignored.
func NewKeySet(entries []string) (KeySet, error) {
	ks := KeySet{byID: map[string]ed25519.PublicKey{}}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		id := ""
		hexKey := entry
		if idx := strings.Index(entry, "="); idx >= 0 {
			id = strings.TrimSpace(entry[:idx])
			hexKey = strings.TrimSpace(entry[idx+1:])
		}
		pub, err := platformcrypto.PubKeyFromHex(hexKey)
		if err != nil {
			return KeySet{}, fmt.Errorf("parse trusted approval key %q: %w", id, err)
		}
		ks.anyID = append(ks.anyID, pub)
		if id != "" {
			ks.byID[id] = pub
		}
	}
	return ks, nil
}

// ParseKeySetCSV builds a KeySet from a comma-separated list (the shape used by
// the AIOPS_APPROVAL_PUBKEYS environment variable).
func ParseKeySetCSV(csv string) (KeySet, error) {
	if strings.TrimSpace(csv) == "" {
		return KeySet{}, nil
	}
	return NewKeySet(strings.Split(csv, ","))
}
