package approval

import (
	"testing"

	platformcrypto "github.com/ihsenalaya/ai-confidential-operator/pkg/crypto"
)

func testDecision() Decision {
	return Decision{
		Namespace:   "finance",
		Name:        "risk-assistant-cheaper",
		Action:      "reroute",
		SourceModel: "gpt-us-mini",
		TargetModel: "gpt-france-mini",
		Approval:    "Approved",
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ks, err := NewKeySet([]string{platformcrypto.PubKeyToHex(pub)})
	if err != nil {
		t.Fatalf("build keyset: %v", err)
	}

	sig, err := Sign(priv, testDecision())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := Verify(ks, "", testDecision(), sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("valid signature did not verify")
	}
}

func TestVerifyRejectsEmptySignature(t *testing.T) {
	pub, _, _ := platformcrypto.GenerateEd25519KeyPair()
	ks, _ := NewKeySet([]string{platformcrypto.PubKeyToHex(pub)})
	ok, err := Verify(ks, "", testDecision(), "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("empty signature must not verify")
	}
}

func TestVerifyRejectsTamperedTargetModel(t *testing.T) {
	pub, priv, _ := platformcrypto.GenerateEd25519KeyPair()
	ks, _ := NewKeySet([]string{platformcrypto.PubKeyToHex(pub)})

	sig, err := Sign(priv, testDecision())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tampered := testDecision()
	tampered.TargetModel = "gpt-us-premium" // attacker swaps the reroute target
	ok, err := Verify(ks, "", tampered, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("signature must not verify after the target model is altered")
	}
}

func TestVerifyRejectsForeignKey(t *testing.T) {
	_, priv, _ := platformcrypto.GenerateEd25519KeyPair() // signer NOT trusted
	trustedPub, _, _ := platformcrypto.GenerateEd25519KeyPair()
	ks, _ := NewKeySet([]string{platformcrypto.PubKeyToHex(trustedPub)})

	sig, err := Sign(priv, testDecision())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := Verify(ks, "", testDecision(), sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("signature from an untrusted key must not verify")
	}
}

func TestVerifyHonoursKeyID(t *testing.T) {
	pubA, privA, _ := platformcrypto.GenerateEd25519KeyPair()
	pubB, _, _ := platformcrypto.GenerateEd25519KeyPair()
	ks, err := NewKeySet([]string{
		"reviewer-a=" + platformcrypto.PubKeyToHex(pubA),
		"reviewer-b=" + platformcrypto.PubKeyToHex(pubB),
	})
	if err != nil {
		t.Fatalf("build keyset: %v", err)
	}

	sig, _ := Sign(privA, testDecision())

	// Correct key id verifies.
	if ok, err := Verify(ks, "reviewer-a", testDecision(), sig); err != nil || !ok {
		t.Fatalf("verify with correct key id: ok=%v err=%v", ok, err)
	}
	// Wrong key id must not match even though the signature is otherwise valid.
	if ok, err := Verify(ks, "reviewer-b", testDecision(), sig); err != nil || ok {
		t.Fatalf("verify with wrong key id should fail: ok=%v err=%v", ok, err)
	}
}

func TestParseKeySetCSVEmptyIsDisabled(t *testing.T) {
	ks, err := ParseKeySetCSV("   ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ks.Empty() {
		t.Fatal("blank CSV must yield an empty (disabled) key set")
	}
}

func TestNewKeySetRejectsBadHex(t *testing.T) {
	if _, err := NewKeySet([]string{"not-hex"}); err == nil {
		t.Fatal("expected error for malformed public key")
	}
}
