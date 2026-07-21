// sign-approval produces the Ed25519 signature a reviewer attaches to an
// AIChangeRequest as spec.approvalSignature so the signed-approval admission
// webhook (internal/webhook/changerequest) admits the decision. It can also mint
// a key pair for bootstrapping the trusted-key set (AIOPS_APPROVAL_PUBKEYS).
//
// Usage:
//
//	sign-approval --gen-key
//	sign-approval --priv-hex <seed> --namespace finance --name my-crq \
//	  --action reroute --source gpt-us-mini --target gpt-france-mini --approval Approved
//
// The output signature binds the decision to this exact request, so it cannot be
// replayed onto another request or reused after the target model is altered.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ihsenalaya/ai-confidential-operator/internal/approval"
	platformcrypto "github.com/ihsenalaya/ai-confidential-operator/pkg/crypto"
)

func main() {
	var (
		genKey    = flag.Bool("gen-key", false, "generate a new Ed25519 key pair and print pub/priv hex")
		privHex   = flag.String("priv-hex", "", "hex-encoded Ed25519 private key seed (or set APPROVAL_PRIV_HEX)")
		namespace = flag.String("namespace", "", "AIChangeRequest namespace")
		name      = flag.String("name", "", "AIChangeRequest name")
		action    = flag.String("action", "reroute", "spec.action")
		source    = flag.String("source", "", "spec.sourceModel")
		target    = flag.String("target", "", "spec.targetModel")
		approvalV = flag.String("approval", "Approved", "decision: Approved or Rejected")
	)
	flag.Parse()

	if *genKey {
		pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
		if err != nil {
			fail(err)
		}
		fmt.Printf("public_key_hex=%s\n", platformcrypto.PubKeyToHex(pub))
		fmt.Printf("private_key_hex=%s\n", platformcrypto.PrivKeyToHex(priv))
		return
	}

	seed := *privHex
	if seed == "" {
		seed = os.Getenv("APPROVAL_PRIV_HEX")
	}
	if seed == "" {
		fail(fmt.Errorf("a private key is required: pass --priv-hex or set APPROVAL_PRIV_HEX (or use --gen-key)"))
	}
	priv, err := platformcrypto.PrivKeyFromHex(seed)
	if err != nil {
		fail(err)
	}

	sig, err := approval.Sign(priv, approval.Decision{
		Namespace:   *namespace,
		Name:        *name,
		Action:      *action,
		SourceModel: *source,
		TargetModel: *target,
		Approval:    *approvalV,
	})
	if err != nil {
		fail(err)
	}
	fmt.Println(sig)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sign-approval:", err)
	os.Exit(1)
}
