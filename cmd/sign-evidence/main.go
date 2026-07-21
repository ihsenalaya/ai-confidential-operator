package main

import (
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/ihsenalaya/ai-confidential-operator/internal/evidence"
)

func main() {
	var (
		file    = flag.String("file", "", "path to the evidence ConfigMap YAML/JSON to sign")
		privHex = flag.String("priv-hex", "", "hex-encoded Ed25519 private key seed (or set EVIDENCE_PRIV_HEX)")
	)
	flag.Parse()

	if *file == "" {
		fail(fmt.Errorf("--file is required"))
	}
	seed := *privHex
	if seed == "" {
		seed = os.Getenv("EVIDENCE_PRIV_HEX")
	}
	if seed == "" {
		fail(fmt.Errorf("a private key is required: pass --priv-hex or set EVIDENCE_PRIV_HEX"))
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fail(err)
	}
	var cm corev1.ConfigMap
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		fail(fmt.Errorf("decode configmap: %w", err))
	}
	sig, err := evidence.Sign(seed, &cm)
	if err != nil {
		fail(err)
	}
	fmt.Println(sig)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sign-evidence:", err)
	os.Exit(1)
}
