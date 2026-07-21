package evidence

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/ihsenalaya/ai-confidential-operator/internal/approval"
	platformcrypto "github.com/ihsenalaya/ai-confidential-operator/pkg/crypto"
)

const (
	AnnotationSignatureRequired = "aiops.imperium.io/evidence-signature-required"
	AnnotationSignature         = "aiops.imperium.io/evidence-signature"
	AnnotationKeyID             = "aiops.imperium.io/evidence-key-id"
)

// SignedConfigMap is the deterministic view of an evidence ConfigMap that gets
// signed and later checked by the admission webhook.
type SignedConfigMap struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Labels     map[string]string `json:"labels,omitempty"`
	Data       map[string]string `json:"data,omitempty"`
	BinaryData map[string]string `json:"binaryData,omitempty"`
}

// SignatureRequired reports whether the ConfigMap opted into signed-evidence
// enforcement.
func SignatureRequired(cm *corev1.ConfigMap) bool {
	if cm == nil || cm.Annotations == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(cm.Annotations[AnnotationSignatureRequired]), "true")
}

// Canonicalize extracts the signable view of a ConfigMap. Signature annotations
// themselves are excluded from the signed payload, but opt-in metadata and other
// labels remain bound to the signature.
func Canonicalize(cm *corev1.ConfigMap) SignedConfigMap {
	labels := map[string]string{}
	for k, v := range cm.Labels {
		labels[k] = v
	}
	data := map[string]string{}
	for k, v := range cm.Data {
		data[k] = v
	}
	binaryData := map[string]string{}
	for k, v := range cm.BinaryData {
		binaryData[k] = platformcrypto.SHA256Hex(v)
	}
	if len(labels) == 0 {
		labels = nil
	}
	if len(data) == 0 {
		data = nil
	}
	if len(binaryData) == 0 {
		binaryData = nil
	}
	return SignedConfigMap{
		Namespace:  cm.Namespace,
		Name:       cm.Name,
		Kind:       "ConfigMap",
		Labels:     labels,
		Data:       data,
		BinaryData: binaryData,
	}
}

// Sign signs the canonical view of a ConfigMap and returns the hex-encoded
// Ed25519 signature.
func Sign(privHex string, cm *corev1.ConfigMap) (string, error) {
	priv, err := platformcrypto.PrivKeyFromHex(privHex)
	if err != nil {
		return "", err
	}
	payload, err := platformcrypto.CanonicalJSON(Canonicalize(cm))
	if err != nil {
		return "", fmt.Errorf("canonicalize evidence configmap: %w", err)
	}
	return platformcrypto.Ed25519Sign(priv, payload), nil
}

// Verify checks the ConfigMap signature against the trusted key set.
func Verify(trusted approval.KeySet, keyID string, cm *corev1.ConfigMap, sigHex string) (bool, error) {
	if strings.TrimSpace(sigHex) == "" {
		return false, nil
	}
	payload, err := platformcrypto.CanonicalJSON(Canonicalize(cm))
	if err != nil {
		return false, fmt.Errorf("canonicalize evidence configmap: %w", err)
	}
	return approval.VerifyCanonical(trusted, keyID, payload, sigHex)
}
