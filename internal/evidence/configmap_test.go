package evidence

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ihsenalaya/ai-confidential-operator/internal/approval"
	platformcrypto "github.com/ihsenalaya/ai-confidential-operator/pkg/crypto"
)

func testConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shadow-egress",
			Namespace: "default",
			Labels: map[string]string{
				"app.kubernetes.io/component": "evidence",
			},
			Annotations: map[string]string{
				AnnotationSignatureRequired: "true",
			},
		},
		Data: map[string]string{
			"egress.json": `[{"namespace":"shadow","application":"rogue","host":"api.openai.com","connections":2}]`,
		},
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ks, err := approval.NewKeySet([]string{platformcrypto.PubKeyToHex(pub)})
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	sig, err := Sign(platformcrypto.PrivKeyToHex(priv), testConfigMap())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := Verify(ks, "", testConfigMap(), sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("valid configmap signature did not verify")
	}
}

func TestVerifyRejectsTamperedData(t *testing.T) {
	pub, priv, _ := platformcrypto.GenerateEd25519KeyPair()
	ks, _ := approval.NewKeySet([]string{platformcrypto.PubKeyToHex(pub)})
	cm := testConfigMap()
	sig, _ := Sign(platformcrypto.PrivKeyToHex(priv), cm)
	cm.Data["egress.json"] = `[{"namespace":"shadow","application":"rogue","host":"api.anthropic.com","connections":2}]`
	ok, err := Verify(ks, "", cm, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("tampered configmap data must not verify")
	}
}

func TestSignatureRequiredFlag(t *testing.T) {
	cm := testConfigMap()
	if !SignatureRequired(cm) {
		t.Fatal("configmap should require signature")
	}
	cm.Annotations[AnnotationSignatureRequired] = "false"
	if SignatureRequired(cm) {
		t.Fatal("configmap should no longer require signature")
	}
}
