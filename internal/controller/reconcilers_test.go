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

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	aiopsv1alpha1 "github.com/ihsenalaya/ai-confidential-operator/api/v1alpha1"
	"github.com/ihsenalaya/ai-confidential-operator/pkg/attestation/maa"
)

const testNamespace = "default"

func reqFor(name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: testNamespace}}
}

// This suite is scoped to ai-confidential-operator only: it keeps the
// AttestationEvidence/RawAttestationReport/AIPlacementDecision/AIKeyReleasePolicy
// Context blocks from the monolith's reconcilers_test.go (the finops/govar
// Context blocks - AIProvider, AIGateway, AIModel, AIBudgetPolicy, etc - live in
// their own repos now). AIEvidenceRecord and AIRevocationPolicy have no dedicated
// Context in the source suite either, so none is invented here.
var _ = Describe("aiops reconcilers", func() {
	ctx := context.Background()

	Context("AttestationEvidence refresh", func() {
		It("requeues simulated evidence to keep it fresh, but not real evidence", func() {
			simEvidence := &aiopsv1alpha1.AttestationEvidence{
				ObjectMeta: metav1.ObjectMeta{Name: "ae-sim-refresh", Namespace: testNamespace},
				Spec: aiopsv1alpha1.AttestationEvidenceSpec{
					SubjectRef:   aiopsv1alpha1.ObjectReference{Name: "node-sim"},
					EvidenceType: "cpu",
					TEE:          "TDX",
					Freshness:    aiopsv1alpha1.EvidenceFreshness{MaxAgeSeconds: 300, Simulated: true},
					Simulated:    true,
				},
			}
			Expect(k8sClient.Create(ctx, simEvidence)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, simEvidence) })

			evr := &AttestationEvidenceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			res, err := evr.Reconcile(ctx, reqFor("ae-sim-refresh"))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(BeNumerically(">", 0), "simulated evidence must be requeued for refresh")

			got := &aiopsv1alpha1.AttestationEvidence{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "ae-sim-refresh", Namespace: testNamespace}, got)).To(Succeed())
			Expect(got.Status.Verified).To(BeTrue())
			Expect(got.Status.LastVerifiedTime).NotTo(BeNil())

			// Real evidence (digest-backed, not simulated) must NOT be auto-refreshed.
			realEvidence := &aiopsv1alpha1.AttestationEvidence{
				ObjectMeta: metav1.ObjectMeta{Name: "ae-real-norefresh", Namespace: testNamespace},
				Spec: aiopsv1alpha1.AttestationEvidenceSpec{
					SubjectRef:   aiopsv1alpha1.ObjectReference{Name: "node-real"},
					EvidenceType: "cpu",
					TEE:          "SEV-SNP",
					Freshness:    aiopsv1alpha1.EvidenceFreshness{MaxAgeSeconds: 300},
					Digest:       "sha256:real-evidence-digest",
				},
			}
			Expect(k8sClient.Create(ctx, realEvidence)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, realEvidence) })

			resReal, err := evr.Reconcile(ctx, reqFor("ae-real-norefresh"))
			Expect(err).NotTo(HaveOccurred())
			Expect(resReal.RequeueAfter).To(BeZero(), "real evidence freshness must not be auto-refreshed")
		})
	})

	Context("RawAttestationReport central verifier", func() {
		It("turns a simulated raw report into simulated verified evidence", func() {
			report := &aiopsv1alpha1.RawAttestationReport{
				ObjectMeta: metav1.ObjectMeta{Name: "raw-sim-report", Namespace: testNamespace},
				Spec: aiopsv1alpha1.RawAttestationReportSpec{
					NodeName:            "node-sim-report",
					NodeUID:             "node-uid-sim",
					Provider:            "simulator",
					RawToken:            "simulated-token",
					RawTokenHash:        "simulated-token-hash",
					Nonce:               "nonce-sim",
					CollectedAt:         metav1.Now(),
					AgentPodUID:         "agent-pod-sim",
					AgentServiceAccount: "node-attestation-agent",
					Simulated:           true,
				},
			}
			Expect(k8sClient.Create(ctx, report)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, report) })
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, &aiopsv1alpha1.AttestationEvidence{
					ObjectMeta: metav1.ObjectMeta{Name: "evidence-node-sim-report", Namespace: testNamespace},
				})
			})

			r := &RawAttestationReportReconciler{
				Client:           k8sClient,
				Scheme:           k8sClient.Scheme(),
				VerifierIdentity: "test-central-verifier",
				VerifierPodUID:   "verifier-pod-sim",
				ExpectedTEE:      "sevsnpvm",
			}
			res, err := r.Reconcile(ctx, reqFor("raw-sim-report"))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(BeNumerically(">", 0))

			evidence := &aiopsv1alpha1.AttestationEvidence{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "evidence-node-sim-report", Namespace: testNamespace}, evidence)).To(Succeed())
			Expect(evidence.Spec.Simulated).To(BeTrue())
			Expect(evidence.Status.Verified).To(BeTrue())
			Expect(evidence.Status.EvidenceMode).To(Equal(aiopsv1alpha1.EvidenceModeSimulated))
			Expect(evidence.Status.VerificationStatus).To(Equal(aiopsv1alpha1.VerificationStatusVerified))
			Expect(evidence.Status.VerifiedBy).To(Equal("test-central-verifier"))
			Expect(meta.IsStatusConditionTrue(evidence.Status.Conditions, aiopsv1alpha1.ConditionReady)).To(BeTrue())

			gotReport := &aiopsv1alpha1.RawAttestationReport{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "raw-sim-report", Namespace: testNamespace}, gotReport)).To(Succeed())
			Expect(gotReport.Status.Processed).To(BeTrue())
			Expect(gotReport.Status.EvidenceRef).To(Equal("evidence-node-sim-report"))
			Expect(gotReport.Status.VerificationStatus).To(Equal(aiopsv1alpha1.VerificationStatusVerified))
		})

		It("keeps a failed real raw report unverified", func() {
			report := &aiopsv1alpha1.RawAttestationReport{
				ObjectMeta: metav1.ObjectMeta{Name: "raw-real-fail-report", Namespace: testNamespace},
				Spec: aiopsv1alpha1.RawAttestationReportSpec{
					NodeName:            "node-real-fail-report",
					NodeUID:             "node-uid-real",
					Provider:            "maa",
					RawToken:            "not-a-valid-maa-token",
					RawTokenHash:        "raw-token-hash",
					Nonce:               "nonce-real",
					CollectedAt:         metav1.Now(),
					AgentPodUID:         "agent-pod-real",
					AgentServiceAccount: "node-attestation-agent",
					Simulated:           false,
				},
			}
			Expect(k8sClient.Create(ctx, report)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, report) })
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, &aiopsv1alpha1.AttestationEvidence{
					ObjectMeta: metav1.ObjectMeta{Name: "evidence-node-real-fail-report", Namespace: testNamespace},
				})
			})

			r := &RawAttestationReportReconciler{
				Client:           k8sClient,
				Scheme:           k8sClient.Scheme(),
				VerifierIdentity: "test-central-verifier",
				VerifierPodUID:   "verifier-pod-real",
				ExpectedTEE:      "sevsnpvm",
				verifyFn: func(token string, opts maa.Options) maa.Result {
					Expect(token).To(Equal("not-a-valid-maa-token"))
					Expect(opts.ExpectedNonce).To(Equal("nonce-real"))
					return maa.Result{
						Status:    maa.StatusFailed,
						Reason:    "injected verifier failure",
						TokenHash: "sha256:bogus",
					}
				},
			}
			res, err := r.Reconcile(ctx, reqFor("raw-real-fail-report"))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(BeZero())

			evidence := &aiopsv1alpha1.AttestationEvidence{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "evidence-node-real-fail-report", Namespace: testNamespace}, evidence)).To(Succeed())
			Expect(evidence.Spec.Simulated).To(BeFalse())
			Expect(evidence.Status.Verified).To(BeFalse())
			Expect(evidence.Status.EvidenceMode).To(Equal(aiopsv1alpha1.EvidenceModeUnverified))
			Expect(evidence.Status.VerificationStatus).To(Equal(aiopsv1alpha1.VerificationStatusFailed))
			Expect(evidence.Status.FailureReason).To(Equal("injected verifier failure"))
			Expect(evidence.Status.MAATokenHash).To(Equal("sha256:bogus"))
			Expect(meta.IsStatusConditionFalse(evidence.Status.Conditions, aiopsv1alpha1.ConditionReady)).To(BeTrue())

			gotReport := &aiopsv1alpha1.RawAttestationReport{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "raw-real-fail-report", Namespace: testNamespace}, gotReport)).To(Succeed())
			Expect(gotReport.Status.Processed).To(BeTrue())
			Expect(gotReport.Status.EvidenceRef).To(Equal("evidence-node-real-fail-report"))
			Expect(gotReport.Status.VerificationStatus).To(Equal(aiopsv1alpha1.VerificationStatusFailed))
		})
	})

	Context("AIPlacementDecision", func() {
		It("allows placement with verified non-revoked evidence", func() {
			policy := &aiopsv1alpha1.ConfidentialInferencePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "conf-place", Namespace: testNamespace},
				Spec: aiopsv1alpha1.ConfidentialInferencePolicySpec{
					Target:                aiopsv1alpha1.WorkloadTarget{},
					RequiredTEE:           []string{"TDX"},
					MaxEvidenceAgeSeconds: 300,
					AllowedRuntimeClasses: []string{"simulated-kata-qemu-tdx"},
					EnforcementMode:       aiopsv1alpha1.EnforcementModeEnforce,
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, policy) })

			evidence := &aiopsv1alpha1.AttestationEvidence{
				ObjectMeta: metav1.ObjectMeta{Name: "ae-place", Namespace: testNamespace},
				Spec: aiopsv1alpha1.AttestationEvidenceSpec{
					SubjectRef:   aiopsv1alpha1.ObjectReference{Name: "risk-assistant"},
					EvidenceType: "runtime",
					TEE:          "TDX",
					Runtime:      aiopsv1alpha1.RuntimeExpectation{RuntimeClassName: "simulated-kata-qemu-tdx", Simulated: true},
					Freshness:    aiopsv1alpha1.EvidenceFreshness{MaxAgeSeconds: 30, Simulated: true},
					Simulated:    true,
				},
			}
			Expect(k8sClient.Create(ctx, evidence)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, evidence) })

			evr := &AttestationEvidenceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := evr.Reconcile(ctx, reqFor("ae-place"))
			Expect(err).NotTo(HaveOccurred())

			placementDecision := &aiopsv1alpha1.AIPlacementDecision{
				ObjectMeta: metav1.ObjectMeta{Name: "place-x", Namespace: testNamespace},
				Spec: aiopsv1alpha1.AIPlacementDecisionSpec{
					TargetRef:      aiopsv1alpha1.ObjectReference{Name: "risk-assistant"},
					PolicyRef:      aiopsv1alpha1.ObjectReference{Name: "conf-place"},
					EvidenceRef:    &aiopsv1alpha1.ObjectReference{Name: "ae-place"},
					PlacementToken: aiopsv1alpha1.PlacementTokenSpec{Required: true, TTLSeconds: 300},
					SchedulerName:  "ai-attestation-scheduler",
				},
			}
			Expect(k8sClient.Create(ctx, placementDecision)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, placementDecision) })

			r := &AIPlacementDecisionReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err = r.Reconcile(ctx, reqFor("place-x"))
			Expect(err).NotTo(HaveOccurred())

			got := &aiopsv1alpha1.AIPlacementDecision{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "place-x", Namespace: testNamespace}, got)).To(Succeed())
			Expect(got.Status.Decision).To(Equal("allow"))
			Expect(got.Status.PlacementTokenDigest).NotTo(BeEmpty())
		})
	})

	Context("AIKeyReleasePolicy", func() {
		It("allows key release with verified evidence and valid placement", func() {
			policy := &aiopsv1alpha1.ConfidentialInferencePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "conf-kr", Namespace: testNamespace},
				Spec: aiopsv1alpha1.ConfidentialInferencePolicySpec{
					Target:                aiopsv1alpha1.WorkloadTarget{},
					RequiredTEE:           []string{"TDX"},
					MaxEvidenceAgeSeconds: 300,
					AllowedRuntimeClasses: []string{"simulated-kata-qemu-tdx"},
					EnforcementMode:       aiopsv1alpha1.EnforcementModeEnforce,
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, policy) })

			evidence := &aiopsv1alpha1.AttestationEvidence{
				ObjectMeta: metav1.ObjectMeta{Name: "ae-kr", Namespace: testNamespace},
				Spec: aiopsv1alpha1.AttestationEvidenceSpec{
					SubjectRef:   aiopsv1alpha1.ObjectReference{Name: "risk-assistant"},
					EvidenceType: "runtime",
					TEE:          "TDX",
					Runtime:      aiopsv1alpha1.RuntimeExpectation{RuntimeClassName: "simulated-kata-qemu-tdx", Simulated: true},
					Freshness:    aiopsv1alpha1.EvidenceFreshness{MaxAgeSeconds: 30, Simulated: true},
					Simulated:    true,
				},
			}
			Expect(k8sClient.Create(ctx, evidence)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, evidence) })
			evr := &AttestationEvidenceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := evr.Reconcile(ctx, reqFor("ae-kr"))
			Expect(err).NotTo(HaveOccurred())

			placementDecision := &aiopsv1alpha1.AIPlacementDecision{
				ObjectMeta: metav1.ObjectMeta{Name: "place-kr", Namespace: testNamespace},
				Spec: aiopsv1alpha1.AIPlacementDecisionSpec{
					TargetRef:      aiopsv1alpha1.ObjectReference{Name: "risk-assistant"},
					PolicyRef:      aiopsv1alpha1.ObjectReference{Name: "conf-kr"},
					EvidenceRef:    &aiopsv1alpha1.ObjectReference{Name: "ae-kr"},
					PlacementToken: aiopsv1alpha1.PlacementTokenSpec{Required: true, TTLSeconds: 300},
				},
			}
			Expect(k8sClient.Create(ctx, placementDecision)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, placementDecision) })
			pdr := &AIPlacementDecisionReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err = pdr.Reconcile(ctx, reqFor("place-kr"))
			Expect(err).NotTo(HaveOccurred())

			keyPolicy := &aiopsv1alpha1.AIKeyReleasePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "kr-x", Namespace: testNamespace},
				Spec: aiopsv1alpha1.AIKeyReleasePolicySpec{
					EvidenceRef:             &aiopsv1alpha1.ObjectReference{Name: "ae-kr"},
					RequireAttestedEvidence: true,
					KeyRelease:              aiopsv1alpha1.PolicyKeyReleaseSpec{Required: true, TTLSeconds: 300},
					EnforcementMode:         aiopsv1alpha1.EnforcementModeEnforce,
				},
			}
			Expect(k8sClient.Create(ctx, keyPolicy)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, keyPolicy) })

			r := &AIKeyReleasePolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err = r.Reconcile(ctx, reqFor("kr-x"))
			Expect(err).NotTo(HaveOccurred())

			got := &aiopsv1alpha1.AIKeyReleasePolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "kr-x", Namespace: testNamespace}, got)).To(Succeed())
			Expect(got.Status.LastDecision).To(Equal("allow"))
		})
	})
})
