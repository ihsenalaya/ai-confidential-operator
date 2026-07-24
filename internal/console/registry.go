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

// Package console implements a generic, schema-driven REST API over this
// operator's own CRDs, so a graphical UI can create/edit/delete custom
// resources without anyone hand-writing YAML. It talks to the Kubernetes API
// using whatever kubeconfig/context is currently active for the caller running
// the binary (KUBECONFIG env var, ~/.kube/config, or --kubeconfig flag) — it
// never uses an in-cluster service account of its own, so every action is
// performed with the operator of this tool's own RBAC permissions.
package console

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Resource describes one CRD kind this console exposes.
type Resource struct {
	// Kind is the CRD Kind, used as the path segment in the REST API
	// (e.g. "AttestationEvidence").
	Kind string
	// Plural is the CRD's plural resource name (e.g. "attestationevidences").
	Plural string
	// Group/Version identify the CRD's apiVersion.
	Group   string
	Version string
	// ShortName is a compact label for list views (kubectl shortName), purely
	// cosmetic.
	ShortName string
}

// GVR returns the GroupVersionResource for this resource.
func (r Resource) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Plural}
}

// CRDName is the name of the CustomResourceDefinition object itself
// (<plural>.<group>), used to fetch the OpenAPI schema for form generation.
func (r Resource) CRDName() string {
	return r.Plural + "." + r.Group
}

const apiGroup = "aiops.imperium.io"
const apiVersion = "v1alpha1"

// Registry lists the 7 CRDs owned by ai-confidential-operator. This is the
// single place to edit when a CRD is added/renamed. Note:
// ConfidentialInferencePolicy, RawAttestationReport and AttestationEvidence
// are normally created by the platform itself (node-attestation-agent /
// central-verifier / attestation-scheduler), not hand-authored — the console
// still lets you view and, if you know what you're doing, edit them.
var Registry = []Resource{
	{Kind: "ConfidentialInferencePolicy", Plural: "confidentialinferencepolicies", Group: apiGroup, Version: apiVersion, ShortName: "cip"},
	{Kind: "RawAttestationReport", Plural: "rawattestationreports", Group: apiGroup, Version: apiVersion, ShortName: "rar"},
	{Kind: "AttestationEvidence", Plural: "attestationevidences", Group: apiGroup, Version: apiVersion, ShortName: "aevid"},
	{Kind: "AIPlacementDecision", Plural: "aiplacementdecisions", Group: apiGroup, Version: apiVersion, ShortName: "apd"},
	{Kind: "AIKeyReleasePolicy", Plural: "aikeyreleasepolicies", Group: apiGroup, Version: apiVersion, ShortName: "akrp"},
	{Kind: "AIRevocationPolicy", Plural: "airevocationpolicies", Group: apiGroup, Version: apiVersion, ShortName: "airvp"},
	{Kind: "AIEvidenceRecord", Plural: "aievidencerecords", Group: apiGroup, Version: apiVersion, ShortName: "aier"},
}

// ByKind finds a registered resource by its Kind (case-sensitive, exact match).
func ByKind(kind string) (Resource, bool) {
	for _, r := range Registry {
		if r.Kind == kind {
			return r, true
		}
	}
	return Resource{}, false
}
