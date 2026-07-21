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

// Package metrics registers the confidential-computing Prometheus metrics on
// the controller-runtime registry (exposed via the manager's /metrics
// endpoint). ai-confidential-operator owns a single collector today: whether
// a confidential pod policy is currently mapped onto a simulated (non-TEE)
// runtime class, set by the pod-injection webhook.
package metrics

import (
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// SimulatedRuntimeClassInUse indicates a pod/policy is using a simulated runtime class.
	SimulatedRuntimeClassInUse = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ai_simulated_runtimeclass_in_use",
		Help: "Whether a confidential pod policy is currently using a simulated runtime class mapping.",
	}, []string{"namespace", "policy", "runtimeclass"})
)

// all is every collector this package owns. init() registers them and Names()
// derives their metric names — so the set of exposed names has a single source of
// truth.
var all = []prometheus.Collector{
	SimulatedRuntimeClassInUse,
}

func init() {
	crmetrics.Registry.MustRegister(all...)
}

var fqNameRe = regexp.MustCompile(`fqName: "([^"]+)"`)

// Names returns the fully-qualified names of every metric this package registers.
// It Describe()s each collector and extracts the fqName, so it stays correct
// automatically when metrics are added, removed or renamed.
func Names() []string {
	var names []string
	for _, c := range all {
		ch := make(chan *prometheus.Desc, 4)
		c.Describe(ch)
		close(ch)
		for d := range ch {
			if m := fqNameRe.FindStringSubmatch(d.String()); m != nil {
				names = append(names, m[1])
			}
		}
	}
	return names
}
