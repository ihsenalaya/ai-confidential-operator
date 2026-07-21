# ConfidentialInferencePolicy

`ConfidentialInferencePolicy` (shortName `cip`) déclare les **exigences confidential-computing**
d'un workload d'inférence : TEE accepté, fraîcheur d'évidence, runtime classes autorisées,
digests d'image/modèle, GPU confidentiel et key-release conditionnel. Les webhooks pods de
l'opérateur la consomment en lecture pour injecter/valider les pods ciblés.

## Spec

| Champ | Type | Rôle |
|---|---|---|
| `target` * | object | Sélection des namespaces (`namespaceSelector`) et workloads (`workloadSelector`) protégés. |
| `enforcementMode` * | enum `warn` \| `enforce` \| `audit` | `enforce` fait rejeter les pods non conformes par le webhook de validation. |
| `maxEvidenceAgeSeconds` * | int | Limite de fraîcheur de l'évidence d'attestation. |
| `requiredTEE` | array de `TDX` \| `SEV-SNP` | TEE acceptés. |
| `allowedRuntimeClasses` | array | Runtime classes autorisées en production (les classes `simulated-kata-qemu-*` servent en kind). |
| `requireConfidentialContainers` | bool | Exige une runtime class confidentielle. |
| `requireImageDigest` / `requireModelDigest` | bool | Exige des références d'image / un digest de modèle immuables. |
| `gpu` | object | GPU confidentiel attendu : `vendor` (`nvidia`/`amd`/`intel`), `deviceClass`, `draClass`. |
| `keyRelease` | object | `required` + `ttlSeconds` : exige un key-release réussi avant exécution. |
| `audit` | object | `required` + `level` (`summary`/`full`). |

## Status

| Champ | Rôle |
|---|---|
| `effectiveRuntime` | Runtime résolue (avec `simulated: true` quand mappée en kind). |
| `simulated` | La policy est actuellement résolue en mode simulation locale. |
| `policyHash`, `conditions`, `observedGeneration` | Diagnostic standard. |

## Exemple

```yaml
apiVersion: aiops.imperium.io/v1alpha1
kind: ConfidentialInferencePolicy
metadata:
  name: regulated-inference
spec:
  target:
    namespaceSelector:
      matchLabels:
        confidential-ai/enabled: "true"
  requiredTEE: ["SEV-SNP"]
  maxEvidenceAgeSeconds: 3600
  requireConfidentialContainers: true
  requireImageDigest: true
  enforcementMode: enforce
```

```bash
kubectl get cip
kubectl get cip regulated-inference -o jsonpath='{.status.effectiveRuntime}'
```
