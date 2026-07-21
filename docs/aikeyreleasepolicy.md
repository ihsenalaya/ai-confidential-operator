# AIKeyReleasePolicy

`AIKeyReleasePolicy` (shortName `akrp`) conditionne la **libération de clés/secrets** à
l'état d'attestation : la `key-release-gateway` ne délivre le matériel sensible qu'à un
workload dont l'évidence est vérifiée et fraîche.

## Spec

| Champ | Type | Rôle |
|---|---|---|
| `target` * | object | Namespaces/workloads soumis au key-release. |
| `enforcementMode` * | enum `warn` \| `enforce` \| `audit` | Mode de décision de la gateway. |
| `requireAttestedEvidence` | bool | Bloque la libération quand l'évidence est absente. |
| `evidenceRef` | object | Évidence d'attestation requise. |
| `allowedSecrets` | array | Secrets Kubernetes libérables (moindre privilège). |
| `keyRelease` | object | `required` + `ttlSeconds` (fenêtre de validité de la décision). |
| `audit` | object | `required` + `level`. |

## Status

| Champ | Rôle |
|---|---|
| `lastDecision` | `allow` \| `deny` \| `pending`. |
| `lastDecisionTime` | Dernière évaluation. |

```bash
kubectl get akrp
kubectl get akrp <name> -o jsonpath='{.status.lastDecision}'
```
