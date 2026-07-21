# AIPlacementDecision

`AIPlacementDecision` (shortName `apd`) matérialise une **décision de placement vérifiable** :
un workload confidentiel est autorisé (ou non) à s'exécuter sur un nœud, sur la base d'une
politique (`ConfidentialInferencePolicy`) et d'une évidence d'attestation. En production le
scheduler attestation-aware mint un **token Ed25519 signé** ; `verify-placement` permet la
vérification hors-cluster.

## Spec

| Champ | Type | Rôle |
|---|---|---|
| `targetRef` * | object | Workload/pod placé. |
| `policyRef` * | object | Politique de confidentialité utilisée. |
| `evidenceRef` | object | Évidence d'attestation utilisée. |
| `placementToken` | object | `required` (mint obligatoire) + `ttlSeconds`. |
| `schedulerName` | string | Scheduler censé honorer la décision. |

## Status

| Champ | Rôle |
|---|---|
| `decision` | `allow` \| `deny` \| `pending`. |
| `nodeName` | Nœud choisi. |
| `placementTokenDigest` | Digest du token de placement minté. |
| `simulated` | Chemin simulé kind. |

```bash
kubectl get apd
kubectl get apd <name> -o jsonpath='{.status.decision} {.status.nodeName}'
```
