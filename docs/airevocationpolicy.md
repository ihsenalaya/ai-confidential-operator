# AIRevocationPolicy

`AIRevocationPolicy` (shortName `airvp`) **révoque** une évidence, une décision de placement
ou un ensemble de workloads pendant une fenêtre bornée (`ttlSeconds`), par exemple après un
incident de sécurité ou une rotation de flotte. À expiration, la réévaluation reprend.

## Spec

| Champ | Type | Rôle |
|---|---|---|
| `target` * | object | Sujets révoqués (namespaces/workloads). |
| `ttlSeconds` * | int | Fenêtre de révocation bornée avant réévaluation. |
| `evidenceRef` | object | Évidence spécifiquement révoquée. |
| `placementRef` | object | Décision de placement spécifiquement révoquée. |
| `reasons` | array | Justifications (audit). |
| `audit` | object | `required` + `level`. |

## Status

| Champ | Rôle |
|---|---|
| `active` | La révocation est en vigueur. |
| `expiresAt` | Fin de la fenêtre de révocation. |

```bash
kubectl get airvp
```
