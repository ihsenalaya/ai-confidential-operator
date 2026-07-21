# AIEvidenceRecord

`AIEvidenceRecord` (shortName `aier`) est le **journal d'audit chaîné** de la gouvernance
confidentielle : chaque enregistrement immuable référence le digest du précédent
(append-only) et peut être ancré sur un checkpoint externe (anti-falsification).

## Spec

| Champ | Type | Rôle |
|---|---|---|
| `category` * | enum `attestation` \| `placement` \| `key-release` \| `revocation` \| `audit-checkpoint` | Domaine audité. |
| `subjectRef` * | object | Workload/décision audité. |
| `payloadDigest` | string | Digest immuable du payload stocké. |
| `previousRecordDigest` | string | Chaînage append-only. |
| `externalCheckpointRef` | string | Checkpoint d'ancrage externe. |
| `policyRef` | object | Politique émettrice. |
| `retentionDays` | int | Objectif de rétention. |

## Status

| Champ | Rôle |
|---|---|
| `chainDigest` | Digest matérialisé de ce nœud de chaîne. |
| `anchored` | Le segment est checkpointé en externe. |

```bash
kubectl get aier
kubectl get aier <name> -o jsonpath='{.status.chainDigest}'
```
