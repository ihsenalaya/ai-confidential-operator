# AttestationEvidence

`AttestationEvidence` (shortName `aevid`) est l'**évidence d'attestation appraisée** d'un
sujet (nœud, workload, device). En production, **seul le central-verifier écrit son status**
(single-writer prouvé par RBAC) ; l'agent nœud ne produit que des `RawAttestationReport`.
En kind, une évidence `simulated: true` permet de dérouler toute la chaîne sans TEE réel.

## Spec

| Champ | Type | Rôle |
|---|---|---|
| `subjectRef` * | object | Sujet attesté (`name`, `namespace`). |
| `evidenceType` * | enum `cpu` \| `gpu` \| `runtime` \| `composite` | Domaine d'attestation. |
| `tee` * | enum `TDX` \| `SEV-SNP` \| `none` | TEE attesté. |
| `freshness` * | object | `maxAgeSeconds` (requis) + `simulated`. |
| `simulated` | bool | Évidence produite par le simulateur kind (explicite). |
| `digest`, `evidenceURI`, `signatures` | — | Digest immuable, payload externe, signatures. |
| `policyRef`, `runtime` | object | Liaison optionnelle à une CIP / runtime attendue. |

## Status (single-writer : central-verifier)

| Champ | Rôle |
|---|---|
| `verificationStatus` | `Verified` \| `Failed` \| `Unavailable`. |
| `evidenceMode` | `real` (attestation authentique) \| `simulated` \| `unverified`. |
| `claimsDigest`, `maaTokenHash`, `nonce` | Digests canoniques des claims vérifiés. |
| `issuedAt`, `expiresAt`, `freshnessSeconds`, `lastVerifiedTime` | Fenêtre de validité. |
| `verifiedBy`, `verifierPodUID`, `nodeUID` | Identité du verifier + liaison au nœud. |
| `revoked` | Évidence invalidée (voir `AIRevocationPolicy`). |

## Exemple (kind, simulé)

```yaml
apiVersion: aiops.imperium.io/v1alpha1
kind: AttestationEvidence
metadata:
  name: node-worker-evidence
spec:
  subjectRef:
    name: kind-worker
  evidenceType: cpu
  tee: SEV-SNP
  simulated: true
  freshness:
    maxAgeSeconds: 3600
    simulated: true
```

```bash
kubectl get aevid -o wide
kubectl get aevid node-worker-evidence -o jsonpath='{.status.evidenceMode}'
```
