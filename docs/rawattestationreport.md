# RawAttestationReport

`RawAttestationReport` (shortName `rar`) est le **rapport d'attestation brut, non appraisé**,
émis par le `node-attestation-agent` (DaemonSet). Il n'est **pas** une preuve : seul le
`central-verifier` (writer unique) le consomme pour produire une `AttestationEvidence`
appraisée. Cette séparation est le cœur du modèle single-writer RATS.

## Spec

| Champ | Type | Rôle |
|---|---|---|
| `nodeName` * | string | Nœud d'origine. |
| `provider` * | enum `maa` \| `simulator` | Source d'attestation (Microsoft Azure Attestation ou simulateur kind). |
| `collectedAt` * | date-time | Horodatage de collecte par l'agent. |
| `rawToken` / `rawTokenHash` | string | Token MAA/guest-attestation brut (JWT) et son SHA-256 (tamper-evidence). |
| `nonce` | string | Nonce de fraîcheur embarqué dans la requête d'attestation. |
| `nodeUID`, `agentPodUID`, `agentServiceAccount` | string | Traçabilité de l'agent collecteur. |
| `simulated` | bool | Marque les rapports kind/dev — ils ne peuvent jamais devenir de l'évidence réelle. |

## Status (écrit par le central-verifier)

| Champ | Rôle |
|---|---|
| `processed` | Le verifier a consommé ce rapport. |
| `evidenceRef` | Nom de l'`AttestationEvidence` produite (si vérifié). |
| `verificationStatus` | `Verified` \| `Failed` \| `Unavailable`. |

```bash
kubectl get rar -o wide
```
