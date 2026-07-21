# AI Confidential Operator

Opérateur Kubernetes **autonome** de gouvernance confidential-computing pour workloads IA :
chaîne d'attestation **RATS** (SEV-SNP/TDX, simulée en kind), placement vérifiable signé
(Ed25519), libération de clés conditionnée à l'attestation, révocation bornée et journal
d'audit chaîné. Il héberge aussi les **webhooks pods** (injection de sidecar + validation
confidentielle).

Module Go indépendant (`github.com/ihsenalaya/ai-confidential-operator`), dépôt et
historique git propres. Il s'installe et fonctionne **seul**, sans aucune dépendance
d'exécution vers un autre opérateur.

## Contenu du dépôt

```
ai-confidential-operator/
├── api/v1alpha1/                     ← 7 CRDs possédées
├── cmd/                              ← manager + binaires satellites (voir tableau ci-dessous)
├── internal/                         ← contrôleurs + moteurs (keyrelease, evidence, approval,
│                                        placement, scheduler, webhook/{bootstrap,podinjector})
├── pkg/                              ← attestation (dont provider maa), crypto, token
├── config/                           ← manifests kustomize (crd, rbac, manager, webhook, samples)
├── charts/ai-confidential-operator/  ← Helm chart indépendant (7 CRDs + RBAC scopé)
├── docs/                             ← une fiche par CRD
├── automatisation/
│   ├── up.sh / down.sh               ← cluster kind complet en une commande (mode simulé)
│   ├── test-apps/                    ← chaîne d'attestation simulée + policies + pod démo
│   └── dashboards/                   ← dashboard Grafana "Attestation & Placement"
└── Dockerfile[.<satellite>]          ← une image par binaire
```

## Architecture single-writer

```
node-attestation-agent (DaemonSet)          central-verifier (Deployment)
        │  émet (non fiable)                        │  UNIQUE writer
        ▼                                           ▼
RawAttestationReport ──── appraisal RATS ──→ AttestationEvidence (status)
                                                    │
                              ┌─────────────────────┼──────────────────┐
                              ▼                     ▼                  ▼
                    AIPlacementDecision      AIKeyReleasePolicy   AIEvidenceRecord
                    (scheduler, token        (key-release-        (audit chaîné,
                     Ed25519 signé)           gateway)             ancrage externe)
```

Le manager (`cmd/confidential-manager`) réconcilie les CRDs, bootstrappe les **runtime
classes simulées** (`simulated-kata-qemu-tdx/snp`) et les webhooks pods. L'appraisal réel
reste dans le binaire dédié `central-verifier` (le RBAC prouve le single-writer) ; en kind,
l'évidence simulée est explicite (`simulated: true`, jamais convertible en évidence réelle).

## Binaires & images

Architecture multi-binaire : chaque composant a son propre `cmd/`, sa propre image, et un
périmètre RBAC distinct.

| Binaire | Rôle | Image (Dockerfile) |
|---|---|---|
| `confidential-manager` | Contrôleurs des 7 CRDs, bootstrap runtime classes simulées, webhooks pods | `Dockerfile` |
| `attestation-scheduler` | Traduit une `AttestationEvidence` valide en `AIPlacementDecision` signée | `Dockerfile.attestation-scheduler` |
| `key-release-gateway` | Libère une clé seulement contre évidence valide (`AIKeyReleasePolicy`) | `Dockerfile.key-release-gateway` |
| `central-verifier` | Seul écrivain autorisé d'`AttestationEvidence` (appraisal RATS réel) | `Dockerfile.central-verifier` |
| `node-attestation-agent` | DaemonSet nœud : émet les `RawAttestationReport` (provider `maa` en prod, `simulator` en kind) ; embarque l'helper C++ `guest-attestation-helper` (liaison `azguestattestation`) | `Dockerfile.node-attestation-agent` |

CLI locales (non déployées en cluster, pas d'image dédiée) :

| CLI | Rôle |
|---|---|
| `sign-evidence` | Signe hors-cluster une évidence d'attestation (ConfigMap) |
| `verify-placement` | Vérifie hors-cluster un jeton `AIPlacementDecision` (Ed25519) |
| `sign-approval` | Utilitaire de signature Ed25519 générique (`internal/approval`), réutilisable pour des flux d'approbation côté `ai-govar-operator` — voir [Intégrations](#intégration-avec-les-autres-opérateurs) |

## Fonctionnement

La chaîne suit le modèle **RATS** (Remote ATtestation procedureS) avec une séparation
stricte émetteur / vérifieur / consommateur :

1. **Ingestion** — chaque nœud TEE émet un `RawAttestationReport` (rapport brut,
   **non fiable par construction**) via le `node-attestation-agent`. En kind, le
   provider `simulator` produit des rapports simulés explicites.
2. **Appraisal (single-writer)** — seul le `central-verifier` (ou le mode simulé du
   manager en dev) a le droit RBAC d'écrire une `AttestationEvidence` : le rapport brut
   est appraisé (mesures, TCB, fraîcheur) et l'évidence résultante porte
   `simulated: true|false` — une évidence simulée n'est **jamais convertible** en
   évidence réelle.
3. **Placement** — `AIPlacementDecision` confronte les évidences valides aux exigences
   de la `ConfidentialInferencePolicy` (type de TEE, fraîcheur, runtime class, digest
   d'image) et publie une décision **signée Ed25519**, vérifiable hors cluster.
4. **Webhooks pods** — le manager héberge le mutating webhook (`/mutate-v1-pod`,
   injection du sidecar confidentiel) et le validating webhook (`/validate-v1-pod`,
   conformité runtime class / policy). En mode `warn` il annote, en mode `enforce` il
   **rejette** les pods non conformes. Les namespaces système et celui de l'opérateur
   sont exclus (anti-deadlock). Ce sont les **deux seuls** endpoints d'admission de cet
   opérateur — voir la note sur `AIChangeRequest` dans [Intégrations](#intégration-avec-les-autres-opérateurs).
5. **Libération de clés** — `AIKeyReleasePolicy` conditionne la libération d'une clé
   (via le `key-release-gateway`) à la présence d'une évidence valide : pas
   d'attestation → pas de clé → pas de données déchiffrées.
6. **Révocation & audit** — `AIRevocationPolicy` révoque de façon **bornée** (par nœud,
   par période) évidences et placements ; chaque étape est journalisée dans
   `AIEvidenceRecord`, un journal **append-only chaîné** (hash précédent → suivant)
   ancrable sur un checkpoint externe.
7. **Bootstrap dev** — sur kind, le manager crée automatiquement les runtime classes
   simulées `simulated-kata-qemu-tdx` / `simulated-kata-qemu-snp` et expose la métrique
   `ai_simulated_runtimeclass_in_use` pour rendre le mode simulé **visible** (jamais
   silencieux).

## Fonctionnalités

- **Chaîne d'attestation RATS complète** : rapport brut → appraisal → évidence typée,
  avec séparation émetteur/vérifieur prouvée par le RBAC (single-writer).
- **Mode simulé honnête** pour kind/dev : SEV-SNP/TDX simulés, marqués comme tels de
  bout en bout (CRs, métriques, dashboard) — impossible à confondre avec du TEE réel.
- **Placement vérifiable signé** (Ed25519) : la décision de scheduler un workload
  confidentiel est un artefact vérifiable, pas un effet de bord.
- **Politiques par workload** (`ConfidentialInferencePolicy`) : exigences TEE,
  fraîcheur d'évidence, runtime class, digest d'image, `reportOnly`/`warn`/`enforce`.
- **Key-release conditionné à l'attestation** : libération de clés seulement contre
  évidence valide, avec raisons de refus auditables.
- **Révocation bornée** : rayon d'action limité par policy (pas de révocation globale
  accidentelle).
- **Audit chaîné append-only** avec ancrage externe optionnel (non-répudiation).
- **Injection & validation de pods** par webhooks, avec exclusions anti-deadlock.

## CRDs possédées (7)

| CRD | shortName | Rôle | Doc |
|---|---|---|---|
| ConfidentialInferencePolicy | `cip` | Exigences TEE/fraîcheur/runtime d'un workload | [docs/confidentialinferencepolicy.md](docs/confidentialinferencepolicy.md) |
| RawAttestationReport | `rar` | Rapport brut non appraisé (agent nœud) | [docs/rawattestationreport.md](docs/rawattestationreport.md) |
| AttestationEvidence | `aevid` | Évidence appraisée (single-writer) | [docs/attestationevidence.md](docs/attestationevidence.md) |
| AIPlacementDecision | `apd` | Décision de placement signée | [docs/aiplacementdecision.md](docs/aiplacementdecision.md) |
| AIKeyReleasePolicy | `akrp` | Libération de clé conditionnée à l'attestation | [docs/aikeyreleasepolicy.md](docs/aikeyreleasepolicy.md) |
| AIRevocationPolicy | `airvp` | Révocation bornée d'évidence/placement | [docs/airevocationpolicy.md](docs/airevocationpolicy.md) |
| AIEvidenceRecord | `aier` | Journal d'audit append-only chaîné | [docs/aievidencerecord.md](docs/aievidencerecord.md) |

## Installation

### Prérequis

- Kubernetes ≥ 1.29, Helm ≥ 3.12.
- **Production** : nœuds SEV-SNP/TDX (ex. AKS confidential), Microsoft Azure Attestation
  (provider `maa`), les déploiements `central-verifier`, `node-attestation-agent` et
  `key-release-gateway` (images publiées sur le même registre `ghcr.io/ihsenalaya/ai-confidential-operator/*`).
- **kind/dev** : rien d'autre — le mode simulé est bootstrappé automatiquement.

### Installation du chart

```bash
helm install confidential ./charts/ai-confidential-operator \
  --namespace confidential-system --create-namespace
```

Image par défaut : `ghcr.io/ihsenalaya/ai-confidential-operator/confidential-operator`.
Valeurs utiles :

```bash
# Image locale (kind) :
--set image.repository=confidential-operator --set image.tag=dev --set image.pullPolicy=Never
# Prometheus Operator :
--set metrics.serviceMonitor.enabled=true --set metrics.serviceMonitor.labels.release=monitoring
# Fallbacks embarqués dev-only (le single-writer reste le central-verifier) :
--set compat.enableEmbeddedVerifier=true
```

### Vérification

```bash
kubectl -n confidential-system get deploy
kubectl get runtimeclasses | grep simulated       # bootstrappées par l'opérateur
kubectl get mutatingwebhookconfigurations aiops-sidecar-injector
```

## Démarrage rapide kind (tout-en-un)

```bash
cd automatisation
./up.sh          # kind + Prometheus/Grafana + opérateur + chaîne simulée + dashboard
```

Les applications de test (`confidential-demo`) installent : une
`ConfidentialInferencePolicy` (warn), un `RawAttestationReport` simulé, une
`AttestationEvidence` SEV-SNP simulée, un `AIEvidenceRecord`, une `AIKeyReleasePolicy`,
une `AIRevocationPolicy` et un **pod démo** sur la runtime class `simulated-kata-qemu-snp`
(validé par le webhook).

```bash
kubectl -n confidential-demo get cip,rar,aevid,akrp,airvp,aier
kubectl -n confidential-demo get pod confidential-demo-app -o jsonpath='{.spec.runtimeClassName}'
```

Grafana : `kubectl -n monitoring port-forward svc/monitoring-grafana 3000:80`
→ dashboard **AI Confidential Operator — Attestation & Placement** (réconciliations
par contrôleur et erreurs, taux de succès et latence p99 des webhooks pods, workqueue,
runtime class simulée en usage, latences de réconciliation p50/p95/p99).

Démontage : `./down.sh`.

## Utilisation

### Passer en mode enforce

```yaml
spec:
  enforcementMode: enforce   # le webhook rejette les pods non conformes
```

Le webhook de validation exclut les namespaces système et le namespace de l'opérateur
(anti-deadlock) ; la politique s'applique aux namespaces sélectionnés par `target`.

### Production (TEE réel)

1. Déployer `central-verifier` + `node-attestation-agent` (DaemonSet) + `key-release-gateway`.
2. Les agents émettent des `RawAttestationReport` (provider `maa`) ; le verifier produit les
   `AttestationEvidence` avec `evidenceMode: real`.
3. `ConfidentialInferencePolicy` en `enforce`, avec `requireImageDigest` et TTL courts.
4. La chaîne d'audit `AIEvidenceRecord` peut être ancrée sur un checkpoint externe.

## Intégration avec les autres opérateurs

Aucune dépendance d'exécution : `ai-finops-operator` et `ai-govar-operator` fonctionnent
sans `ai-confidential-operator`, et réciproquement. Sur un même cluster, chaque chart
n'installe que ses propres CRDs et son propre RBAC.

- **Webhooks pods, propres à cet opérateur** : `/mutate-v1-pod` et `/validate-v1-pod`
  sont les deux seuls endpoints d'admission enregistrés par `confidential-manager`
  (`bootstrap.Scope = ScopePods`). Il n'y a **aucune délégation en cours d'exécution**
  vers l'admission `AIChangeRequest` de `ai-govar-operator` : une branche héritée du
  webhook pods qui appelait conditionnellement le code d'approbation de `govar` était
  du **code mort** (la seule scope réellement enregistrée par ce manager ne pouvait
  jamais l'atteindre) — elle a été supprimée, pas dupliquée.
- **Utilitaire de signature partagé, optionnel** : la CLI `sign-approval` (et le paquet
  `internal/approval`) implémentent la primitive de signature Ed25519 qui lie une
  décision d'approbation humaine à un `AIChangeRequest` — c'est un utilitaire
  cryptographique autonome, indépendant du webhook pods, utile si vous exploitez ce
  binaire aux côtés d'`ai-govar-operator` (qui possède la CRD `AIChangeRequest` et son
  propre webhook d'admission). Il ne crée pas de dépendance réseau ou API entre les
  deux opérateurs.
- **Runtime classes simulées et évidences** : purement locales à ce cluster/opérateur,
  aucun état partagé avec `ai-finops-operator`/`ai-govar-operator`.

> Ne pas installer ce chart **et** un ancien chart monolithique qui enregistrerait aussi
> les webhooks pods sur le même cluster (double enregistrement de
> `mutatingwebhookconfigurations`/`validatingwebhookconfigurations`).

## Statut

Déployé et vérifié bout en bout sur kind (mode simulé) : runtime classes simulées
bootstrappées, webhooks pods `/mutate-v1-pod` + `/validate-v1-pod` répondant HTTP 200,
chaîne d'attestation simulée bout en bout (`RawAttestationReport` → `AttestationEvidence`
→ `AIPlacementDecision`/`AIKeyReleasePolicy`/`AIEvidenceRecord`), pod démo planifié sur
`simulated-kata-qemu-snp` et validé par le webhook, dashboard Grafana **AI Confidential
Operator — Attestation & Placement** importé et aligné sur les métriques `ai_*` réellement
exposées.
