# AI Confidential Operator

[![Go Reference](https://img.shields.io/badge/go-1.26-00ADD8?logo=go)](go.mod)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CRDs](https://img.shields.io/badge/CRDs-7-informational)](docs/)

Un opérateur Kubernetes qui répond à une question simple : **« ce workload IA tourne-t-il
vraiment sur du matériel sécurisé, et puis-je le prouver ? »**

Il vérifie que les nœuds sont dans un environnement d'exécution matériel protégé (un
**TEE**, *Trusted Execution Environment* — par exemple Intel TDX ou AMD SEV-SNP), place les
pods confidentiels uniquement sur ces nœuds avec une preuve signée, ne libère les clés/secrets
sensibles qu'aux workloads correctement attestés, et journalise tout dans une chaîne d'audit
infalsifiable. Un mode simulé honnête permet de tester tout le flux sur un simple cluster
`kind`, sans matériel spécial — jamais confondu avec une attestation réelle.

C'est un module Go indépendant, installable et fonctionnel **seul**, sans dépendre d'aucun
autre opérateur.

## Table des matières

- [Glossaire express](#glossaire-express)
- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Les 7 CRDs, expliquées simplement](#les-7-crds-expliquées-simplement)
- [Comment les décisions sont prises](#comment-les-décisions-sont-prises)
  - [Le scheduling d'un pod confidentiel, en détail](#le-scheduling-dun-pod-confidentiel-en-détail)
- [Binaires & images](#binaires--images)
- [Installation](#installation)
- [Démarrage rapide (kind)](#démarrage-rapide-kind)
- [Console graphique](#console-graphique)
- [Configuration](#configuration)
- [Métriques Prometheus](#métriques-prometheus)
- [Modèle de sécurité](#modèle-de-sécurité)
- [Référence technique avancée](#référence-technique-avancée)
- [Dépannage](#dépannage)
- [Contribuer](#contribuer)
- [License](#license)

## Glossaire express

Quatre mots reviennent partout dans ce document — les comprendre suffit à lire tout le reste :

| Terme | En clair |
|---|---|
| **TEE** | Une zone protégée du processeur où le code et la mémoire d'un programme sont chiffrés et invisibles même pour l'administrateur de la machine. |
| **SEV-SNP / TDX** | Deux implémentations concrètes de TEE — AMD et Intel. Ce sont les deux seuls types supportés ici. |
| **Attestation** | La preuve cryptographique, signée par le processeur ou le cloud, qu'un TEE donné est authentique et non trafiqué. |
| **RATS** | Le nom du flux standard « collecter → vérifier → produire une évidence de confiance » que cet opérateur implémente. |

## Fonctionnalités

- **Vérifie l'attestation matérielle des nœuds** et transforme un rapport brut, non fiable, en
  une évidence de confiance signée par un seul composant autorisé à le faire.
- **Choisit où un pod confidentiel peut tourner**, uniquement sur un nœud dont l'attestation
  est valide et récente, et **signe la décision** (Ed25519) pour qu'elle reste vérifiable même
  hors du cluster.
- **Ne libère jamais une clé ou un secret** à un workload sans évidence d'attestation valide —
  avec une raison de refus précise et lisible à chaque fois.
- **Révoque un nœud ou une décision** pendant une durée bornée (jamais une révocation globale
  accidentelle), avec réévaluation automatique à expiration.
- **Journalise tout dans une chaîne d'audit** append-only (chaque entrée référence la
  précédente par son empreinte), avec ancrage externe optionnel.
- **Filtre et corrige les pods à l'admission** (webhooks) : annotation automatique, choix de la
  bonne runtime class, ou rejet des pods non conformes selon la politique du namespace.
- **Mode simulé honnête pour le développement** : tout le flux (rapport → évidence → placement
  → clé) fonctionne sur `kind` sans matériel TEE réel, et chaque objet simulé est marqué
  `simulated: true` de bout en bout — jamais silencieusement pris pour une attestation réelle.
- **Une responsabilité, un binaire** : le manager, le scheduler, la gateway de clés et le
  vérificateur d'attestation sont des processus et des permissions Kubernetes (RBAC) séparés,
  pas seulement des couches de code — voir [Modèle de sécurité](#modèle-de-sécurité).

## Architecture

```
node-attestation-agent (DaemonSet)          central-verifier (Deployment)
        │  collecte (non fiable)                     │  SEUL autorisé à écrire
        ▼                                             ▼
RawAttestationReport ──── vérification ──────→ AttestationEvidence
                                                       │
                              ┌────────────────────────┼───────────────────┐
                              ▼                        ▼                   ▼
                    AIPlacementDecision       AIKeyReleasePolicy     AIEvidenceRecord
                    (attestation-scheduler,    (key-release-          (audit chaîné,
                     jeton Ed25519 signé)       gateway)               ancrage externe)
```

Le manager (`confidential-manager`) réconcilie les CRDs de politique et d'audit, prépare
l'environnement `kind` (runtime classes simulées), et filtre les pods à l'admission. La
vérification d'attestation elle-même est isolée dans un binaire séparé, `central-verifier` —
volontairement, pour que ce soit les permissions Kubernetes, et non une simple convention de
code, qui garantissent qu'aucun autre composant ne peut fabriquer une évidence.

> Deux réconciliateurs de compatibilité existent mais sont **désactivés par défaut**
> (`AIOPS_ENABLE_LEGACY_EVIDENCE_RECONCILER`, `AIOPS_ENABLE_EMBEDDED_VERIFIER`) — utiles pour
> un déploiement mono-binaire en dev, jamais recommandés en production. Détails dans la
> [référence technique](#référence-technique-avancée).

## Les 7 CRDs, expliquées simplement

Chaque CRD a une fiche complète dans [`docs/`](docs/) (tous les champs, tout le status). Ici :
une explication en une phrase, un exemple minimal, et ce qu'il faut retenir.

### 1. ConfidentialInferencePolicy — la règle du jeu

*« Les pods de ce namespace doivent tourner sur tel TEE, avec une évidence pas trop vieille,
sinon je préviens / je bloque. »*

```yaml
apiVersion: aiops.imperium.io/v1alpha1
kind: ConfidentialInferencePolicy
metadata:
  name: llm-workloads-must-be-attested
  namespace: production
spec:
  target:
    workloadSelector:
      matchLabels: { ai-workload: "true" }
  enforcementMode: enforce        # warn | enforce | audit
  maxEvidenceAgeSeconds: 300
  requiredTEE: [SEV-SNP]
  requireConfidentialContainers: true
```

À retenir : c'est une politique de référence, lue par les webhooks et le scheduler — elle n'a
**pas de contrôleur qui la réconcilie en tâche de fond**, donc pas de `status` qui se met à
jour tout seul. → [Détails](docs/confidentialinferencepolicy.md)

### 2. RawAttestationReport — la preuve brute, pas encore fiable

*« Voici ce que le nœud prétend, ne me croyez pas encore. »* Créé automatiquement par
`node-attestation-agent` toutes les `REPORT_INTERVAL_SECONDS` — vous ne l'écrivez jamais à la
main :

```bash
kubectl get rawattestationreport -n confidential-system
```

→ [Détails](docs/rawattestationreport.md)

### 3. AttestationEvidence — le verdict officiel

*« Voici le résultat vérifié : ce nœud est bien dans un TDX/SEV-SNP authentique, valide
jusqu'à telle date. »* Créé automatiquement par `central-verifier` à partir du rapport
ci-dessus — vous ne l'écrivez pas non plus, vous le consultez :

```bash
kubectl get attestationevidence -n confidential-system -o wide
```

À retenir : `status.evidenceMode` vaut `real`, `simulated` ou `unverified` — c'est le champ
que tout le reste du système regarde. → [Détails](docs/attestationevidence.md)

### 4. AIPlacementDecision — le droit de tourner ici, signé

*« Ce pod a le droit de tourner sur ce nœud, et voici la preuve signée cryptographiquement. »*
Créé automatiquement par `attestation-scheduler` quand il place un pod — consultation :

```bash
kubectl get aiplacementdecision -n production
```

→ [Détails](docs/aiplacementdecision.md)

### 5. AIKeyReleasePolicy — le gardien des clés

*« Ne libère jamais cette clé/ce secret à un workload sans évidence d'attestation valide. »*

```yaml
apiVersion: aiops.imperium.io/v1alpha1
kind: AIKeyReleasePolicy
metadata:
  name: model-weights-release
  namespace: production
spec:
  target:
    workloadSelector:
      matchLabels: { ai-workload: "true" }
  enforcementMode: enforce
  requireAttestedEvidence: true
  allowedSecrets: [model-weights-secret]
  keyRelease: { required: true, ttlSeconds: 300 }
  audit: { required: true, level: full }
```

→ [Détails](docs/aikeyreleasepolicy.md) · la règle de décision exacte est expliquée
[plus bas](#comment-les-décisions-sont-prises).

### 6. AIRevocationPolicy — couper court, mais pas pour toujours

*« Révoque ce nœud ou cette décision pendant X secondes, puis réévalue automatiquement. »*

```yaml
apiVersion: aiops.imperium.io/v1alpha1
kind: AIRevocationPolicy
metadata:
  name: revoke-compromised-node
  namespace: production
spec:
  target:
    nodeName: worker-3
  ttlSeconds: 3600
  reasons: ["suspected key compromise"]
```

À retenir : la fenêtre est **toujours bornée** (`ttlSeconds`) — impossible de révoquer
« pour toujours » par erreur. → [Détails](docs/airevocationpolicy.md)

### 7. AIEvidenceRecord — la ligne d'audit infalsifiable

*« Voici l'entrée N de la chaîne d'audit, elle référence l'entrée N-1 par son empreinte. »*
Alimenté par le flux d'audit (attestation, placement, libération de clé, révocation) — chaque
entrée est immuable une fois créée :

```bash
kubectl get aievidencerecord -n confidential-system
```

→ [Détails](docs/aievidencerecord.md)

## Comment les décisions sont prises

Vue simple d'abord ; le détail exact (codes de refus, algorithme du scheduler) est dans la
[référence technique avancée](#référence-technique-avancée).

- **Libération de clé** : une clé n'est jamais libérée si la politique n'est pas satisfaite,
  si l'évidence est absente/révoquée/expirée, ou si le jeton de placement ne correspond pas
  exactement au pod/à l'image/au modèle attendus. Chaque refus a une raison machine-lisible
  précise (ex. `EVIDENCE_EXPIRED`, `POD_UID_MISMATCH`).
- **Placement d'un pod** : le scheduler ne retient que les nœuds avec une évidence valide et
  fraîche, revérifie tout **une seconde fois juste avant de lier le pod** (pour ne rien laisser
  changer entre la sélection et l'exécution), puis seulement à ce moment-là signe et publie la
  décision. Schéma détaillé juste en dessous.
- **Admission des pods** : un pod couvert par une `ConfidentialInferencePolicy` peut être
  annoté/corrigé automatiquement (runtime class, scheduler) ou rejeté selon que la politique est
  en `warn`, `audit` ou `enforce`.

### Le scheduling d'un pod confidentiel, en détail

`attestation-scheduler` **n'est pas un plugin du scheduler par défaut de Kubernetes** — c'est
un second scheduler complet, qui tourne en parallèle, à côté du scheduler standard. Les deux
coexistent sans se gêner : chaque pod choisit lequel doit le placer via un seul champ de sa
spec :

```yaml
spec:
  schedulerName: ai-attestation-scheduler   # sinon, le scheduler par défaut le prend en charge
```

Le scheduler par défaut ignore tous les pods qui portent ce nom ; symétriquement,
`attestation-scheduler` n'observe **que** ceux-là. Une fois qu'un tel pod apparaît, il traverse
six étapes, dans cet ordre :

```
 Pod créé avec schedulerName: ai-attestation-scheduler
                          │
                          ▼
 ① PreFilter   charge la ConfidentialInferencePolicy dont le namespaceSelector/
                workloadSelector correspond à ce pod (aucune policy → le pod
                n'est pas géré par ce scheduler)
                          │
                          ▼
 ② Filter      liste tous les nœuds du cluster, élimine :
                  • les nœuds non-schedulable, ou dont le nodeSelector/taint
                    du pod (ou de sa RuntimeClass) n'est pas satisfait
                  • PUIS ne garde que ceux qui ont au moins une
                    AttestationEvidence : non révoquée, vérifiée (Verified=true),
                    assez fraîche (< maxEvidenceAgeSeconds) et du bon type de
                    TEE (requiredTEE)
                          │
                 candidats trouvés ? ──oui──┐
                          │ non              │
                          ▼                  │
 ③ Permit      relance l'étape ② toutes      │
                les 250 ms, jusqu'à 15 s     │
                (laisse le temps à une       │
                évidence en cours de         │
                vérification d'arriver)      │
                          │                  │
                 toujours aucun ? ──▶ échec  │
                (le pod reste Pending)       │
                          │                  │
                          └────────┬─────────┘
                                   ▼
 ④ Score       chaque nœud candidat part de 100 points, puis :
                  + jusqu'à 50 points selon la fraîcheur de son évidence
                  + 20 points si l'évidence n'est pas simulée
                  + 10 points (TDX) ou 5 points (SEV-SNP)
                → tri décroissant, le nœud le mieux noté est retenu
                          │
                          ▼
 ⑤ Reserve     crée l'AIPlacementDecision avec status.decision = "pending"
                          │
                          ▼
    PreBind    🔒 fail-closed, obligatoire : relit À CET INSTANT PRÉCIS le
   (dans        pod, la policy et l'évidence sélectionnée, et revérifie que
   Reserve)     rien n'a changé depuis l'étape ② (même empreinte de policy,
                évidence toujours non révoquée et toujours dans sa fenêtre
                de fraîcheur). Un seul écart → status.decision = "deny",
                et AUCUN jeton n'est émis : la réservation s'arrête là.
                          │
                     PreBind passé
                          ▼
      Mint      un jeton signé Ed25519 est créé, liant ensemble : l'UID du
                pod, l'empreinte de sa spec, le digest de l'image et du
                modèle, le nom du nœud, l'empreinte de la policy et celle
                de l'évidence — avec une expiration (5 min par défaut).
                L'AIPlacementDecision passe à status.decision = "allow",
                le jeton est stocké dans une annotation.
                          │
                          ▼
 ⑥ Bind        le pod est lié au nœud choisi via l'API Binding native de
                Kubernetes — le scheduler par défaut n'intervient à aucun
                moment de ce flux.
```

**Pourquoi une revérification à l'étape PreBind, alors que l'étape ② vient déjà de tout
vérifier ?** Entre le moment où un nœud est choisi (Score) et celui où le pod y est
effectivement lié (Bind), un peu de temps s'écoule — le temps qu'une évidence expire, qu'une
policy change, ou qu'une révocation arrive. Sans cette seconde vérification, un pod pourrait
être lié sur la base d'une évidence qui n'est déjà plus valide au moment de l'exécution. En
revérifiant juste avant le `Bind`, cette fenêtre est réduite au minimum : c'est ce que la
[section sécurité](#modèle-de-sécurité) appelle le comportement *fail-closed* du scheduler.

`verify-placement` (CLI) permet de revérifier ce jeton entièrement hors cluster, à partir de la
seule clé publique — utile pour qu'un tiers audite une décision sans accès au cluster.

## Binaires & images

| Binaire | Rôle en une phrase | Image |
|---|---|---|
| `confidential-manager` | Réconcilie les politiques et l'audit, prépare le mode simulé, filtre les pods à l'admission. | `Dockerfile` |
| `attestation-scheduler` | Un second scheduler Kubernetes qui ne place les pods confidentiels que sur des nœuds attestés, et signe sa décision. | `Dockerfile.attestation-scheduler` |
| `central-verifier` | Le seul composant autorisé à transformer un rapport brut en évidence de confiance. | `Dockerfile.central-verifier` |
| `key-release-gateway` | Service HTTP qui décide d'autoriser ou refuser la libération d'une clé/d'un secret. | `Dockerfile.key-release-gateway` |
| `node-attestation-agent` | Tourne sur chaque nœud (DaemonSet), collecte la preuve d'attestation matérielle. | `Dockerfile.node-attestation-agent` |
| `guest-attestation-helper` | Petit binaire C++ utilisé par l'agent ci-dessus pour parler à Azure en production. | intégré à l'image `node-attestation-agent` |

Trois petits outils en ligne de commande (à lancer localement, jamais déployés en cluster) :
`sign-evidence` (signe un ConfigMap d'évidence hors cluster), `verify-placement` (vérifie un
jeton de placement hors cluster) et `sign-approval` (signe une décision humaine générique,
réutilisable par d'autres opérateurs sans créer de dépendance réseau).

## Installation

### Prérequis

- Kubernetes ≥ 1.29, Helm ≥ 3.12.
- **En production** : des nœuds SEV-SNP ou TDX réels (ex. AKS confidential-computing) et
  Microsoft Azure Attestation.
- **En local (kind)** : rien de spécial — le mode simulé est activé automatiquement.

### Installer le chart

```bash
helm install confidential ./charts/ai-confidential-operator \
  --namespace confidential-system --create-namespace
```

```bash
kubectl -n confidential-system get deploy
kubectl get runtimeclasses | grep simulated
```

## Démarrage rapide (kind)

```bash
cd automatisation
./up.sh      # crée un cluster kind, installe l'opérateur et une démo simulée complète
```

```bash
kubectl -n confidential-demo get cip,rar,aevid,akrp,airvp,aier
```

Démontage : `./down.sh`.

## Console graphique

Une interface web pour créer/modifier les CRDs sans écrire de YAML à la main —
**déployée automatiquement avec l'opérateur**, dans le cluster, comme n'importe où d'autre
tu installes ce chart (`console.enabled: true` par défaut).

Elle tourne avec son **propre ServiceAccount et son propre RBAC**, scopé uniquement aux 7
CRDs de cet opérateur (`charts/ai-confidential-operator/templates/console-rbac.yaml`) — pas
de compte de service partagé avec `confidential-manager`, pas de dépendance à un kubeconfig
personnel.

```bash
kubectl -n <namespace> port-forward svc/<release>-ai-confidential-operator-console 8090:8090
# → http://localhost:8090
```

La console lit le schéma OpenAPI de chaque CRD directement depuis le cluster et génère un
formulaire à partir de ce schéma — un bouton **« Voir en YAML »** reste disponible à tout
moment. Rappel utile : `RawAttestationReport`, `AttestationEvidence` et `AIPlacementDecision`
sont normalement produites automatiquement par la plateforme (voir
[Les 7 CRDs](#les-7-crds-expliquées-simplement)) — la console permet de les consulter, mais
les créer/modifier à la main n'a de sens qu'en dev/debug. Désactivable via
`--set console.enabled=false`.

### En développement local (sans passer par le chart)

`go run ./cmd/console-api` détecte automatiquement s'il tourne hors cluster et se rabat sur
ton kubeconfig local (`--kubeconfig`/`--context`/`--addr=:9090` pour surcharger) — même
binaire, seule la source des identifiants change.

### Avec le cluster kind de démo

Le [Démarrage rapide (kind)](#démarrage-rapide-kind) (`cd automatisation && ./up.sh`)
construit aussi l'image de la console et l'installe via le chart — elle est donc déjà là,
dans le cluster, une fois le script terminé.

**Validé de bout en bout** de cette façon : cluster kind réel, `confidential-manager` réel qui
réconcilie et bootstrappe les runtime classes simulées, pod `console-api` réel dans le
cluster connecté via son propre ServiceAccount — pas un processus local, pas seulement
contre envtest.

## Configuration

Variables les plus utiles (liste complète par binaire dans [`docs/`](docs/) et le code de
chaque `cmd/*/main.go`) :

| Variable | Binaire | Rôle |
|---|---|---|
| `AIOPS_PLATFORM_MODE` | manager | `simulated-kind` (défaut) pour le dev, `production`/`aks*` pour du matériel réel. |
| `SCHEDULER_SIGNING_KEY_HEX` | scheduler | Clé de signature Ed25519 — **à fixer explicitement en production**, sinon clé jetable générée au démarrage. |
| `TOKEN_PUBLIC_KEY_HEX` | key-release-gateway | Clé publique pour vérifier les jetons — sans elle, les signatures ne sont **pas** vérifiées. |
| `EXPECTED_TEE` | central-verifier | Type d'attestation attendu (`sevsnpvm` par défaut). |
| `REPORT_INTERVAL_SECONDS` | node-attestation-agent | Fréquence d'émission des rapports (60s par défaut). |

## Métriques Prometheus

| Métrique | Rôle |
|---|---|
| `ai_simulated_runtimeclass_in_use` | Signale qu'un pod tourne en mode simulé — jamais silencieux. |
| `ai_key_release_requests_total` | Nombre de demandes de clé, par issue (`allowed`/`denied`). |
| `ai_key_release_latency_seconds` | Latence de la décision de libération de clé. |

`attestation-scheduler` et `central-verifier` exposent aussi les métriques standard de
reconciliation de controller-runtime.

## Modèle de sécurité

- Un agent de nœud compromis ne peut mentir que dans son propre rapport brut — il n'a jamais
  le droit RBAC d'écrire une évidence.
- La validation des pods est fail-closed (bloque en cas de doute), la mutation est fail-open
  (ne bloque jamais un pod par indisponibilité du webhook) — un choix délibéré, pas un oubli.
- Toute décision de placement est revérifiée une deuxième fois juste avant d'être exécutée.
- Rien n'est silencieux : mode simulé, clé de signature manquante, ou vérification de jeton
  désactivée déclenchent tous un avertissement explicite au démarrage ou un marquage visible
  sur l'objet concerné.
- Aucune dépendance d'exécution vers `ai-finops-operator` ou `ai-govar-operator` — cet
  opérateur fonctionne seul.

## Référence technique avancée

Cette section détaille l'algorithme exact pour qui doit l'auditer ou le déboguer en
profondeur — pas nécessaire pour une utilisation normale.

<details>
<summary><strong>Règle exacte de libération de clé</strong> (<code>internal/keyrelease/keyrelease.go</code>)</summary>

Évaluée dans cet ordre, la première condition qui matche l'emporte :

1. `policyRequired == false` → **allow** immédiat.
2. `policyTTLSeconds <= 0` → **deny** (`TTL_INVALID`).
3. Révocation active → **deny** (`REVOCATION_ACTIVE`).
4. Évidence révoquée → **deny** (`EVIDENCE_REVOKED`).
5. Évidence non vérifiée → **deny** (`EVIDENCE_NOT_VERIFIED`).
6. Évidence trop vieille → **deny** (`EVIDENCE_EXPIRED`).
7. Jeton de placement fourni mais invalide/expiré/ne correspondant pas exactement au pod,
   à l'image, au modèle ou à la politique → **deny** avec le code précis (`TOKEN_EXPIRED`,
   `POD_UID_MISMATCH`, `MODEL_DIGEST_MISMATCH`, `IMAGE_DIGEST_MISMATCH`,
   `POLICY_HASH_MISMATCH`, `TOKEN_INVALID`).
8. Audit requis mais aucune preuve fournie → **deny** (`AUDIT_REQUIRED_NOT_MET`).
9. Sinon → **allow**.

**Nuance importante** : le contrôleur `AIKeyReleasePolicyReconciler` (celui qui met à jour
`status.lastDecision` sur le CRD) n'alimente que 4 des signaux ci-dessus (policy, TTL,
évidence vérifiée/révoquée). La vérification complète du jeton et des digests n'a lieu que
lors d'un appel réel à `key-release-gateway` (`POST /v1/key-release`) — le status du CRD est
donc une vérification partielle, la décision opposable se fait au moment de l'appel HTTP.

</details>

<details>
<summary><strong>Algorithme du scheduler d'attestation</strong> — schéma complet et code source</summary>

Le schéma détaillé des 6 étapes (PreFilter → Filter → Permit → Score → Reserve/PreBind → Bind)
est dans [Le scheduling d'un pod confidentiel, en détail](#le-scheduling-dun-pod-confidentiel-en-détail)
ci-dessus. Implémentation exacte : `internal/scheduler/scheduler.go` (`SchedulePod`,
`filter`, `score`, `reserveTimed`, `preBind`).

</details>

<details>
<summary><strong>Webhooks pods : ce qu'ils font exactement</strong> (<code>internal/webhook/podinjector</code>)</summary>

- `/mutate-v1-pod` (fail-open) : pose des annotations de traçabilité, applique la runtime
  class attendue si absente, force le scheduler d'attestation, ajoute une scheduling gate tant
  qu'aucune évidence n'est déjà attachée au pod. **Ce même point d'entrée héberge aussi**, de
  façon totalement indépendante de l'attestation, une fonctionnalité générique d'injection de
  sidecar proxy pilotée par annotations — sans lien avec la confidentialité, à ne pas confondre.
- `/validate-v1-pod` (fail-closed) : rejette un pod si l'image n'est pas pinée par digest quand
  requis, si la runtime class n'est pas autorisée, si un GPU confidentiel est demandé (non
  implémenté — toujours refusé explicitement), ou si une runtime class simulée est utilisée en
  mode production.

Les deux excluent par construction les namespaces système et celui de l'opérateur lui-même.

</details>

## Dépannage

- **Pod bloqué en `Pending` avec une scheduling gate** : vérifiez que la chaîne
  `RawAttestationReport → AttestationEvidence` a bien tourné (`kubectl get aevid -o wide`) et
  que `schedulerName: ai-attestation-scheduler` est bien posé sur le pod.
- **`AIPlacementDecision` reste `pending`/`deny` sans jeton** : la revérification juste avant le
  bind a probablement échoué — regardez les logs `attestation-scheduler` (`prebind: ...`).
- **`key-release-gateway` répond `TOKEN_INVALID`** : `TOKEN_PUBLIC_KEY_HEX` sur la gateway ne
  correspond pas à la clé utilisée par `attestation-scheduler`.
- **Un pod non conforme n'est pas rejeté** : vérifiez `enforcementMode` — seul `enforce` bloque
  réellement, `warn`/`audit` se contentent d'observer.
- **Runtime class simulée refusée** : normal en mode production — c'est volontaire.

## Contribuer

Les contributions sont bienvenues : ouvrez une issue avant une PR conséquente, gardez les
commits atomiques, et vérifiez que `go build ./...`, `go vet ./...` et `go test ./...` passent.

## License

[Apache License 2.0](LICENSE).
