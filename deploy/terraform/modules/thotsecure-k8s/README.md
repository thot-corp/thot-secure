# Module Terraform `thotsecure-k8s`

Déploie **Thot Secure** (SOAR/CSPM 100 % défensif, Apache-2.0, v0.1.0) sur un cluster
Kubernetes générique (AWS EKS, Azure AKS, k3s, ...) :

- **namespace** dédié, étiqueté (`app.kubernetes.io/*`) et verrouillé en
  Pod Security Admission `restricted` ;
- **coquille de Secret optionnelle** — jamais de valeur secrète dans Terraform ;
- **release Helm** du chart local `deploy/helm/thotsecure`, durcie par défaut :
  l'image `ghcr.io/thot-corp/thot-secure:0.1.0` tourne en utilisateur non-root
  **UID/GID 10001**, avec `readOnlyRootFilesystem: true`, `tmpfs` sur `/tmp`,
  `capabilities.drop: ["ALL"]`, `allowPrivilegeEscalation: false` et
  `seccompProfile: RuntimeDefault`. Jamais `privileged`, jamais `hostNetwork`,
  jamais de socket Docker monté, jamais de capability ajoutée ;
- **persistance** de `/var/lib/thotsecure` (base SQLite + quarantaine) via un PVC ;
- **configuration en lecture seule** montée depuis un ConfigMap sur
  `/etc/thotsecure/{rules,policies,playbooks,targets.yaml}` ;
- exposition optionnelle de la **console web** (`/`) par Ingress, avec HTTPS forcé
  par défaut.

> ## ⚠️ AVERTISSEMENT DE SÛRETÉ
>
> - `dry_run = true` et `autonomy = "supervised"` sont les **valeurs par défaut**
>   de ce module, et doivent le rester. **AVERTISSEMENT : désactiver le dry-run
>   autorise des actions réelles sur des cibles de production.**
> - `autonomy = "auto"` supprime la validation humaine. Ne l'activez jamais par
>   défaut : un déploiement ne doit jamais activer l'automatisation destructive
>   sans procédure de validation humaine documentée.
> - Aucun secret en clair : la clé d'application est lue dans un Secret Kubernetes
>   **préexistant** (`set_sensitive`) ou fournie par un gestionnaire de secrets
>   externe. Le state Terraform contient la valeur lue : utilisez **impérativement**
>   un backend chiffré (`encrypt = true`) et des droits d'accès restreints.

## Prérequis

1. Terraform >= 1.5.0 et providers `hashicorp/kubernetes` ~> 2.27, `hashicorp/helm` ~> 2.12.
2. Un cluster Kubernetes joignable (kubeconfig ou provider configuré par l'appelant).
3. Le chart Helm local [`deploy/helm/thotsecure`](../../../helm/thotsecure) (fourni via `chart_path`).
4. Le **Secret d'application créé hors bande avant le premier `terraform apply`**
   (voir « Consommation du secret » ci-dessous).
5. Un ConfigMap de configuration contenant `targets.yaml`, `rules/`, `policies/`,
   `playbooks/` — monté en lecture seule sur `/etc/thotsecure`.

## Exemple d'appel

```hcl
module "thotsecure_k8s" {
  source = "../../modules/thotsecure-k8s"

  namespace = "thotsecure"

  # Chart local : chemin résolu depuis le répertoire du module racine appelant.
  chart_path = "../../../helm/thotsecure"

  image_repository = "ghcr.io/thot-corp/thot-secure"
  image_tag        = "0.1.0"

  # Garde-fous de sûreté : ne pas modifier sans procédure de validation humaine.
  dry_run  = true
  autonomy = "supervised"

  # Secret créé hors bande par un gestionnaire de secrets (jamais de valeur ici).
  existing_secret_name = "thotsecure-secrets"

  environment = "prod"
  replica_count = 1

  persistence_enabled = true
  persistence_size    = "10Gi"

  ingress_enabled     = true
  ingress_host        = "thotsecure.example.com"
  ingress_class_name  = "nginx"
  ingress_annotations = { "cert-manager.io/cluster-issuer" = "letsencrypt-prod" }
  tls_enabled         = true
  app_tls_enabled     = false

  labels = {
    Project     = "Thot Secure"
    Environment = "prod"
    ManagedBy   = "terraform"
    Owner       = "security-team"
    Compliance  = "defensive-security"
  }
}
```

## Inputs

| Nom | Type | Défaut | Description |
| --- | --- | --- | --- |
| `namespace` | `string` | `"thotsecure"` | Namespace Kubernetes de destination (DNS-1123). |
| `create_namespace` | `bool` | `true` | Créer le namespace (labels standards + PSA `restricted`). |
| `release_name` | `string` | `"thotsecure"` | Nom de la release Helm (sert aussi de nom de Service/Deployment). |
| `chart_path` | `string` | — | Chemin **local** vers `deploy/helm/thotsecure` (résolu depuis le module racine). |
| `image_repository` | `string` | `"ghcr.io/thot-corp/thot-secure"` | Dépôt de l'image conteneur. |
| `image_tag` | `string` | `"0.1.0"` | Tag d'image (préférer un tag immuable). |
| `image_pull_policy` | `string` | `"IfNotPresent"` | `Always`, `IfNotPresent` ou `Never`. |
| `replica_count` | `number` | `1` | Nombre de réplicas (>= 1 ; > 1 incompatible avec SQLite RWO + bus `memory`). |
| `dry_run` | `bool` | `true` | **AVERTISSEMENT : désactiver le dry-run autorise des actions réelles sur des cibles de production.** |
| `autonomy` | `string` | `"supervised"` | `manual`, `supervised` ou `auto`. **AVERTISSEMENT : `auto` exécute des actions sans validation humaine.** |
| `existing_secret_name` | `string` | — | **Obligatoire.** Secret préexistant contenant `THOT_SECRET_KEY` (jamais la valeur). |
| `secret_key_env_var` | `string` | `"THOT_SECRET_KEY"` | Attribut du Secret portant la clé d'application. |
| `create_secret_shell` | `bool` | `false` | Créer une coquille de Secret **vide** à peupler hors bande (aucune valeur dans Terraform). |
| `bus_mode` | `string` | `"memory"` | `THOT_BUS` : `memory`, `sqlite` ou `nats`. |
| `nats_url` | `string` | `""` | `THOT_NATS_URL` ; vide = défaut applicatif `nats://127.0.0.1:4222`. |
| `nats_embedded` | `bool` | `false` | NATS embarqué (sidecar `nats:2.10-alpine` sur `127.0.0.1:4222`). |
| `persistence_enabled` | `bool` | `true` | PVC pour `/var/lib/thotsecure` (SQLite + quarantaine). |
| `persistence_size` | `string` | `"10Gi"` | Taille du volume (format Kubernetes). |
| `storage_class_name` | `string` | `""` | StorageClass du PVC ; vide = StorageClass par défaut. |
| `db_url` | `string` | `""` | `THOT_DB_URL` ; vide = valeur déduite (volume persistant ou défaut applicatif). |
| `retention_days` | `number` | `30` | `THOT_RETENTION_DAYS` (>= 1). |
| `resource_requests` | `map(string)` | `{cpu="100m", memory="256Mi"}` | Requêtes CPU/mémoire. |
| `resource_limits` | `map(string)` | `{cpu="1000m", memory="1Gi"}` | Limites CPU/mémoire. |
| `ingress_enabled` | `bool` | `false` | Exposer la console web par Ingress. |
| `ingress_class_name` | `string` | `"nginx"` | IngressClass utilisée. |
| `ingress_host` | `string` | `""` | Nom d'hôte (obligatoire si `ingress_enabled = true`). |
| `ingress_annotations` | `map(string)` | `{}` | Annotations d'Ingress (ex. `cert-manager.io/cluster-issuer`). |
| `ingress_tls_secret_name` | `string` | `""` | Secret TLS fourni par cert-manager ou hors bande. |
| `tls_enabled` | `bool` | `true` | TLS au bord (Ingress) + redirection HTTPS. |
| `app_tls_enabled` | `bool` | `false` | `THOT_TLS_ENABLED` (TLS terminé par l'application ; sondes à basculer en HTTPS). |
| `service_monitor_enabled` | `bool` | `false` | ServiceMonitor Prometheus pour `/metrics`. |
| `network_policy_enabled` | `bool` | `true` | NetworkPolicy rendue par le chart (voir module [`network`](../network)). |
| `pod_security_context` | `object` | durci (UID/GID 10001, seccomp `RuntimeDefault`) | Contexte de sécurité du Pod — verrouillé par validation. |
| `container_security_context` | `object` | durci (`drop=["ALL"]`, rootfs RO) | Contexte de sécurité du conteneur — verrouillé par validation. |
| `labels` | `map(string)` | `{}` | Libellés/tags de gouvernance additionnels. |
| `environment` | `string` | `"prod"` | `THOT_ENV` : `dev` ou `prod`. |
| `log_level` | `string` | `"INFO"` | `THOT_LOG_LEVEL`. |
| `log_format` | `string` | `"json"` | `THOT_LOG_FORMAT` : `json` ou `console`. |
| `rate_limit_per_min` | `number` | `600` | `THOT_RATE_LIMIT_PER_MIN`. |
| `opa_bin` | `string` | `""` | `THOT_OPA_BIN` ; vide = évaluation interne. |
| `helm_timeout_seconds` | `number` | `600` | Délai Helm (>= 30 s). |
| `helm_atomic` | `bool` | `true` | Installation atomique (rollback en cas d'échec). |
| `extra_values` | `map(any)` | `{}` | Valeurs Helm additionnelles (fusion **superficielle** ; ne peut pas contredire `dry_run`/`autonomy`). |

## Outputs

| Nom | Sensible | Description |
| --- | --- | --- |
| `namespace` | non | Namespace de déploiement. |
| `release_name` | non | Nom de la release Helm. |
| `release_version` | non | Version du chart déployée. |
| `service_name` | non | Nom du Service Thot Secure. |
| `service_port` | non | Port applicatif (`8080`). |
| `dry_run` | non | État du garde-fou dry-run. |
| `autonomy` | non | Niveau d'autonomie appliqué. |
| `helm_manifest_summary` | **oui** | Manifeste rendu (peut contenir des valeurs d'environnement sensibles). |
| `persistence_claim_name` | non | Nom du PVC de `/var/lib/thotsecure` (vide si persistance désactivée). |
| `internal_url` | non | `http://thotsecure.<namespace>.svc.cluster.local:8080`. |
| `next_steps` | non | Commandes `kubectl`/`curl` de vérification post-déploiement. |

## Consommation du secret (décision d'implémentation)

Le module ne crée **jamais** de valeur secrète. Deux modes :

1. **Mode par défaut (`create_secret_shell = false`), recommandé.**
   Le Secret `<existing_secret_name>` doit exister **avant le plan** : il est lu par
   un `data "kubernetes_secret_v1"`, la clé `THOT_SECRET_KEY` (et, si présente,
   `THOT_BOOTSTRAP_API_KEY`) est injectée dans la release via
   `set_sensitive`. Une `precondition` échoue avec un message explicite si la clé
   est absente. Conséquence : le Secret doit être créé hors bande, puis un premier
   `terraform apply` peut être exécuté.
2. **Mode gestionnaire de secrets externe (`create_secret_shell = true`).**
   Terraform crée une coquille de Secret **vide** (`data = {}`,
   `ignore_changes = [data]`) que votre gestionnaire de secrets
   (External Secrets Operator, Vault Agent Injector, SOPS + job de synchronisation,
   ...) vient peupler hors bande. Aucune valeur n'entre jamais dans le state ; en
   contrepartie le module n'injecte pas la clé via `set_sensitive` et c'est à votre
   chart / gestionnaire de fournir la clé au conteneur (par exemple via une
   surcharge `extra_values`).

Création hors bande de référence (la valeur ne doit jamais être écrite dans un
fichier du dépôt) :

```sh
kubectl --namespace thotsecure create secret generic thotsecure-secrets \
  --from-literal=THOT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
```

Le module [`secrets`](../secrets) permet de générer cette clé avec Terraform pour
les environnements clos ; lisez son README (procédure d'application en deux phases).

## Flux réseau attendus

Le module `network_policy_enabled` n'active que la politique rendue par le chart.
Pour un modèle de flux explicite (deny-all + DNS + ingress controller + NATS +
cibles supervisées + scrape Prometheus), utilisez le module
[`network`](../network), qui crée les `kubernetes_network_policy_v1` dédiées.

## Vérification après déploiement

```sh
kubectl --namespace thotsecure get pods -l app.kubernetes.io/name=thotsecure
kubectl --namespace thotsecure port-forward svc/thotsecure 8080:8080
curl -fsS http://127.0.0.1:8080/healthz   # liveness
curl -fsS http://127.0.0.1:8080/readyz    # readiness (503 si dépendance KO)
curl -fsS http://127.0.0.1:8080/metrics | head
```

Rappel : `dry_run = true` et `autonomy = "supervised"` sont les défauts sûrs ;
toute désactivation en production exige une procédure de validation humaine
documentée.
