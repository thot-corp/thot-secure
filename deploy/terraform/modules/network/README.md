# Module Terraform `network`

Politiques réseau Kubernetes pour Thot Secure, selon le modèle **« tout est interdit
sauf explicitement autorisé »**.

Le module ne crée que des `kubernetes_network_policy_v1` : il est portable
(EKS, AKS, k3s) et **n'exige aucun provider cloud**. Les équivalents cloud
(Security Group AWS, NSG Azure) sont documentés dans `versions.tf` et rappelés par
la sortie `cloud_firewall_rule_documents`.

## Modèle de flux

| Politique | Type | Source / destination | Ports | Justification |
| --- | --- | --- | --- | --- |
| `thotsecure-default-deny` | Ingress + Egress | tout (podSelector vide) | — | Socle : rien n'est autorisé implicitement. |
| `thotsecure-allow-ingress-controller` | Ingress | pods de `ingress_namespace` étiquetés `ingress_pod_selector` | TCP 8080 | Publier la console web (`/`) et l'API, sondes `/healthz`, `/readyz`, `/metrics`. |
| `thotsecure-allow-dns-egress` | Egress | pods DNS de `dns_namespace` (`k8s-app=kube-dns`) | UDP 53, TCP 53 | Sans DNS, aucune cible ni service ne peut être résolu par nom. |
| `thotsecure-allow-nats-egress` | Egress | pods NATS de `nats_namespace` | TCP `nats_port` (4222) | Bus distribué `THOT_BUS=nats` (image `nats:2.10-alpine`). Inutile en mode embarqué. |
| `thotsecure-allow-targets-egress` | Egress | `managed_target_cidrs` | TCP `managed_target_ports` (443) | Périmètre d'action sur les cibles supervisées (collecte, réponse supervisée). |
| `thotsecure-allow-monitoring-scrape` | Ingress | `monitoring_namespace` | TCP 8080 | Scrape Prometheus de `/metrics`. |
| `thotsecure-allow-extra-ingress-cidrs` | Ingress | `extra_ingress_cidrs` (+ `0.0.0.0/0` si exception) | TCP 8080 | Accès direct depuis un réseau d'administration ou du CI. |

### Règles de conception respectées

- **Aucun `0.0.0.0/0`** : `managed_target_cidrs` et `extra_ingress_cidrs` refusent
  explicitement `0.0.0.0/0` par validation. La seule exception possible est le
  booléen `allow_public_ingress_any = true`, désactivé par défaut, commenté dans
  `main.tf` et signalé par la sortie `public_ingress_allowed`.
- **Source doublement contrainte** pour l'entrée applicative : namespace *et*
  étiquettes de pods (sémantique ET des `NetworkPolicy`).
- **Sortie DNS restreinte** aux pods DNS de `dns_namespace`. Si votre cluster
  utilise un cache DNS local aux nœuds (NodeLocal DNSCache, `169.254.25.10`),
  ajoutez le flux correspondant : le module ne l'autorise pas implicitement.
- **Sortie cibles bornée** aux CIDR et ports déclarés : un SOAR ne doit jamais
  pouvoir joindre arbitrairement l'Internet.
- Les pods Thot Secure sont durcis par ailleurs (UID/GID 10001, rootfs en lecture
  seule, `capabilities.drop: ["ALL"]`), ce qui rend inutile toute règle
  privilégiée.

> ## ⚠️ AVERTISSEMENT DE SÛRETÉ
>
> Ce module est **défensif** : il restreint les flux, il ne les élargit pas.
> `allow_public_ingress_any = true` expose Thot Secure à toute source, y compris
> Internet : **ne l'activez jamais en production** — préférez un Ingress avec
> authentification et TLS. Les garde-fous applicatifs `dry_run = true` et
> `autonomy = "supervised"` (défauts du module
> [`thotsecure-k8s`](../thotsecure-k8s)) doivent rester en place, et leur
> désactivation exige une procédure de validation humaine documentée.

## Prérequis

1. Terraform >= 1.5.0 et provider `hashicorp/kubernetes` ~> 2.27.
2. Un cluster dont le CNI **applique** les NetworkPolicy (Calico, Cilium, VPC CNI
   avec politique activée, Azure CNI, k3s avec le contrôleur par défaut). Un CNI
   qui ignore les NetworkPolicy annule tout le bénéfice de ce module.
3. Le namespace cible déjà créé (voir le module [`thotsecure-k8s`](../thotsecure-k8s)).
4. Pour un pare-feu cloud : les équivalents listés dans `versions.tf`
   (`configuration_aliases`), ou un report manuel depuis
   `cloud_firewall_rule_documents`.

## Exemple d'appel

```hcl
module "network" {
  source = "../../modules/network"

  namespace = module.thotsecure_k8s.namespace

  app_label_selector = "app.kubernetes.io/name=thotsecure"

  ingress_namespace    = "ingress-nginx"
  ingress_pod_selector = "app.kubernetes.io/name=ingress-nginx"

  dns_namespace    = "kube-system"
  dns_pod_selector = "k8s-app=kube-dns"

  nats_enabled   = false
  nats_namespace = "thotsecure"

  # Périmètre d'action borné : jamais 0.0.0.0/0.
  managed_target_cidrs = ["10.20.0.0/16", "10.30.0.0/16"]
  managed_target_ports = ["443"]

  monitoring_namespace   = "monitoring"
  metrics_scrape_enabled = true

  enable_default_deny = true

  # Accès direct depuis le réseau d'administration uniquement.
  extra_ingress_cidrs = ["10.0.10.0/24"]

  emit_cloud_firewall_documents = true

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
| `namespace` | `string` | — | Namespace des charges Thot Secure (obligatoire, doit exister). |
| `app_label_selector` | `string` | `"app.kubernetes.io/name=thotsecure"` | Sélecteur `clé=valeur` des pods Thot Secure. |
| `ingress_namespace` | `string` | `"ingress-nginx"` | Namespace de l'ingress controller. |
| `ingress_pod_selector` | `string` | `"app.kubernetes.io/name=ingress-nginx"` | Étiquettes des pods de l'ingress controller. |
| `dns_namespace` | `string` | `"kube-system"` | Namespace du résolveur DNS. |
| `dns_pod_selector` | `string` | `"k8s-app=kube-dns"` | Étiquettes des pods DNS. |
| `nats_enabled` | `bool` | `false` | Autoriser la sortie vers NATS. |
| `nats_namespace` | `string` | `"thotsecure"` | Namespace du service NATS. |
| `nats_pod_selector` | `string` | `"app.kubernetes.io/name=nats"` | Étiquettes des pods NATS. |
| `nats_port` | `number` | `4222` | Port TCP NATS. |
| `managed_target_cidrs` | `list(string)` | `[]` | CIDR des cibles supervisées (validation CIDR IPv4, `0.0.0.0/0` refusé). |
| `managed_target_ports` | `list(string)` | `["443"]` | Ports TCP autorisés vers les cibles. |
| `monitoring_namespace` | `string` | `"monitoring"` | Namespace autorisé à scraper `/metrics`. |
| `metrics_scrape_enabled` | `bool` | `true` | Créer la politique de scrape Prometheus. |
| `enable_default_deny` | `bool` | `true` | Créer la politique deny-all. |
| `extra_ingress_cidrs` | `list(string)` | `[]` | CIDR autorisés en entrée directe (validation CIDR, `0.0.0.0/0` refusé). |
| `allow_public_ingress_any` | `bool` | `false` | **AVERTISSEMENT** : seule exception possible à l'interdiction de `0.0.0.0/0`. |
| `emit_cloud_firewall_documents` | `bool` | `false` | Publier les règles cloud équivalentes (documentaire). |
| `labels` | `map(string)` | `{}` | Libellés appliqués aux politiques. |

## Outputs

| Nom | Description |
| --- | --- |
| `policy_names` | Liste des politiques créées. |
| `deny_all_policy_name` | Nom de la politique deny-all (vide si désactivée). |
| `app_pod_selector` | Carte d'étiquettes des pods Thot Secure ciblés. |
| `namespace` | Namespace concerné. |
| `managed_target_cidrs` | CIDR des cibles actuellement autorisés en sortie. |
| `public_ingress_allowed` | `true` si l'exception `0.0.0.0/0` est active (doit rester `false`). |
| `cloud_firewall_rule_documents` | Règles équivalentes à reporter côté pare-feu cloud. |

## Vérification

```sh
kubectl --namespace thotsecure get networkpolicy
kubectl --namespace thotsecure describe networkpolicy thotsecure-default-deny
```

En cas de doute sur l'atteignabilité : depuis un pod de test non autorisé, un
`curl` vers `http://thotsecure.thotsecure.svc.cluster.local:8080/healthz` doit expirer,
alors que depuis l'ingress controller ou après `kubectl port-forward` il doit
répondre.
