# ---------------------------------------------------------------------------
# Variables du module « thotsecure-k8s ».
#
# IMPÉRATIF DE SÛRETÉ — les valeurs par défaut de ce module sont volontairement
# les valeurs sûres :
#   * dry_run  = true         : aucune action réelle n'est exécutée sur les cibles.
#   * autonomy = "supervised" : toute action reste soumise à une validation humaine.
#
# Thot Secure est un SOAR/CSPM 100 % défensif : un déploiement ne doit JAMAIS
# activer l'automatisation destructive par défaut. Ne désactivez ces garde-fous
# qu'après une procédure de validation humaine documentée.
# ---------------------------------------------------------------------------

variable "namespace" {
  description = "Namespace Kubernetes dans lequel déployer Thot Secure."
  type        = string
  default     = "thotsecure"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace doit être un nom DNS-1123 valide (minuscules, chiffres et tirets uniquement)."
  }
}

variable "create_namespace" {
  description = "Créer le namespace via Terraform (avec les libellés standards et pod-security.kubernetes.io/enforce=restricted). Mettre à false si le namespace est déjà géré ailleurs ; le chart Helm est de toute façon installé avec create_namespace = false."
  type        = bool
  default     = true
}

variable "release_name" {
  description = "Nom de la release Helm (sert aussi de nom de Service et de Deployment par convention du chart)."
  type        = string
  default     = "thotsecure"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.release_name))
    error_message = "release_name doit être un nom DNS-1123 valide (minuscules, chiffres et tirets uniquement)."
  }
}

variable "chart_path" {
  description = "Chemin LOCAL vers le chart Helm Thot Secure, typiquement \"deploy/helm/thotsecure\". Le chemin est résolu depuis le répertoire de travail du module racine (pas depuis ce module) : les exemples fournis passent un chemin relatif à leur propre répertoire."
  type        = string

  validation {
    condition     = length(trimspace(var.chart_path)) > 0
    error_message = "chart_path est obligatoire : indiquez le chemin local vers le chart deploy/helm/thotsecure."
  }
}

variable "image_repository" {
  description = "Dépôt de l'image conteneur Thot Secure."
  type        = string
  default     = "ghcr.io/thotsecure/thot-secure"

  validation {
    condition     = length(trimspace(var.image_repository)) > 0
    error_message = "image_repository ne peut pas être vide."
  }
}

variable "image_tag" {
  description = "Tag de l'image conteneur Thot Secure. Préférez un tag immuable (version) à « latest »."
  type        = string
  default     = "0.1.0"
}

variable "image_pull_policy" {
  description = "Politique de récupération de l'image (Always, IfNotPresent ou Never)."
  type        = string
  default     = "IfNotPresent"

  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image_pull_policy)
    error_message = "image_pull_policy doit valoir Always, IfNotPresent ou Never."
  }
}

variable "replica_count" {
  description = "Nombre de réplicas du Deployment Thot Secure."
  type        = number
  default     = 1

  validation {
    condition     = var.replica_count >= 1
    error_message = "replica_count doit être supérieur ou égal à 1."
  }

  validation {
    condition     = !(var.persistence_enabled && var.bus_mode == "memory" && var.replica_count > 1)
    error_message = "replica_count > 1 est incohérent avec persistence_enabled = true et bus_mode = \"memory\" : la base SQLite vit sur un volume ReadWriteOnce qui ne peut pas être partagé par plusieurs réplicas. Passez à bus_mode = \"nats\" ou revenez à 1 réplica."
  }
}

variable "dry_run" {
  description = "AVERTISSEMENT : désactiver le dry-run autorise des actions réelles sur des cibles de production. Valeur injectée dans THOT_DRY_RUN et dans le chart (dryRun). Défaut sûr : true (aucune action n'est réellement exécutée)."
  type        = bool
  default     = true
}

variable "autonomy" {
  description = "AVERTISSEMENT : autonomy = \"auto\" autorise l'exécution d'actions sans validation humaine ; à ne jamais activer par défaut en production. Défaut sûr : \"supervised\" (toute action attend une approbation). Valeurs : manual, supervised, auto."
  type        = string
  default     = "supervised"

  validation {
    condition     = contains(["manual", "supervised", "auto"], var.autonomy)
    error_message = "autonomy doit valoir manual, supervised ou auto. Le défaut sûr est supervised."
  }
}

variable "existing_secret_name" {
  description = "Nom du Secret Kubernetes EXISTANT qui contient la clé d'application (attribut attendu : THOT_SECRET_KEY, personnalisable via secret_key_env_var). Le Secret doit être créé HORS BANDE — gestionnaire de secrets, External Secrets Operator, ou module ../../secrets — AVANT le premier terraform apply, car ce module le lit via un data source au moment du plan. Aucune valeur secrète n'est écrite dans ce module."
  type        = string

  validation {
    condition     = length(trimspace(var.existing_secret_name)) > 0
    error_message = "existing_secret_name est obligatoire : créez le Secret hors bande avant d'appeler ce module."
  }
}

variable "secret_key_env_var" {
  description = "Clé (attribut du Secret) qui porte la clé d'application, injectée dans le conteneur sous forme de variable d'environnement THOT_SECRET_KEY via helm set_sensitive."
  type        = string
  default     = "THOT_SECRET_KEY"

  validation {
    condition     = can(regex("^[A-Z][A-Z0-9_]*$", var.secret_key_env_var))
    error_message = "secret_key_env_var doit être un nom de variable d'environnement en majuscules (A-Z, 0-9, _)."
  }
}

variable "create_secret_shell" {
  description = <<-EOT
    Mode « gestionnaire de secrets externe ». Si true, Terraform crée une coquille de Secret VIDE
    (type Opaque, aucune donnée) portant le nom existing_secret_name, que votre gestionnaire de
    secrets viendra peupler hors bande (External Secrets Operator, Vault Agent Injector, SOPS + job
    de synchronisation, ...). Terraform ne contient alors AUCUNE valeur secrète et n'injecte pas la
    clé via set_sensitive : c'est au chart / à votre gestionnaire de fournir la clé au conteneur.
    Si false (défaut, recommandé), le Secret doit déjà exister avec sa clé et le module l'injecte
    via helm set_sensitive.
  EOT
  type        = bool
  default     = false
}

variable "bus_mode" {
  description = "Backend du bus d'événements Thot Secure (THOT_BUS). « memory » convient à un réplica unique ; « sqlite » persiste les messages localement ; « nats » est requis pour un déploiement multi-réplica."
  type        = string
  default     = "memory"

  validation {
    condition     = contains(["memory", "sqlite", "nats"], var.bus_mode)
    error_message = "bus_mode doit valoir memory, sqlite ou nats."
  }
}

variable "nats_url" {
  description = "URL du serveur NATS (THOT_NATS_URL) utilisée lorsque bus_mode = \"nats\". Vide = valeur par défaut applicative nats://127.0.0.1:4222 (à réserver au mode embarqué)."
  type        = string
  default     = ""

  validation {
    condition     = var.bus_mode != "nats" || var.nats_embedded || length(trimspace(var.nats_url)) > 0
    error_message = "nats_url doit être renseigné lorsque bus_mode = \"nats\" et que nats_embedded = false (par exemple nats://thotsecure-nats.<namespace>.svc.cluster.local:4222)."
  }
}

variable "nats_embedded" {
  description = "Déployer/consommer NATS en mode embarqué dans le pod Thot Secure (nats:2.10-alpine en sidecar, écoute sur 127.0.0.1:4222). Laisser false pour utiliser un service NATS dédié."
  type        = bool
  default     = false
}

variable "persistence_enabled" {
  description = "Activer la persistance de /var/lib/thotsecure (base SQLite + quarantaine) via un PersistentVolumeClaim. Laisser true en production : sans persistance, l'historique et la quarantaine sont perdus à chaque redémarrage."
  type        = bool
  default     = true
}

variable "persistence_size" {
  description = "Taille du volume de persistance (format Kubernetes, ex. 10Gi)."
  type        = string
  default     = "10Gi"

  validation {
    condition     = can(regex("^[0-9]+(Mi|Gi|Ti)$", var.persistence_size))
    error_message = "persistence_size doit être une quantité de stockage Kubernetes de la forme 512Mi, 10Gi ou 1Ti."
  }
}

variable "storage_class_name" {
  description = "StorageClass utilisée par le PersistentVolumeClaim de /var/lib/thotsecure. Vide = StorageClass par défaut du cluster. Les exemples fournis créent une StorageClass chiffrée (EBS gp3 chiffré côté AWS, disque managé côté Azure, local-path côté k3s)."
  type        = string
  default     = ""
}

variable "db_url" {
  description = "Valeur injectée dans THOT_DB_URL. Vide = valeur déduite : sqlite:////var/lib/thotsecure/thotsecure.db quand persistence_enabled = true, sinon la valeur par défaut applicative sqlite:///./data/thotsecure.db (stockage éphémère). Renseignez-la explicitement si l'analyse d'URL de votre version d'Thot Secure attend une autre forme."
  type        = string
  default     = ""
}

variable "retention_days" {
  description = "Durée de rétention des données Thot Secure en jours (THOT_RETENTION_DAYS)."
  type        = number
  default     = 30

  validation {
    condition     = var.retention_days >= 1
    error_message = "retention_days doit être supérieur ou égal à 1."
  }
}

variable "resource_requests" {
  description = "Requêtes de ressources du conteneur (clés cpu / memory, format Kubernetes)."
  type        = map(string)
  default = {
    cpu    = "100m"
    memory = "256Mi"
  }
}

variable "resource_limits" {
  description = "Limites de ressources du conteneur (clés cpu / memory, format Kubernetes)."
  type        = map(string)
  default = {
    cpu    = "1000m"
    memory = "1Gi"
  }
}

variable "ingress_enabled" {
  description = "Exposer la console web Thot Secure (/) via un Ingress."
  type        = bool
  default     = false
}

variable "ingress_class_name" {
  description = "IngressClass à utiliser lorsque ingress_enabled = true (ex. nginx, alb, traefik)."
  type        = string
  default     = "nginx"
}

variable "ingress_host" {
  description = "Nom d'hôte de l'Ingress (obligatoire lorsque ingress_enabled = true)."
  type        = string
  default     = ""

  validation {
    condition     = !var.ingress_enabled || length(trimspace(var.ingress_host)) > 0
    error_message = "ingress_host doit être renseigné lorsque ingress_enabled = true."
  }
}

variable "ingress_annotations" {
  description = "Annotations additionnelles de l'Ingress (par exemple {\"cert-manager.io/cluster-issuer\" = \"letsencrypt-prod\"} pour activer TLS via cert-manager)."
  type        = map(string)
  default     = {}
}

variable "ingress_tls_secret_name" {
  description = "Nom du Secret TLS utilisé par l'Ingress. Le Secret est fourni par cert-manager ou créé hors bande : ce module ne crée jamais de matériel de clé privée."
  type        = string
  default     = ""
}

variable "tls_enabled" {
  description = "Forcer HTTPS côté application et redirection HTTPS côté Ingress (THOT_TLS_ENABLED). Laisser true dès que l'instance est exposée hors du cluster."
  type        = bool
  default     = true
}

variable "app_tls_enabled" {
  description = "Activer TLS au niveau de l'APPLICATION (THOT_TLS_ENABLED). Laisser false (défaut sûr) lorsque TLS est terminé à l'Ingress : le conteneur continue de servir du HTTP sur 8080 et les sondes /healthz et /readyz restent en HTTP. Passer à true uniquement si Thot Secure doit terminer TLS lui-même, auquel cas les sondes du chart doivent être basculées en HTTPS."
  type        = bool
  default     = false
}

variable "service_monitor_enabled" {
  description = "Créer un ServiceMonitor Prometheus pour /metrics (nécessite l'opérateur Prometheus dans le cluster)."
  type        = bool
  default     = false
}

variable "network_policy_enabled" {
  description = "Activer le NetworkPolicy deny-all rendu par le chart (le module ../../network fournit un jeu de politiques plus complet et explicite)."
  type        = bool
  default     = true
}

variable "pod_security_context" {
  description = "Contexte de sécurité du Pod. Durci par défaut : non-root, UID/GID 10001 (utilisateur de l'image Thot Secure), fsGroup 10001, seccomp RuntimeDefault. Ces valeurs ne doivent pas être assouplies."
  type = object({
    run_as_non_root        = optional(bool, true)
    run_as_user            = optional(number, 10001)
    run_as_group           = optional(number, 10001)
    fs_group               = optional(number, 10001)
    fs_group_change_policy = optional(string, "OnRootMismatch")
    seccomp_profile_type   = optional(string, "RuntimeDefault")
  })
  default = {}

  validation {
    condition     = var.pod_security_context.run_as_non_root
    error_message = "run_as_non_root doit rester true : l'image Thot Secure s'exécute en utilisateur non-root 10001."
  }

  validation {
    condition     = var.pod_security_context.run_as_user == 10001 && var.pod_security_context.run_as_group == 10001 && var.pod_security_context.fs_group == 10001
    error_message = "run_as_user, run_as_group et fs_group doivent rester 10001 pour correspondre à l'utilisateur non-root de l'image Thot Secure."
  }

  validation {
    condition     = contains(["RuntimeDefault", "Localhost"], var.pod_security_context.seccomp_profile_type)
    error_message = "seccomp_profile_type doit valoir RuntimeDefault (recommandé) ou Localhost."
  }
}

variable "container_security_context" {
  description = "Contexte de sécurité du conteneur. Durci et verrouillé par validation : jamais privileged, jamais d'escalade de privilèges, rootfs en lecture seule, capabilities ajoutées interdites et drop = [\"ALL\"]."
  type = object({
    allow_privilege_escalation = optional(bool, false)
    privileged                 = optional(bool, false)
    read_only_root_filesystem  = optional(bool, true)
    run_as_non_root            = optional(bool, true)
    run_as_user                = optional(number, 10001)
    run_as_group               = optional(number, 10001)
    capabilities_drop          = optional(list(string), ["ALL"])
    capabilities_add           = optional(list(string), [])
    seccomp_profile_type       = optional(string, "RuntimeDefault")
  })
  default = {}

  validation {
    condition = (
      var.container_security_context.privileged == false &&
      var.container_security_context.allow_privilege_escalation == false &&
      var.container_security_context.read_only_root_filesystem &&
      var.container_security_context.run_as_non_root &&
      length(var.container_security_context.capabilities_add) == 0 &&
      contains(var.container_security_context.capabilities_drop, "ALL")
    )
    error_message = "Le conteneur Thot Secure doit rester durci : privileged = false, allow_privilege_escalation = false, read_only_root_filesystem = true, run_as_non_root = true, capabilities_add vide et capabilities_drop contenant ALL."
  }

  validation {
    condition     = contains(["RuntimeDefault", "Localhost"], var.container_security_context.seccomp_profile_type)
    error_message = "seccomp_profile_type doit valoir RuntimeDefault (recommandé) ou Localhost."
  }
}

variable "labels" {
  description = "Libellés additionnels appliqués au namespace et transmis à la release Helm (par exemple les tags de gouvernance : Project, Environment, ManagedBy, Owner, Compliance)."
  type        = map(string)
  default     = {}
}

variable "environment" {
  description = "Environnement applicatif Thot Secure (THOT_ENV) : dev ou prod."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment doit valoir dev ou prod."
  }
}

variable "log_level" {
  description = "Niveau de journalisation (THOT_LOG_LEVEL)."
  type        = string
  default     = "INFO"

  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], upper(var.log_level))
    error_message = "log_level doit valoir DEBUG, INFO, WARNING, ERROR ou CRITICAL."
  }
}

variable "log_format" {
  description = "Format des journaux (THOT_LOG_FORMAT) : json (recommandé, ingestion SIEM) ou console."
  type        = string
  default     = "json"

  validation {
    condition     = contains(["json", "console"], var.log_format)
    error_message = "log_format doit valoir json ou console."
  }
}

variable "rate_limit_per_min" {
  description = "Limite de requêtes par minute et par client côté API (THOT_RATE_LIMIT_PER_MIN)."
  type        = number
  default     = 600

  validation {
    condition     = var.rate_limit_per_min >= 1
    error_message = "rate_limit_per_min doit être supérieur ou égal à 1."
  }
}

variable "opa_bin" {
  description = "Chemin du binaire Open Policy Agent (THOT_OPA_BIN). Vide = évaluation de politiques interne (aucun binaire externe)."
  type        = string
  default     = ""
}

variable "helm_timeout_seconds" {
  description = "Délai maximal (secondes) accordé par Helm à l'installation/mise à jour de la release."
  type        = number
  default     = 600

  validation {
    condition     = var.helm_timeout_seconds >= 30
    error_message = "helm_timeout_seconds doit être supérieur ou égal à 30 secondes."
  }
}

variable "helm_atomic" {
  description = "Installer la release en mode atomique : en cas d'échec, Helm annule et restaure l'état précédent. Laisser true en production."
  type        = bool
  default     = true
}

variable "extra_values" {
  description = "Valeurs Helm additionnelles fusionnées à la RACINE des values calculées (fusion superficielle : une clé de premier niveau fournie ici REMPLACE intégralement la clé calculée par le module). Utilisez-la pour les réglages propres au chart ; ne l'utilisez pas pour contourner dry_run ou autonomy."
  type        = map(any)
  default     = {}

  validation {
    condition     = try(var.extra_values["dryRun"], var.dry_run) == var.dry_run && try(var.extra_values["autonomy"], var.autonomy) == var.autonomy
    error_message = "extra_values ne peut pas contredire dry_run ou autonomy : modifiez explicitement les variables dédiées et lisez leur AVERTISSEMENT de sûreté."
  }
}
