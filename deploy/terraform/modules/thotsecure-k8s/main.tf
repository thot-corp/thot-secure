# ---------------------------------------------------------------------------
# Thot Secure — module Terraform « thotsecure-k8s »
#
# Ce module déploie Thot Secure (SOAR/CSPM 100 % défensif) sur un cluster
# Kubernetes générique (EKS, AKS, k3s, ...) :
#   * namespace dédié, étiqueté et verrouillé en Pod Security Admission
#     « restricted » ;
#   * coquille de Secret optionnelle (jamais de valeur secrète dans Terraform) ;
#   * release Helm du chart local deploy/helm/thotsecure, durcie par défaut
#     (utilisateur 10001, rootfs en lecture seule, drop ALL, seccomp
#     RuntimeDefault, jamais privileged ni hostNetwork).
#
# IMPÉRATIF DE SÛRETÉ : dry_run = true et autonomy = "supervised" sont les
# valeurs par défaut. Un déploiement ne doit JAMAIS activer l'automatisation
# destructive par défaut.
#
# Ordre d'application garanti par depends_on / dépendances implicites :
#   namespace -> Secret (coquille ou préexistant) -> release Helm.
# ---------------------------------------------------------------------------

locals {
  # Libellés standards Kubernetes (recommandation app.kubernetes.io) complétés
  # par les libellés de gouvernance fournis par l'appelant.
  common_labels = merge(
    {
      "app.kubernetes.io/name"       = "thotsecure"
      "app.kubernetes.io/instance"   = var.release_name
      "app.kubernetes.io/part-of"    = "thotsecure"
      "app.kubernetes.io/component"  = "soar-cspm"
      "app.kubernetes.io/managed-by" = "terraform"
    },
    var.labels
  )

  # Clés attendues dans le Secret d'application : la clé d'application est
  # obligatoire, la clé de bootstrap est optionnelle (voir README).
  expected_secret_keys = [var.secret_key_env_var, "THOT_BOOTSTRAP_API_KEY"]

  # Le provider kubernetes expose l'attribut `data` de la source de données en
  # base64 (l'API Kubernetes stocke toujours les Secret en base64). On tente un
  # décodage base64 et on retombe sur la valeur brute si elle est déjà en clair,
  # afin de rester compatible avec les deux comportements du provider.
  raw_secret_data = var.create_secret_shell ? {} : try(data.kubernetes_secret_v1.thotsecure[0].data, {})

  secret_data = {
    for key, value in local.raw_secret_data :
    key => try(base64decode(value), value)
  }

  # Seules les clés réellement présentes dans le Secret sont injectées dans la
  # release Helm via set_sensitive : aucune valeur secrète n'est écrite en clair
  # dans le dépôt ni dans les values calculées.
  sensitive_env_from_secret = {
    for key in local.expected_secret_keys :
    key => local.secret_data[key]
    if lookup(local.secret_data, key, null) != null
  }

  # En mode « coquille », la clé est fournie par le gestionnaire de secrets
  # externe : on ne peut pas (et on ne doit pas) la lire au plan.
  missing_secret_keys = var.create_secret_shell ? [] : [
    for key in [var.secret_key_env_var] :
    key
    if lookup(local.secret_data, key, null) == null
  ]

  # Emplacement des données persistantes (base SQLite + quarantaine).
  data_dir = "/var/lib/thotsecure"

  effective_db_url = var.db_url != "" ? var.db_url : (
    var.persistence_enabled ? "sqlite:////var/lib/thotsecure/thotsecure.db" : "sqlite:///./data/thotsecure.db"
  )

  # Valeur par défaut applicative lorsque aucune URL NATS n'est fournie.
  effective_nats_url = var.nats_url != "" ? var.nats_url : "nats://127.0.0.1:4222"

  # Variables d'environnement NON secrètes (les valeurs secrètes passent par
  # helm set_sensitive et n'apparaissent jamais ici).
  app_env = merge(
    {
      THOT_ENV                = var.environment
      THOT_HOST               = "0.0.0.0"
      THOT_PORT               = "8080"
      THOT_DRY_RUN            = var.dry_run ? "true" : "false"
      THOT_AUTONOMY           = var.autonomy
      THOT_LOG_LEVEL          = var.log_level
      THOT_LOG_FORMAT         = var.log_format
      THOT_RATE_LIMIT_PER_MIN = tostring(var.rate_limit_per_min)
      THOT_RETENTION_DAYS     = tostring(var.retention_days)
      THOT_DB_URL             = local.effective_db_url
      THOT_RULES_DIR          = "/etc/thotsecure/rules"
      THOT_POLICIES_DIR       = "/etc/thotsecure/policies"
      THOT_PLAYBOOKS_DIR      = "/etc/thotsecure/playbooks"
      THOT_TARGETS_FILE       = "/etc/thotsecure/targets.yaml"
      THOT_BUS                = var.bus_mode
      THOT_TLS_ENABLED        = var.app_tls_enabled ? "true" : "false"
    },
    var.bus_mode == "nats" ? { THOT_NATS_URL = local.effective_nats_url } : {},
    var.opa_bin != "" ? { THOT_OPA_BIN = var.opa_bin } : {}
  )

  # Valeurs transmises au chart Helm. Les clés suivent le contrat du chart
  # deploy/helm/thotsecure : image, replicaCount, autonomy, dryRun, env, resources,
  # persistence, ingress, serviceMonitor, networkPolicy, podSecurityContext,
  # containerSecurityContext, nats.
  helm_values = {
    image = {
      repository = var.image_repository
      tag        = var.image_tag
      pullPolicy = var.image_pull_policy
    }

    replicaCount = var.replica_count

    # Garde-fous de sûreté : les mêmes valeurs que dans env pour éviter toute
    # ambiguïté selon la façon dont le chart rend la configuration.
    autonomy = var.autonomy
    dryRun   = var.dry_run

    env = local.app_env

    resources = {
      requests = var.resource_requests
      limits   = var.resource_limits
    }

    persistence = {
      enabled      = var.persistence_enabled
      size         = var.persistence_size
      storageClass = var.storage_class_name
      accessMode   = "ReadWriteOnce"
      mountPath    = local.data_dir
    }

    ingress = {
      enabled       = var.ingress_enabled
      className     = var.ingress_class_name
      host          = var.ingress_host
      tlsSecretName = var.ingress_tls_secret_name
      tls           = var.tls_enabled
      forceHttps    = var.tls_enabled
      annotations   = var.ingress_annotations
    }

    serviceMonitor = {
      enabled  = var.service_monitor_enabled
      path     = "/metrics"
      port     = "http"
      interval = "30s"
    }

    networkPolicy = {
      enabled = var.network_policy_enabled
    }

    podSecurityContext = {
      runAsNonRoot        = var.pod_security_context.run_as_non_root
      runAsUser           = var.pod_security_context.run_as_user
      runAsGroup          = var.pod_security_context.run_as_group
      fsGroup             = var.pod_security_context.fs_group
      fsGroupChangePolicy = var.pod_security_context.fs_group_change_policy
      seccompProfile = {
        type = var.pod_security_context.seccomp_profile_type
      }
    }

    containerSecurityContext = {
      allowPrivilegeEscalation = var.container_security_context.allow_privilege_escalation
      privileged               = var.container_security_context.privileged
      readOnlyRootFilesystem   = var.container_security_context.read_only_root_filesystem
      runAsNonRoot             = var.container_security_context.run_as_non_root
      runAsUser                = var.container_security_context.run_as_user
      runAsGroup               = var.container_security_context.run_as_group
      capabilities = {
        drop = var.container_security_context.capabilities_drop
        add  = var.container_security_context.capabilities_add
      }
      seccompProfile = {
        type = var.container_security_context.seccomp_profile_type
      }
    }

    nats = {
      enabled  = var.bus_mode == "nats"
      embedded = var.nats_embedded
      url      = local.effective_nats_url
      image    = "nats:2.10-alpine"
    }
  }

  # Fusion superficielle : une clé de premier niveau fournie dans extra_values
  # remplace intégralement la clé calculée ci-dessus (voir la variable).
  final_helm_values = merge(local.helm_values, var.extra_values)

  # Nom du Service créé par le chart (convention : nom de la release Helm).
  service_name = var.release_name
}

# ---------------------------------------------------------------------------
# Namespace : création optionnelle, toujours étiqueté et verrouillé en
# Pod Security Admission « restricted » (aucun conteneur privilégié, aucun
# ajout de capability, aucune escalade de privilèges).
# ---------------------------------------------------------------------------
resource "kubernetes_namespace_v1" "thotsecure" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace

    labels = merge(local.common_labels, {
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    })
  }
}

# ---------------------------------------------------------------------------
# Secret d'application — OPTIONNEL (créé uniquement si create_secret_shell).
#
# ATTENTION : cette ressource ne contient JAMAIS de valeur secrète. Elle crée une
# coquille vide, destinée à être remplie HORS BANDE par un gestionnaire de
# secrets (External Secrets Operator, Vault Agent Injector, SOPS + job de
# synchronisation, ...). Terraform ne connaît donc aucune valeur secrète et ne
# peut pas l'écraser : `ignore_changes = [data]` protège les clés ajoutées
# hors bande.
# ---------------------------------------------------------------------------
resource "kubernetes_secret_v1" "shell" {
  count = var.create_secret_shell ? 1 : 0

  metadata {
    name      = var.existing_secret_name
    namespace = var.namespace

    labels = local.common_labels

    annotations = {
      "thotsecure.io/populated-by"       = "external-secret-manager"
      "thotsecure.io/expected-keys"      = join(",", local.expected_secret_keys)
      "thotsecure.io/terraform-manages"  = "shell-only-no-values"
      "thotsecure.io/rotation-procedure" = "voir deploy/terraform/modules/secrets/README.md"
    }
  }

  type = "Opaque"
  data = {}

  lifecycle {
    # Les clés injectées hors bande ne doivent jamais être supprimées ni
    # réécrites par un apply Terraform.
    ignore_changes = [data]
  }
}

# ---------------------------------------------------------------------------
# Lecture du Secret préexistant. Le Secret DOIT exister avant le plan : il est
# créé hors bande (gestionnaire de secrets) ou par le module ../../secrets.
# En mode create_secret_shell = true, la lecture est désactivée et la clé est
# fournie au conteneur par le gestionnaire de secrets externe.
# ---------------------------------------------------------------------------
data "kubernetes_secret_v1" "thotsecure" {
  count = var.create_secret_shell ? 0 : 1

  metadata {
    name      = var.existing_secret_name
    namespace = var.namespace
  }

  depends_on = [kubernetes_namespace_v1.thotsecure]
}

# ---------------------------------------------------------------------------
# Release Helm Thot Secure.
#
# Le chart est installé dans un namespace déjà existant (create_namespace = false
# côté Helm comme côté module) ; les dépendances explicites garantissent que le
# namespace et le Secret sont prêts avant l'installation.
# ---------------------------------------------------------------------------
resource "helm_release" "thotsecure" {
  name      = var.release_name
  namespace = var.namespace
  chart     = var.chart_path

  create_namespace = false
  atomic           = var.helm_atomic
  cleanup_on_fail  = true
  timeout          = var.helm_timeout_seconds
  wait             = true
  max_history      = 5

  values = [yamlencode(local.final_helm_values)]

  # Valeurs secrètes : transmises uniquement de manière « sensitive » depuis le
  # Secret lu au plan. set_sensitive empêche Helm/Terraform d'afficher la valeur
  # dans les logs, mais elle reste présente dans le state Terraform : utilisez
  # impérativement un backend chiffré (encrypt = true) et des droits restreints.
  dynamic "set_sensitive" {
    for_each = local.sensitive_env_from_secret

    content {
      name  = set_sensitive.key
      value = set_sensitive.value
    }
  }

  depends_on = [
    kubernetes_namespace_v1.thotsecure,
    kubernetes_secret_v1.shell,
  ]

  lifecycle {
    precondition {
      condition     = length(local.missing_secret_keys) == 0
      error_message = "Le Secret existant ne contient pas la clé requise. Créez hors bande un Secret nommé « ${var.existing_secret_name} » dans le namespace « ${var.namespace} » contenant l'attribut ${var.secret_key_env_var} (voir le README du module). Aucune valeur secrète ne doit être écrite dans Terraform."
    }
  }
}
