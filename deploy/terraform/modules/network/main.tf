# ---------------------------------------------------------------------------
# Thot Secure — module Terraform « network »
#
# Modèle de flux : « tout est interdit sauf explicitement autorisé ».
#
#   1. <prefix>-default-deny            : deny-all (Ingress + Egress), podSelector vide.
#   2. <prefix>-allow-ingress-controller: entrée console/API depuis l'ingress controller.
#   3. <prefix>-allow-dns-egress        : sortie DNS vers kube-system (53/udp, 53/tcp).
#   4. <prefix>-allow-nats-egress       : sortie vers le bus NATS (si nats_enabled).
#   5. <prefix>-allow-targets-egress    : sortie vers les cibles supervisées (CIDR explicites).
#   6. <prefix>-allow-monitoring-scrape : entrée du scrape Prometheus de /metrics.
#   7. <prefix>-allow-extra-ingress-cidrs : entrée directe depuis des CIDR listés
#      explicitement (réseau d'administration, CI). Seule exception possible à
#      l'interdiction de 0.0.0.0/0 : allow_public_ingress_any = true, commentée
#      et volontairement non activée par défaut.
#
# Toutes les politiques ciblent les pods Thot Secure du namespace (sauf la
# deny-all, qui vise tous les pods du namespace).
# ---------------------------------------------------------------------------

locals {
  name_prefix = "thotsecure"

  # Conversion des sélecteurs « clé=valeur[,clé=valeur] » en cartes d'étiquettes
  # utilisables par les blocs namespace_selector / pod_selector.
  app_labels = {
    for pair in split(",", var.app_label_selector) :
    trimspace(split("=", pair)[0]) => trimspace(split("=", pair)[1])
  }

  ingress_pod_labels = {
    for pair in split(",", var.ingress_pod_selector) :
    trimspace(split("=", pair)[0]) => trimspace(split("=", pair)[1])
  }

  dns_pod_labels = {
    for pair in split(",", var.dns_pod_selector) :
    trimspace(split("=", pair)[0]) => trimspace(split("=", pair)[1])
  }

  nats_pod_labels = {
    for pair in split(",", var.nats_pod_selector) :
    trimspace(split("=", pair)[0]) => trimspace(split("=", pair)[1])
  }

  # Libellés appliqués aux politiques, pour l'audit et le filtrage.
  common_labels = merge(
    {
      "app.kubernetes.io/name"       = "thotsecure"
      "app.kubernetes.io/part-of"    = "thotsecure"
      "app.kubernetes.io/managed-by" = "terraform"
      "thotsecure.io/purpose"          = "network-policy"
    },
    var.labels
  )

  # 0.0.0.0/0 n'apparaît que si allow_public_ingress_any = true (exception
  # explicite documentée sur la variable).
  extra_ingress_cidrs = concat(var.extra_ingress_cidrs, var.allow_public_ingress_any ? ["0.0.0.0/0"] : [])

  # Inventaire des politiques réellement créées (utilisé par les sorties).
  policy_names = concat(
    var.enable_default_deny ? ["${local.name_prefix}-default-deny"] : [],
    [
      "${local.name_prefix}-allow-ingress-controller",
      "${local.name_prefix}-allow-dns-egress",
    ],
    var.nats_enabled ? ["${local.name_prefix}-allow-nats-egress"] : [],
    length(var.managed_target_cidrs) > 0 ? ["${local.name_prefix}-allow-targets-egress"] : [],
    var.metrics_scrape_enabled ? ["${local.name_prefix}-allow-monitoring-scrape"] : [],
    length(local.extra_ingress_cidrs) > 0 ? ["${local.name_prefix}-allow-extra-ingress-cidrs"] : []
  )
}

# ---------------------------------------------------------------------------
# 1. Deny-all : socle du modèle. podSelector vide = TOUS les pods du namespace ;
#    policyTypes = Ingress + Egress = tout est refusé par défaut.
# ---------------------------------------------------------------------------
resource "kubernetes_network_policy_v1" "default_deny" {
  count = var.enable_default_deny ? 1 : 0

  metadata {
    name      = "${local.name_prefix}-default-deny"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {}

    policy_types = ["Ingress", "Egress"]
  }
}

# ---------------------------------------------------------------------------
# 2. Entrée depuis l'ingress controller : publie la console web (/) et l'API.
#    Source doublement contrainte (namespace ET étiquettes de pods) et limitée
#    au port applicatif 8080 : aucun autre pod du cluster ne peut joindre
#    Thot Secure directement.
# ---------------------------------------------------------------------------
resource "kubernetes_network_policy_v1" "allow_ingress_controller" {
  metadata {
    name      = "${local.name_prefix}-allow-ingress-controller"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = local.app_labels
    }

    policy_types = ["Ingress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.ingress_namespace
          }
        }

        pod_selector {
          match_labels = local.ingress_pod_labels
        }
      }

      ports {
        port     = "8080"
        protocol = "TCP"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 3. Sortie DNS vers le résolveur du cluster. Sans cette règle, aucune cible ni
#    aucun service ne peut être résolu par nom : la collecte et la corrélation
#    d'événements échoueraient silencieusement.
#    Limité aux pods DNS de dns_namespace et aux ports 53/udp et 53/tcp.
# ---------------------------------------------------------------------------
resource "kubernetes_network_policy_v1" "allow_dns_egress" {
  metadata {
    name      = "${local.name_prefix}-allow-dns-egress"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = local.app_labels
    }

    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.dns_namespace
          }
        }

        pod_selector {
          match_labels = local.dns_pod_labels
        }
      }

      ports {
        port     = "53"
        protocol = "UDP"
      }

      ports {
        port     = "53"
        protocol = "TCP"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 4. Sortie vers le bus NATS (image nats:2.10-alpine). Nécessaire uniquement
#    lorsque THOT_BUS = nats sans NATS embarqué : le mode embarqué utilise
#    la boucle locale du pod et ne requiert aucune règle.
# ---------------------------------------------------------------------------
resource "kubernetes_network_policy_v1" "allow_nats_egress" {
  count = var.nats_enabled ? 1 : 0

  metadata {
    name      = "${local.name_prefix}-allow-nats-egress"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = local.app_labels
    }

    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.nats_namespace
          }
        }

        pod_selector {
          match_labels = local.nats_pod_labels
        }
      }

      ports {
        port     = tostring(var.nats_port)
        protocol = "TCP"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 5. Sortie vers les cibles supervisées. Thot Secure est un outil défensif : il doit
#    pouvoir interroger les systèmes qu'il surveille (collecte d'indicateurs,
#    réponse à incident supervisée). Le périmètre est strictement borné par
#    managed_target_cidrs — la variable refuse 0.0.0.0/0 — et par
#    managed_target_ports (443 par défaut).
# ---------------------------------------------------------------------------
resource "kubernetes_network_policy_v1" "allow_targets_egress" {
  count = length(var.managed_target_cidrs) > 0 ? 1 : 0

  metadata {
    name      = "${local.name_prefix}-allow-targets-egress"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = local.app_labels
    }

    policy_types = ["Egress"]

    egress {
      dynamic "to" {
        for_each = var.managed_target_cidrs

        content {
          ip_block {
            cidr = to.value
          }
        }
      }

      dynamic "ports" {
        for_each = var.managed_target_ports

        content {
          port     = ports.value
          protocol = "TCP"
        }
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 6. Entrée du scrape Prometheus (/metrics). NetworkPolicy ne filtre pas par
#    chemin HTTP : tout pod du namespace de supervision peut atteindre le port
#    8080. Restreindre davantage supposerait un proxy ou un maillage de services.
# ---------------------------------------------------------------------------
resource "kubernetes_network_policy_v1" "allow_monitoring_scrape" {
  count = var.metrics_scrape_enabled ? 1 : 0

  metadata {
    name      = "${local.name_prefix}-allow-monitoring-scrape"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = local.app_labels
    }

    policy_types = ["Ingress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.monitoring_namespace
          }
        }
      }

      ports {
        port     = "8080"
        protocol = "TCP"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 7. Entrées supplémentaires explicitement listées (réseau d'administration, CI).
#
#    NOTE DE SÛRETÉ : si allow_public_ingress_any = true, cette politique contient
#    la SEULE occurrence de 0.0.0.0/0 du module. C'est une exception volontaire,
#    commentée, désactivée par défaut et fortement déconseillée : elle expose
#    l'API et la console Thot Secure à toute source, y compris Internet. Préférez
#    l'Ingress avec authentification et TLS.
# ---------------------------------------------------------------------------
resource "kubernetes_network_policy_v1" "allow_extra_ingress_cidrs" {
  count = length(local.extra_ingress_cidrs) > 0 ? 1 : 0

  metadata {
    name      = "${local.name_prefix}-allow-extra-ingress-cidrs"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = local.app_labels
    }

    policy_types = ["Ingress"]

    ingress {
      dynamic "from" {
        for_each = local.extra_ingress_cidrs

        content {
          ip_block {
            cidr = from.value
          }
        }
      }

      ports {
        port     = "8080"
        protocol = "TCP"
      }
    }
  }
}
