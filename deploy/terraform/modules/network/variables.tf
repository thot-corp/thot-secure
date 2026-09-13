# ---------------------------------------------------------------------------
# Variables du module « network ».
#
# Modèle : deny-all par défaut, puis autorisations explicites, une par flux
# justifié (DNS sortant, entrée depuis l'ingress controller, NATS, cibles
# supervisées, scrape Prometheus). Aucun 0.0.0.0/0 n'est autorisé sans
# justification explicite.
# ---------------------------------------------------------------------------

variable "namespace" {
  description = "Namespace Kubernetes des charges Thot Secure auxquelles appliquer les politiques réseau. Il doit déjà exister."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace doit être un nom DNS-1123 valide (minuscules, chiffres et tirets uniquement)."
  }
}

variable "app_label_selector" {
  description = "Sélecteur d'étiquettes des pods Thot Secure, au format Kubernetes « clé=valeur » (plusieurs paires séparées par des virgules)."
  type        = string
  default     = "app.kubernetes.io/name=thotsecure"

  validation {
    condition = alltrue([
      for pair in split(",", var.app_label_selector) :
      length(split("=", pair)) == 2 && trimspace(split("=", pair)[0]) != "" && trimspace(split("=", pair)[1]) != ""
    ])
    error_message = "app_label_selector doit être une liste de paires « clé=valeur » séparées par des virgules, par exemple app.kubernetes.io/name=thotsecure."
  }
}

variable "ingress_namespace" {
  description = "Namespace de l'ingress controller autorisé à joindre l'API et la console Thot Secure."
  type        = string
  default     = "ingress-nginx"
}

variable "ingress_pod_selector" {
  description = "Sélecteur d'étiquettes des pods de l'ingress controller, au format « clé=valeur »."
  type        = string
  default     = "app.kubernetes.io/name=ingress-nginx"

  validation {
    condition = alltrue([
      for pair in split(",", var.ingress_pod_selector) :
      length(split("=", pair)) == 2 && trimspace(split("=", pair)[0]) != ""
    ])
    error_message = "ingress_pod_selector doit être une liste de paires « clé=valeur » séparées par des virgules."
  }
}

variable "dns_namespace" {
  description = "Namespace du résolveur DNS du cluster (kube-system pour CoreDNS)."
  type        = string
  default     = "kube-system"
}

variable "dns_pod_selector" {
  description = "Sélecteur d'étiquettes des pods DNS (k8s-app=kube-dns pour CoreDNS, y compris sur EKS)."
  type        = string
  default     = "k8s-app=kube-dns"

  validation {
    condition = alltrue([
      for pair in split(",", var.dns_pod_selector) :
      length(split("=", pair)) == 2 && trimspace(split("=", pair)[0]) != ""
    ])
    error_message = "dns_pod_selector doit être une liste de paires « clé=valeur » séparées par des virgules."
  }
}

variable "nats_enabled" {
  description = "Autoriser le flux sortant vers un bus NATS déployé dans le cluster (requis lorsque THOT_BUS=nats sans mode embarqué)."
  type        = bool
  default     = false
}

variable "nats_namespace" {
  description = "Namespace du service NATS lorsque nats_enabled = true."
  type        = string
  default     = "thotsecure"
}

variable "nats_pod_selector" {
  description = "Sélecteur d'étiquettes des pods NATS (image nats:2.10-alpine)."
  type        = string
  default     = "app.kubernetes.io/name=nats"

  validation {
    condition = alltrue([
      for pair in split(",", var.nats_pod_selector) :
      length(split("=", pair)) == 2 && trimspace(split("=", pair)[0]) != ""
    ])
    error_message = "nats_pod_selector doit être une liste de paires « clé=valeur » séparées par des virgules."
  }
}

variable "nats_port" {
  description = "Port TCP du service NATS (4222 par défaut)."
  type        = number
  default     = 4222

  validation {
    condition     = var.nats_port >= 1 && var.nats_port <= 65535
    error_message = "nats_port doit être un port TCP valide (1-65535)."
  }
}

variable "managed_target_cidrs" {
  description = "CIDR des cibles supervisées (périmètre d'action d'Thot Secure). Chaque CIDR donne lieu à une règle de sortie explicite ; aucun 0.0.0.0/0 n'est accepté. IPv4 uniquement (la validation s'appuie sur cidrnetmask)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.managed_target_cidrs : can(cidrnetmask(cidr))])
    error_message = "managed_target_cidrs doit contenir uniquement des CIDR IPv4 valides, par exemple 10.20.0.0/16."
  }

  validation {
    condition     = alltrue([for cidr in var.managed_target_cidrs : cidr != "0.0.0.0/0"])
    error_message = "managed_target_cidrs ne peut pas contenir 0.0.0.0/0 : le périmètre d'action d'un SOAR doit être explicitement borné."
  }
}

variable "managed_target_ports" {
  description = "Ports TCP autorisés vers les cibles supervisées (443 par défaut). N'ouvrez que les ports réellement utilisés par vos intégrations."
  type        = list(string)
  default     = ["443"]

  validation {
    condition     = length(var.managed_target_ports) > 0
    error_message = "managed_target_ports doit contenir au moins un port lorsque managed_target_cidrs n'est pas vide."
  }

  validation {
    condition     = alltrue([for port in var.managed_target_ports : can(regex("^[0-9]{1,5}$", port))])
    error_message = "managed_target_ports doit contenir des numéros de port TCP sous forme de chaînes (par exemple \"443\")."
  }
}

variable "monitoring_namespace" {
  description = "Namespace de la pile de supervision autorisée à scraper /metrics (Prometheus)."
  type        = string
  default     = "monitoring"
}

variable "metrics_scrape_enabled" {
  description = "Autoriser l'entrée depuis monitoring_namespace vers le port applicatif 8080 pour le scrape Prometheus de /metrics."
  type        = bool
  default     = true
}

variable "enable_default_deny" {
  description = "Créer la politique deny-all (podSelector vide, policyTypes Ingress et Egress). À laisser true : c'est le socle du modèle « tout est interdit sauf explicitement autorisé »."
  type        = bool
  default     = true
}

variable "extra_ingress_cidrs" {
  description = "CIDR supplémentaires autorisés à joindre directement le port applicatif 8080 (par exemple le réseau d'administration ou le CI). Chaque entrée est un flux entrant explicite et doit être justifiée."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.extra_ingress_cidrs : can(cidrnetmask(cidr))])
    error_message = "extra_ingress_cidrs doit contenir uniquement des CIDR IPv4 valides, par exemple 10.0.0.0/8."
  }

  validation {
    condition     = alltrue([for cidr in var.extra_ingress_cidrs : cidr != "0.0.0.0/0"])
    error_message = "extra_ingress_cidrs ne peut pas contenir 0.0.0.0/0. L'exposition publique doit passer par l'ingress controller ; si elle est réellement voulue, utilisez allow_public_ingress_any = true en connaissance de cause."
  }
}

variable "allow_public_ingress_any" {
  description = "AVERTISSEMENT : exception explicite au principe « aucun 0.0.0.0/0 ». Si true, une règle d'entrée depuis 0.0.0.0/0 vers le port 8080 est créée : Thot Secure devient joignable depuis n'importe quelle source, y compris Internet. À ne jamais activer en production ; préférez un Ingress avec authentification."
  type        = bool
  default     = false
}

variable "emit_cloud_firewall_documents" {
  description = "Publier dans la sortie cloud_firewall_rule_documents l'équivalent des flux autorisés pour les pare-feux cloud (Security Group AWS / NSG Azure). Purement documentaire : aucun provider cloud n'est requis."
  type        = bool
  default     = false
}

variable "labels" {
  description = "Libellés additionnels appliqués aux politiques réseau (tags de gouvernance : Project, Environment, ManagedBy, Owner, Compliance)."
  type        = map(string)
  default     = {}
}
