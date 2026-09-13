# ---------------------------------------------------------------------------
# Thot Secure — module Terraform « thotsecure-k8s »
# Contraintes de version de Terraform et des providers requis.
#
# Le module s'appuie sur deux providers :
#   * kubernetes (hashicorp/kubernetes) : namespace, Secret coquille, lecture du
#     Secret existant au plan.
#   * helm (hashicorp/helm) : installation du chart local deploy/helm/thotsecure.
#
# Aucun provider cloud n'est requis : ce module est portable EKS / AKS / k3s.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }

    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }
}
