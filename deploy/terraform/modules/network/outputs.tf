# ---------------------------------------------------------------------------
# Sorties du module « network ».
# ---------------------------------------------------------------------------

output "policy_names" {
  description = "Liste des politiques réseau effectivement créées dans le namespace (ordre de création du modèle de flux)."
  value       = local.policy_names
}

output "deny_all_policy_name" {
  description = "Nom de la politique deny-all (chaîne vide si enable_default_deny = false)."
  value       = var.enable_default_deny ? "${local.name_prefix}-default-deny" : ""
}

output "app_pod_selector" {
  description = "Sélecteur d'étiquettes (carte) des pods Thot Secure auquel s'appliquent les politiques d'autorisation."
  value       = local.app_labels
}

output "namespace" {
  description = "Namespace dans lequel les politiques ont été créées."
  value       = var.namespace
}

output "managed_target_cidrs" {
  description = "CIDR des cibles supervisées actuellement autorisés en sortie (vide si aucune cible déclarée)."
  value       = var.managed_target_cidrs
}

output "public_ingress_allowed" {
  description = "Indique si l'exception 0.0.0.0/0 (allow_public_ingress_any) est active. Doit rester false en production."
  value       = var.allow_public_ingress_any
}

output "cloud_firewall_rule_documents" {
  description = "Équivalents documentaires des flux autorisés pour les pare-feux cloud (AWS Security Group, Azure NSG). Vide sauf si emit_cloud_firewall_documents = true. Aucun provider cloud n'est requis : ces règles sont à reporter manuellement ou via votre propre code cloud."
  value = var.emit_cloud_firewall_documents ? {
    aws_security_group_rules = concat(
      [
        "Ingress TCP 8080 depuis le Security Group de l'ingress controller (${var.ingress_namespace}/${var.ingress_pod_selector})",
        "Ingress TCP 8080 depuis le Security Group de la supervision (${var.monitoring_namespace}) si metrics_scrape_enabled = true",
        "Egress  UDP/TCP 53 vers le résolveur DNS du VPC ou les nœuds CoreDNS",
      ],
      var.nats_enabled ? ["Egress TCP ${tostring(var.nats_port)} vers le Security Group NATS (${var.nats_namespace}/${var.nats_pod_selector})"] : [],
      length(var.managed_target_cidrs) > 0 ? ["Egress TCP ${join(",", var.managed_target_ports)} vers les CIDR des cibles supervisées : ${join(", ", var.managed_target_cidrs)}"] : [],
      [for cidr in local.extra_ingress_cidrs : "Ingress TCP 8080 depuis ${cidr}"],
      ["Egress TCP 443 vers les endpoints AWS requis par le cluster (ECR, S3, STS) si les nœuds n'ont pas de points de terminaison VPC"]
    )

    azurerm_network_security_rules = concat(
      [
        "Allow Inbound TCP 8080 depuis le subnet de l'ingress controller (priorité à définir, ${var.ingress_namespace})",
        "Allow Inbound TCP 8080 depuis le subnet de supervision (${var.monitoring_namespace}) si metrics_scrape_enabled = true",
        "Allow Outbound UDP/TCP 53 vers le résolveur DNS Azure (168.63.129.16)",
      ],
      var.nats_enabled ? ["Allow Outbound TCP ${tostring(var.nats_port)} vers le subnet NATS (${var.nats_namespace})"] : [],
      length(var.managed_target_cidrs) > 0 ? ["Allow Outbound TCP ${join(",", var.managed_target_ports)} vers les CIDR des cibles supervisées : ${join(", ", var.managed_target_cidrs)}"] : [],
      [for cidr in local.extra_ingress_cidrs : "Allow Inbound TCP 8080 depuis ${cidr}"],
      ["Deny All Inbound / Deny All Outbound en dernière règle (priorité la plus élevée)"]
    )
  } : {}
}
