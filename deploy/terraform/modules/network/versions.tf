# ---------------------------------------------------------------------------
# Thot Secure — module Terraform « network »
#
# Contraintes de version de Terraform et des providers.
#
# Ce module est VOLONTAIREMENT portable : son cœur est un ensemble de
# kubernetes_network_policy_v1, qui fonctionne sur EKS, AKS, k3s et tout cluster
# conforme. Aucun provider cloud n'est requis par défaut, afin de ne pas imposer
# un provider absent de la configuration appelante.
#
# Équivalents cloud (documentés, non codés ici) : les mêmes flux doivent être
# reflétés dans les pare-feux cloud, qui ne connaissent pas les NetworkPolicy :
#   * AWS   : aws_security_group_ingress / aws_security_group_egress,
#             aws_vpc_security_group_ingress_rule / aws_vpc_security_group_egress_rule
#             (provider hashicorp/aws ~> 5.40) ;
#   * Azure : azurerm_network_security_rule rattachées au subnet des nœuds
#             (provider hashicorp/azurerm ~> 3.90).
# Pour les activer dans un appelant, déclarez-les dans le module racine puis
# passez-les avec des alias de configuration :
#
#   # versions.tf du module RACINE (pas de ce module)
#   terraform {
#     required_providers {
#       aws = {
#         source                = "hashicorp/aws"
#         version               = "~> 5.40"
#         configuration_aliases = [aws.network]
#       }
#       azurerm = {
#         source                = "hashicorp/azurerm"
#         version               = "~> 3.90"
#         configuration_aliases = [azurerm.network]
#       }
#     }
#   }
#
# Le module publie en attendant la sortie `cloud_firewall_rule_documents`
# (activée par emit_cloud_firewall_documents = true) qui liste les règles
# équivalentes à reporter côté cloud.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
  }
}
