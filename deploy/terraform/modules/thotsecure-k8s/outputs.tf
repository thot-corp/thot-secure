# ---------------------------------------------------------------------------
# Sorties du module « thotsecure-k8s ».
#
# Aucune sortie n'expose de valeur secrète : les valeurs sensibles injectées via
# helm set_sensitive ne sont jamais réémises ici.
# ---------------------------------------------------------------------------

output "namespace" {
  description = "Namespace Kubernetes dans lequel Thot Secure est déployé."
  value       = var.namespace
}

output "release_name" {
  description = "Nom de la release Helm Thot Secure."
  value       = helm_release.thotsecure.name
}

output "release_version" {
  description = "Version du chart Helm effectivement déployée."
  value       = helm_release.thotsecure.version
}

output "service_name" {
  description = "Nom du Service Kubernetes exposant l'API Thot Secure (convention du chart : nom de la release)."
  value       = local.service_name
}

output "service_port" {
  description = "Port applicatif exposé par le Service (8080 : API, console web, sondes /healthz, /readyz, /metrics)."
  value       = 8080
}

output "dry_run" {
  description = "État du garde-fou dry-run. true (défaut sûr) = aucune action réelle n'est exécutée sur les cibles."
  value       = var.dry_run
}

output "autonomy" {
  description = "Niveau d'autonomie appliqué (manual, supervised, auto). supervised (défaut sûr) = toute action attend une validation humaine."
  value       = var.autonomy
}

output "helm_manifest_summary" {
  description = "Manifeste Kubernetes rendu par la release Helm. SENSIBLE : selon la façon dont le chart rend la configuration, des variables d'environnement secrètes peuvent y figurer en clair. Ne l'affichez ni dans un terminal partagé ni dans un journal de CI."
  value       = helm_release.thotsecure.manifest
  sensitive   = true
}

output "persistence_claim_name" {
  description = "Nom attendu du PersistentVolumeClaim qui porte /var/lib/thotsecure (base SQLite + quarantaine). Chaîne vide si persistence_enabled = false."
  value       = var.persistence_enabled ? "${var.release_name}-data" : ""
}

output "internal_url" {
  description = "URL interne du service Thot Secure, joignable depuis n'importe quel pod du cluster."
  value       = "http://${local.service_name}.${var.namespace}.svc.cluster.local:8080"
}

output "next_steps" {
  description = "Commandes de vérification post-déploiement et rappels de sûreté (healthz, readyz, métriques, état des garde-fous)."
  value = [
    "# 1. Vérifier que le pod est prêt (utilisateur non-root 10001, rootfs en lecture seule).",
    "kubectl --namespace ${var.namespace} get pods -l app.kubernetes.io/name=thotsecure -o wide",
    "# 2. Vérifier la sonde de vivacité /healthz via un accès local au Service.",
    "kubectl --namespace ${var.namespace} port-forward svc/${local.service_name} 8080:8080",
    "curl -fsS http://127.0.0.1:8080/healthz",
    "# 3. Vérifier la sonde de disponibilité /readyz (503 si une dépendance est KO).",
    "curl -fsS -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:8080/readyz",
    "# 4. Vérifier l'exposition Prometheus /metrics.",
    "curl -fsS http://127.0.0.1:8080/metrics | head -n 20",
    "# 5. Confirmer les garde-fous de sûreté effectivement appliqués au conteneur.",
    "kubectl --namespace ${var.namespace} exec deploy/${var.release_name} -- env | grep -E '^THOT_(DRY_RUN|AUTONOMY|ENV)='",
    "# 6. Contrôler le durcissement (doit rester non-root, sans capability ajoutée).",
    "kubectl --namespace ${var.namespace} get pod -l app.kubernetes.io/name=thotsecure -o jsonpath='{.items[0].spec.containers[0].securityContext}'",
    "# RAPPEL DE SÛRETÉ : dryRun=${var.dry_run} et autonomy=${var.autonomy} sont les valeurs sûres par défaut.",
    "# Ne les désactivez jamais en production sans procédure de validation humaine documentée :",
    "# Thot Secure est un SOAR/CSPM 100 % défensif et dry-run désactivé autorise des actions réelles sur des cibles.",
  ]
}
