/**
 * RBAC côté client — miroir exact du tableau du contrat §4.
 *
 * ⚠️ Ceci n'est **pas** une frontière de sécurité : le serveur applique les
 * capacités par dépendance FastAPI et revérifie dans le core (contrat §10).
 * Le rôle de ce module est de **masquer** les contrôles dont la capacité
 * manque : un utilisateur à qui l'action est refusée ne doit même pas voir le
 * bouton, et ne doit jamais pouvoir déclencher une mutation destructive par
 * erreur. Toute capacité absente est traitée de façon restrictive (fail-closed).
 */
import type { Capability, Role } from './types';

/** Capacités cumulatives par rôle (viewer ⊂ analyst ⊂ responder ⊂ admin). */
export const ROLE_CAPABILITIES: Record<Role, readonly Capability[]> = {
  viewer: ['read:events', 'read:findings', 'read:rules', 'read:policies', 'read:audit', 'read:stats'],
  analyst: [
    'read:events',
    'read:findings',
    'read:rules',
    'read:policies',
    'read:audit',
    'read:stats',
    'write:events',
    'write:findings',
  ],
  responder: [
    'read:events',
    'read:findings',
    'read:rules',
    'read:policies',
    'read:audit',
    'read:stats',
    'write:events',
    'write:findings',
    'execute:actions',
    'approve:actions',
  ],
  admin: [
    'read:events',
    'read:findings',
    'read:rules',
    'read:policies',
    'read:audit',
    'read:stats',
    'write:events',
    'write:findings',
    'execute:actions',
    'approve:actions',
    'admin:tenants',
    'admin:rules',
    'admin:keys',
    'admin:policies',
  ],
};

/** Ordre hiérarchique des rôles, pour comparaison. */
const ROLE_RANK: Record<Role, number> = { viewer: 0, analyst: 1, responder: 2, admin: 3 };

/** Libellés français pour l'interface. */
export const ROLE_LABELS: Record<Role, string> = {
  viewer: 'Lecteur',
  analyst: 'Analyste',
  responder: 'Intervenant',
  admin: 'Administrateur',
};

/** Libellés français des capacités (infobulles, pages d'aide). */
export const CAPABILITY_LABELS: Record<Capability, string> = {
  'read:events': 'Lire les événements',
  'read:findings': 'Lire les findings et les actions',
  'read:rules': 'Lire les règles et les playbooks',
  'read:policies': 'Lire les politiques',
  'read:audit': 'Lire le journal d’audit',
  'read:stats': 'Lire les statistiques et les collecteurs',
  'write:events': 'Ingérer des événements',
  'write:findings': 'Modifier le statut des findings',
  'execute:actions': 'Exécuter et annuler des actions',
  'approve:actions': 'Approuver ou rejeter des actions',
  'admin:tenants': 'Administrer les tenants',
  'admin:rules': 'Valider et recharger les règles',
  'admin:keys': 'Gérer les clés API',
  'admin:policies': 'Recharger les politiques',
};

export function capabilitiesForRole(role: Role): Capability[] {
  return [...ROLE_CAPABILITIES[role]];
}

export function isRole(role: unknown): role is Role {
  return typeof role === 'string' && (ROLE_RANK as Record<string, number>)[role] !== undefined;
}

export function isRoleAtLeast(role: Role | null | undefined, minimum: Role): boolean {
  if (!role || !isRole(role)) return false;
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

/**
 * Vérifie une capacité. `granted` vient de `GET /auth/whoami` (source de
 * vérité serveur) ; en cas de valeur absente ou malformée → `false`.
 */
export function hasCapability(
  granted: readonly Capability[] | null | undefined,
  required: Capability,
): boolean {
  if (!granted || granted.length === 0) return false;
  return granted.includes(required);
}

export function hasAnyCapability(
  granted: readonly Capability[] | null | undefined,
  required: readonly Capability[],
): boolean {
  return required.some((capability) => hasCapability(granted, capability));
}

export function hasAllCapabilities(
  granted: readonly Capability[] | null | undefined,
  required: readonly Capability[],
): boolean {
  return required.every((capability) => hasCapability(granted, capability));
}
