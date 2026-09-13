/**
 * Application : routage, garde d'authentification, coque.
 *
 * Structure de routes :
 *   `/login`              — écran de connexion (clé API), hors coque ;
 *   `AuthGate` (layout)   — redirige vers `/login` tant qu'aucune clé valide
 *                           n'est confirmée par `GET /api/v1/auth/whoami` ;
 *   `AppShell` (layout)   — navigation, en-tête, flux live, période ;
 *   chaque page est en outre protégée par sa capacité (`CapabilityGate`) :
 *   l'interface **masque** ce que le rôle n'autorise pas, et le serveur le refuse
 *   indépendamment (défense en profondeur, contrat §10).
 */
import type { ReactNode } from 'react';
import { Navigate, Outlet, Route, Routes } from 'react-router-dom';

import { AppShell } from '@/components/AppShell';
import { LoadingBlock, LockedNotice, Panel } from '@/components/ui';
import { useAuth } from '@/lib/auth';
import type { Capability } from '@/lib/types';
import { ActionsPage } from '@/pages/ActionsPage';
import { AuditPage } from '@/pages/AuditPage';
import { CollectorsPage } from '@/pages/CollectorsPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { FindingsPage } from '@/pages/FindingsPage';
import { LoginPage } from '@/pages/LoginPage';
import { RulesPage } from '@/pages/RulesPage';
import { SupportPage } from '@/pages/SupportPage';

/** Écran d'attente pendant la validation de la clé auprès de l'API. */
function BootScreen(): JSX.Element {
  return (
    <div className="mx-auto max-w-md px-4 py-16">
      <Panel title="Thot Secure — Console SOC" description="Connexion à l’API en cours…">
        <LoadingBlock label="Validation de la clé API (auth/whoami)…" rows={3} />
        <p className="mt-2 text-2xs text-slate-500">
          Le périmètre de données (tenant) et les capacités ne sont pas devinés : ils sont fournis par le serveur.
        </p>
      </Panel>
    </div>
  );
}

/**
 * Garde d'authentification. Sans clé API valide, aucune route de données n'est
 * montée : les composants de page ne peuvent donc pas déclencher de requête
 * authentifiée ni afficher d'état intermédiaire trompeur.
 */
function AuthGate(): JSX.Element {
  const { status } = useAuth();

  if (status === 'loading') return <BootScreen />;
  if (status !== 'authenticated') return <Navigate to="/login" replace />;
  return <Outlet />;
}

interface CapabilityGateProps {
  capability: Capability;
  children: ReactNode;
}

/** Masque une page dont la capacité manque, en expliquant l'absence. */
function CapabilityGate(props: CapabilityGateProps): JSX.Element {
  const { can } = useAuth();
  if (!can(props.capability)) return <LockedNotice capability={props.capability} />;
  return <>{props.children}</>;
}

export default function App(): JSX.Element {
  const { status } = useAuth();

  return (
    <Routes>
      {/* Hors coque : la connexion ne doit afficher ni navigation ni données. */}
      <Route
        path="/login"
        element={status === 'authenticated' ? <Navigate to="/" replace /> : <LoginPage />}
      />

      <Route element={<AuthGate />}>
        <Route element={<AppShell />}>
          <Route
            path="/"
            element={
              <CapabilityGate capability="read:stats">
                <DashboardPage />
              </CapabilityGate>
            }
          />
          <Route
            path="/findings"
            element={
              <CapabilityGate capability="read:findings">
                <FindingsPage />
              </CapabilityGate>
            }
          />
          <Route
            path="/actions"
            element={
              <CapabilityGate capability="read:findings">
                <ActionsPage />
              </CapabilityGate>
            }
          />
          <Route
            path="/audit"
            element={
              <CapabilityGate capability="read:audit">
                <AuditPage />
              </CapabilityGate>
            }
          />
          <Route
            path="/rules"
            element={
              <CapabilityGate capability="read:rules">
                <RulesPage />
              </CapabilityGate>
            }
          />
          <Route
            path="/collectors"
            element={
              <CapabilityGate capability="read:stats">
                <CollectorsPage />
              </CapabilityGate>
            }
          />
          {/* Page de soutien : accessible à tout rôle authentifié. */}
          <Route path="/support" element={<SupportPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
