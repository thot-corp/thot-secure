/**
 * Flux temps réel (`WS /api/v1/ws/stream`, contrat §4.8).
 *
 * Le flux est **ouvert une seule fois** pour toute l'application : ce module
 * expose un fournisseur monté par `AppShell`, l'indicateur d'état affiché dans
 * l'en-tête et le panneau de journal consommés par le tableau de bord. Ouvrir
 * un second socket depuis chaque page multiplierait les connexions authentifiées
 * et les risques de désynchronisation.
 *
 * Sûreté :
 *  - les frames sont des données **non fiables** : `toLiveRow()` (lib/ws.ts)
 *    échantillonne les champs connus et le rendu passe exclusivement par des
 *    nœuds texte React (aucun `dangerouslySetInnerHTML`, jamais) ;
 *  - la liste rendue est bornée (`MAX_RENDERED_ROWS`) en plus du tampon borné du
 *    client : personne ne peut faire exploser le DOM depuis le serveur ;
 *  - la clé API n'est jamais affichée ni journalisée ici (l'URL du WebSocket est
 *    construite par `lib/ws.ts` et n'apparaît dans aucun rendu).
 */
import clsx from 'clsx';
import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import type { JSX } from 'react';

import { EmptyState } from './EmptyState';
import { Button, CodeBlock, StatusPill } from './ui';
import { SeverityBadge } from './SeverityBadge';
import { formatClockTime, formatNumber, formatRelative } from '@/lib/format';
import type { LiveRow, LiveStreamStatus, UseLiveStreamResult } from '@/lib/ws';
import { DEFAULT_BUFFER_SIZE, toLiveRow, useLiveStream } from '@/lib/ws';
import type { LiveFrame, LiveFrameType } from '@/lib/types';
import { LIVE_FRAME_TYPES } from '@/lib/types';

/* -------------------------------------------------------------------------- */
/* Fournisseur                                                                 */
/* -------------------------------------------------------------------------- */

const LiveStreamContext = createContext<UseLiveStreamResult | null>(null);

export interface LiveStreamProviderProps {
  /** Périmètre imposé par la clé API (`whoami.tenant_id`), jamais saisi. */
  tenantId: string | null;
  children: ReactNode;
}

export function LiveStreamProvider(props: LiveStreamProviderProps): JSX.Element {
  // Tampon borné : au-delà, les frames les plus anciennes sont comptabilisées
  // comme perdues (`dropped`) plutôt que de croître sans limite.
  const stream = useLiveStream(props.tenantId, { bufferSize: DEFAULT_BUFFER_SIZE });
  return <LiveStreamContext.Provider value={stream}>{props.children}</LiveStreamContext.Provider>;
}

export function useLiveStreamContext(): UseLiveStreamResult {
  const context = useContext(LiveStreamContext);
  if (!context) {
    throw new Error('useLiveStreamContext() doit être utilisé dans <LiveStreamProvider>.');
  }
  return context;
}

/* -------------------------------------------------------------------------- */
/* État du flux                                                                */
/* -------------------------------------------------------------------------- */

interface StreamStatusMeta {
  label: string;
  dot: string;
  text: string;
}

export const STREAM_STATUS_META: Record<LiveStreamStatus, StreamStatusMeta> = {
  idle: { label: 'Flux inactif', dot: 'bg-slate-500', text: 'text-slate-400' },
  connecting: { label: 'Connexion…', dot: 'bg-amber-400', text: 'text-amber-300' },
  open: { label: 'Flux connecté', dot: 'bg-emerald-400', text: 'text-emerald-300' },
  reconnecting: { label: 'Reconnexion…', dot: 'bg-amber-400', text: 'text-amber-300' },
  closed: { label: 'Flux fermé', dot: 'bg-slate-500', text: 'text-slate-400' },
  unauthorized: { label: 'Flux refusé', dot: 'bg-rose-500', text: 'text-rose-300' },
  error: { label: 'Flux en erreur', dot: 'bg-rose-500', text: 'text-rose-300' },
};

export interface StreamStatusIndicatorProps {
  compact?: boolean;
  className?: string;
}

/** Indicateur d'en-tête : état, dernière réception, reconnexion manuelle. */
export function StreamStatusIndicator(props: StreamStatusIndicatorProps): JSX.Element {
  const { compact = false, className } = props;
  const stream = useLiveStreamContext();
  const meta = STREAM_STATUS_META[stream.status];
  const pulsing = stream.status === 'open' || stream.status === 'connecting' || stream.status === 'reconnecting';

  const title = [
    `État : ${meta.label}`,
    stream.attempts > 0 ? `tentatives : ${stream.attempts}` : null,
    stream.nextRetryMs !== null ? `prochaine tentative dans ${stream.nextRetryMs} ms` : null,
    stream.lastMessageAt !== null ? `dernier message : ${formatRelative(stream.lastMessageAt)}` : null,
    stream.lastError !== null ? `erreur : ${stream.lastError}` : null,
  ]
    .filter((part): part is string => part !== null)
    .join(' · ');

  return (
    <div className={clsx('flex items-center gap-2', className)} title={title}>
      <span
        className={clsx('soc-live-dot', meta.dot, !pulsing && 'after:hidden')}
        aria-hidden="true"
      />
      <span className={clsx('text-2xs font-medium', meta.text)} role="status" aria-live="polite">
        {meta.label}
        {stream.paused ? ' — en pause' : ''}
        {stream.buffered > 0 ? ` (+${stream.buffered})` : ''}
      </span>
      {compact ? null : (
        <Button size="sm" variant="ghost" onClick={stream.reconnect} title="Fermer et rouvrir la connexion">
          Reconnecter
        </Button>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Panneau journal                                                             */
/* -------------------------------------------------------------------------- */

/** Plafond de lignes effectivement montées dans le DOM. */
export const MAX_RENDERED_ROWS = 200;

const FRAME_TYPE_LABELS: Record<LiveFrameType, string> = {
  event: 'Événement',
  finding: 'Finding',
  action: 'Action',
  audit: 'Audit',
  heartbeat: 'Heartbeat',
};

const FRAME_TYPE_CLASSES: Record<LiveFrameType, string> = {
  event: 'border-slate-700 bg-slate-800/70 text-slate-300',
  finding: 'border-rose-800 bg-rose-950/60 text-rose-200',
  action: 'border-cyan-800 bg-cyan-950/50 text-cyan-200',
  audit: 'border-violet-800 bg-violet-950/50 text-violet-200',
  heartbeat: 'border-emerald-900 bg-emerald-950/40 text-emerald-200',
};

/** Frames retenues par défaut : les heartbeats ne sont pas du signal métier. */
const DEFAULT_VISIBLE_TYPES: readonly LiveFrameType[] = ['event', 'finding', 'action', 'audit'];

export interface LiveStreamProps {
  /** Hauteur maximale du tableau (défilement interne). */
  maxHeight?: number;
  className?: string;
}

export function LiveStream(props: LiveStreamProps): JSX.Element {
  const { maxHeight = 420, className } = props;
  const stream = useLiveStreamContext();
  const [visibleTypes, setVisibleTypes] = useState<readonly LiveFrameType[]>(DEFAULT_VISIBLE_TYPES);
  const [showHeartbeats, setShowHeartbeats] = useState(false);
  // L'expansion est mémorisée sur la **frame** et non sur son index d'affichage :
  // l'index se décale à chaque nouvelle frame, la référence d'objet non.
  const [expandedFrame, setExpandedFrame] = useState<LiveFrame | null>(null);

  const entries = useMemo(
    () => stream.frames.map((frame, index) => ({ frame, row: toLiveRow(frame, index) })),
    [stream.frames],
  );

  const filtered = useMemo(
    () =>
      entries
        .filter(({ row }) =>
          row.type === 'heartbeat' ? showHeartbeats : visibleTypes.includes(row.type),
        )
        // Plus récent en premier : en veille, l'œil reste en haut du tableau.
        .slice(-MAX_RENDERED_ROWS)
        .reverse(),
    [entries, showHeartbeats, visibleTypes],
  );

  const toggleType = useCallback((type: LiveFrameType) => {
    setVisibleTypes((previous) =>
      previous.includes(type) ? previous.filter((item) => item !== type) : [...previous, type],
    );
  }, []);

  return (
    <section className={clsx('soc-panel', className)}>
      <header className="soc-panel-header">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2>Flux temps réel</h2>
            <StreamStatusIndicator compact />
          </div>
          <p className="mt-0.5 text-2xs text-slate-400">
            {formatNumber(stream.received)} frames reçues · {formatNumber(stream.dropped)} perdues (tampon) ·{' '}
            {formatNumber(stream.invalidFrames)} illisibles · {formatNumber(stream.heartbeats)} heartbeats
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {stream.paused ? (
            <Button size="sm" variant="primary" onClick={stream.resume}>
              Reprendre
            </Button>
          ) : (
            <Button size="sm" variant="warn" onClick={stream.pause}>
              Pause
            </Button>
          )}
          <Button size="sm" variant="secondary" onClick={stream.reconnect}>
            Reconnecter
          </Button>
          <Button size="sm" variant="ghost" onClick={stream.clear}>
            Vider
          </Button>
        </div>
      </header>

      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 px-3 py-1.5">
        <span className="text-2xs uppercase tracking-wider text-slate-500">Types</span>
        {LIVE_FRAME_TYPES.map((type) => {
          const active = type === 'heartbeat' ? showHeartbeats : visibleTypes.includes(type);
          return (
            <button
              key={type}
              type="button"
              aria-pressed={active}
              onClick={() => (type === 'heartbeat' ? setShowHeartbeats((value) => !value) : toggleType(type))}
              className={clsx(
                'rounded border px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide transition-colors',
                active ? FRAME_TYPE_CLASSES[type] : 'border-slate-800 bg-slate-950 text-slate-500 hover:text-slate-300',
              )}
            >
              {FRAME_TYPE_LABELS[type]}
            </button>
          );
        })}
        {stream.paused ? (
          <span className="ml-auto text-2xs text-amber-300">
            En pause — {formatNumber(stream.buffered)} frame(s) en tampon
          </span>
        ) : null}
      </div>

      <div className="soc-panel-body pt-2">
        {filtered.length === 0 ? (
          <EmptyState
            title="Aucune frame à afficher"
            description={
              stream.status === 'unauthorized'
                ? 'Le serveur a refusé le flux : clé révoquée ou tenant hors périmètre. Reconnectez-vous avec une clé valide.'
                : 'Le flux est ouvert mais aucune frame ne correspond aux types sélectionnés. Les heartbeats sont masqués par défaut.'
            }
          />
        ) : (
          <>
            <div className="overflow-auto" style={{ maxHeight: `${maxHeight}px` }}>
              <table className="soc-table">
                <caption>
                  {filtered.length} ligne(s) affichée(s) — {MAX_RENDERED_ROWS} au maximum, plus récentes en premier
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Heure</th>
                    <th scope="col">Type</th>
                    <th scope="col">Sévérité</th>
                    <th scope="col">Objet</th>
                    <th scope="col">Détail</th>
                    <th scope="col" />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(({ frame, row }) => (
                    <StreamRow
                      key={row.key}
                      row={row}
                      expanded={expandedFrame === frame}
                      onToggle={() =>
                        setExpandedFrame((previous) => (previous === frame ? null : frame))
                      }
                    />
                  ))}
                </tbody>
              </table>
            </div>
            {entries.length > filtered.length ? (
              <p className="mt-1 text-2xs text-slate-500">
                {formatNumber(entries.length - filtered.length)} frame(s) plus ancienne(s) non affichée(s) — le
                tampon est borné à {formatNumber(DEFAULT_BUFFER_SIZE)}.
              </p>
            ) : null}
          </>
        )}
      </div>
    </section>
  );
}

interface StreamRowProps {
  row: LiveRow;
  expanded: boolean;
  onToggle: () => void;
}

function StreamRow(props: StreamRowProps): JSX.Element {
  const { row, expanded, onToggle } = props;

  return (
    <>
      <tr
        className="soc-live-row cursor-pointer"
        onClick={onToggle}
        data-tone={row.severity === 'critical' ? 'danger' : undefined}
      >
        <td className="whitespace-nowrap font-mono text-2xs text-slate-400">{formatClockTime(row.ts)}</td>
        <td>
          <span
            className={clsx(
              'rounded border px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide',
              FRAME_TYPE_CLASSES[row.type],
            )}
          >
            {FRAME_TYPE_LABELS[row.type]}
          </span>
        </td>
        <td>{row.type === 'finding' || row.type === 'event' ? <SeverityBadge severity={row.severity} hint /> : <span className="text-slate-600">—</span>}</td>
        <td className="max-w-[22rem] truncate" title={row.title}>
          {row.title}
        </td>
        <td className="max-w-[26rem] truncate text-2xs text-slate-400" title={row.summary}>
          {row.summary !== '' ? row.summary : <span className="text-slate-600">—</span>}
          {row.status ? (
            <StatusPill className="ml-1 border-slate-700 bg-slate-800/70 text-slate-300" label={row.status} />
          ) : null}
        </td>
        <td>
          <Button size="sm" variant="ghost" onClick={onToggle} aria-expanded={expanded}>
            {expanded ? 'Masquer' : 'JSON'}
          </Button>
        </td>
      </tr>
      {expanded ? (
        <tr>
          <td colSpan={6} className="bg-slate-950/60">
            <p className="mb-1 text-2xs text-slate-500">
              Charge brute de la frame — affichée en texte, jamais interprétée comme du HTML.
            </p>
            <CodeBlock value={row.raw} maxHeight={220} />
          </td>
        </tr>
      ) : null}
    </>
  );
}
