/**
 * Téléchargement de fichiers produits par l'API (rapports de finding, export
 * d'audit). Le contenu est toujours traité comme **donnée opaque** : on ne
 * l'injecte jamais dans le DOM, on le remet au navigateur via un `Blob`.
 */
import type { AuditExportFormat, ReportFormat } from './types';

const REPORT_MIME: Record<ReportFormat, string> = {
  md: 'text/markdown;charset=utf-8',
  html: 'text/html;charset=utf-8',
  json: 'application/json;charset=utf-8',
  sarif: 'application/sarif+json;charset=utf-8',
};

const AUDIT_MIME: Record<AuditExportFormat, string> = {
  jsonl: 'application/x-ndjson;charset=utf-8',
  cef: 'text/plain;charset=utf-8',
};

/** Sanitise un identifiant pour un nom de fichier (pas de traversée de chemin). */
function safeFileNamePart(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80);
}

export function reportFileName(findingId: string, format: ReportFormat): string {
  return `thotsecure-finding-${safeFileNamePart(findingId)}.${format}`;
}

export function auditExportFileName(format: AuditExportFormat): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `thotsecure-audit-${stamp}.${format === 'cef' ? 'cef' : 'jsonl'}`;
}

export function reportMimeType(format: ReportFormat): string {
  return REPORT_MIME[format];
}

export function auditMimeType(format: AuditExportFormat): string {
  return AUDIT_MIME[format];
}

/**
 * Déclenche un téléchargement côté navigateur. No-op silencieux hors DOM
 * (tests, rendu serveur).
 */
export function downloadText(content: string, fileName: string, mimeType: string): void {
  if (typeof document === 'undefined' || typeof URL === 'undefined') return;
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = 'noopener';
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Laisse au navigateur le temps d'amorcer le téléchargement.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
