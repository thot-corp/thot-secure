"""Artefacts exploitables par des professionnels : rapports et exports SIEM.

Un finding qui reste dans une interface ne sert à rien. Thot Secure produit donc des
livrables qui circulent là où le travail se fait réellement :

* **Markdown** : à coller dans un ticket, une PR ou un post-mortem ;
* **HTML** : autonome, imprimable en PDF, sans dépendance réseau ;
* **JSON** : pour l'automatisation ;
* **SARIF 2.1.0** : intégration native dans GitHub Code Scanning (les findings apparaissent
  dans l'onglet Security, avec leur score) ;
* **CEF / JSONL** : export vers un SIEM (Splunk, QRadar, ArcSight, Elastic).

Toutes les valeurs issues des événements sont **échappées** : un finding contient par
construction des charges d'attaque, et un rapport HTML est une surface XSS.
"""

from __future__ import annotations

import json
from typing import Any

from ..core.models import Action, AuditRecord, Finding, Tenant
from ..core.util import canonical_json, humanize_duration, iso_z, strip_html, utcnow
from ..scoring.risk import risk_band

TOOL_NAME = "Thot Secure"
TOOL_VERSION = "0.1.0"
TOOL_URL = "https://thotsecure.dev"

#: Correspondance sévérité → niveau SARIF.
SARIF_LEVELS: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


# --------------------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------------------


def finding_to_markdown(
    finding: Finding,
    *,
    tenant: Tenant | None = None,
    actions: list[Action] | None = None,
    audit: list[AuditRecord] | None = None,
) -> str:
    """Rapport Markdown prêt à coller dans un ticket."""
    actions = actions or []
    audit = audit or []
    lines: list[str] = [
        f"# {finding.title}",
        "",
        f"**Identifiant du finding** : `{finding.finding_id}`  ",
        f"**Règle** : `{finding.rule_id}` — {finding.rule_name}  ",
        f"**Sévérité** : `{finding.severity}`  ",
        f"**Score de risque** : **{finding.risk_score:.1f}/100** "
        f"(bande : {risk_band(finding.risk_score)})  ",
        f"**Confiance de la règle** : {finding.confidence:.0%}  ",
        f"**Statut** : `{finding.status}`  ",
        f"**Occurrences** : {finding.count}  ",
        f"**Première observation** : {iso_z(finding.first_seen)}  ",
        f"**Dernière observation** : {iso_z(finding.last_seen)}  ",
        f"**Durée d'observation** : "
        f"{humanize_duration((finding.last_seen - finding.first_seen).total_seconds())}  ",
    ]
    if tenant is not None:
        lines.extend(
            [
                f"**Tenant** : `{tenant.tenant_id}` ({tenant.name or 'sans nom'})  ",
                f"**Mode d'autonomie** : `{tenant.mode}` — dry-run : "
                f"{'**ACTIF**' if tenant.dry_run else 'désactivé'}  ",
            ]
        )
    if finding.mitre:
        lines.append(f"**MITRE ATT&CK** : {', '.join(f'`{item}`' for item in finding.mitre)}  ")
    if finding.tags:
        lines.append(f"**Étiquettes** : {', '.join(f'`{tag}`' for tag in finding.tags)}")

    lines += [
        "",
        "## Description",
        "",
        finding.description or "_Aucune description fournie par la règle._",
    ]

    remediation = finding.remediation or "_Aucune remédiation documentée._"
    lines += ["", "## Remédiation recommandée", "", remediation]

    risk = finding.evidence.get("risk") or {}
    if risk:
        lines += ["", "## Calcul du score de risque", "", f"`{risk.get('formula', '')}`", ""]
        for step in risk.get("steps") or []:
            lines.append(f"- {step}")
        lines.append(f"- **Score final : {risk.get('final', finding.risk_score)}**")

    threshold = finding.evidence.get("threshold") or {}
    if threshold and threshold.get("count", 1) > 1:
        lines += [
            "",
            "## Agrégation",
            "",
            f"- Seuil déclencheur : **{threshold.get('count')} occurrences** "
            f"sur {threshold.get('window_seconds')}s",
            f"- Occurrences observées dans la fenêtre : {threshold.get('observed')}",
        ]

    samples = finding.evidence.get("samples") or []
    if samples:
        lines += ["", "## Preuves (échantillon)", ""]
        for sample in samples[-5:]:
            lines.append(f"### {sample.get('ts', 'n/a')} — `{sample.get('kind', '')}`")
            source = sample.get("source") or {}
            lines.append(
                f"Source : `{source.get('type', '')}`"
                + (f" / `{source.get('host')}`" if source.get("host") else "")
            )
            labels = sample.get("labels") or {}
            if labels:
                lines.append("")
                lines.append("| champ | valeur |")
                lines.append("| --- | --- |")
                for key, value in sorted(labels.items()):
                    lines.append(f"| `{key}` | `{_md_cell(value)}` |")
            payload = sample.get("payload") or {}
            if payload:
                lines.append("")
                for key, value in sorted(payload.items()):
                    lines.append(f"- `{key}` : `{_md_cell(value)}`")
            lines.append("")

    false_positives = finding.evidence.get("false_positives") or []
    if false_positives:
        lines += ["", "## Faux positifs connus", ""]
        lines += [f"- {item}" for item in false_positives]

    if actions:
        lines += [
            "",
            "## Actions déclenchées",
            "",
            "| action | playbook | statut | dry-run | cible |",
            "| --- | --- | --- | --- | --- |",
        ]
        for action in actions:
            lines.append(
                f"| `{action.action_id}` | `{action.playbook}` | `{action.status}` | "
                f"{'oui' if action.dry_run else 'non'} | `{action.target}` |"
            )

    if audit:
        lines += [
            "",
            "## Piste d'audit",
            "",
            "| seq | horodatage | acteur | action |",
            "| --- | --- | --- | --- |",
        ]
        for record in audit[:20]:
            lines.append(
                f"| {record.seq} | {iso_z(record.ts)} | `{record.actor}` | `{record.action}` |"
            )
        lines += [
            "",
            "> L'intégrité de cette piste se vérifie avec "
            "`thotsecure audit verify` (chaîne de hachage).",
        ]

    lines += [
        "",
        "---",
        "",
        f"_Rapport généré par {TOOL_NAME} {TOOL_VERSION} le {iso_z(utcnow())}._  ",
        "_Action défensive uniquement — aucun test offensif n'a été effectué._",
    ]
    return "\n".join(lines)


def _md_cell(value: Any) -> str:
    text = str(value).replace("|", "\\|").replace("\n", " ").replace("`", "'")
    return text[:300]


# --------------------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------------------


HTML_TEMPLATE = (
    """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; """
    """margin: 0; background: #0b1120; color: #e2e8f0; }}
  main {{ max-width: 960px; margin: 0 auto; padding: 40px 24px 80px; }}
  h1 {{ font-size: 1.7rem; line-height: 1.25; margin: 0 0 8px; }}
  h2 {{ font-size: 1.1rem; margin-top: 36px; """
    """border-bottom: 1px solid #1e293b; padding-bottom: 6px; }}
  .meta {{ display: grid; grid-template-columns: max-content 1fr; """
    """gap: 4px 16px; margin: 16px 0; font-size: .9rem; }}
  .meta dt {{ color: #94a3b8; }}
  .meta dd {{ margin: 0; }}
  code, pre {{ font-family: ui-monospace, "Cascadia Code", Consolas, monospace; """
    """font-size: .85rem; }}
  code {{ background: #111c33; padding: 1px 5px; border-radius: 4px; }}
  pre {{ background: #111c33; padding: 12px; border-radius: 6px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: .85rem; }}
  th, td {{ text-align: left; padding: 6px 8px; """
    """border-bottom: 1px solid #1e293b; vertical-align: top; }}
  th {{ color: #94a3b8; font-weight: 600; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 999px; """
    """font-size: .75rem; font-weight: 700; text-transform: uppercase; }}
  .sev-critical {{ background: #7f1d1d; color: #fecaca; }}
  .sev-high {{ background: #9a3412; color: #fed7aa; }}
  .sev-medium {{ background: #854d0e; color: #fef08a; }}
  .sev-low {{ background: #164e63; color: #a5f3fc; }}
  .sev-info {{ background: #1e293b; color: #cbd5e1; }}
  .gauge {{ height: 10px; background: #1e293b; border-radius: 999px; """
    """overflow: hidden; margin: 8px 0 4px; }}
  .gauge > span {{ display: block; height: 100%; }}
  .warn {{ background: #422006; border-left: 3px solid #f59e0b; """
    """padding: 12px 16px; border-radius: 4px; margin: 16px 0; }}
  footer {{ margin-top: 48px; color: #64748b; font-size: .8rem; }}
</style>
</head>
<body>
<main>
  <h1>{title}</h1>
  <p><span class="badge sev-{severity}">{severity}</span>
     &nbsp;score de risque <strong>{risk_score:.1f}/100</strong> ({band})</p>
  <div class="gauge"><span style="width:{risk_pct}%;background:{gauge_color}"></span></div>
  <dl class="meta">{meta}</dl>
  {dry_run_banner}
  <h2>Description</h2>
  <p>{description}</p>
  <h2>Remédiation recommandée</h2>
  <p>{remediation}</p>
  {risk_block}
  {evidence_block}
  {actions_block}
  {audit_block}
  <footer>
    Rapport généré par {tool} {version} le {generated_at}.<br>
    Outil <strong>strictement défensif</strong> : aucun test offensif, aucune exploitation,
    aucun accès à un système tiers n'a été effectué.<br>
    Adresses de dons officielles : BTC <code>{btc}</code> — SOL <code>{sol}</code>.
    Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le
    dépôt officiel : seule la source officielle fait foi.
  </footer>
</main>
</body>
</html>
"""
)


def finding_to_html(
    finding: Finding,
    *,
    tenant: Tenant | None = None,
    actions: list[Action] | None = None,
    audit: list[AuditRecord] | None = None,
) -> str:
    """Rapport HTML autonome (aucune ressource distante, imprimable en PDF)."""
    from .. import FUNDING_ADDRESSES

    actions = actions or []
    audit = audit or []
    meta_rows = [
        ("Identifiant", f"<code>{strip_html(finding.finding_id)}</code>"),
        ("Règle", f"<code>{strip_html(finding.rule_id)}</code> — {strip_html(finding.rule_name)}"),
        ("Occurrences", str(finding.count)),
        ("Première observation", iso_z(finding.first_seen)),
        ("Dernière observation", iso_z(finding.last_seen)),
    ]
    if tenant is not None:
        meta_rows.append(("Tenant", f"<code>{strip_html(tenant.tenant_id)}</code>"))
        meta_rows.append(("Mode d'autonomie", strip_html(tenant.mode)))
    if finding.mitre:
        meta_rows.append(("MITRE ATT&CK", ", ".join(strip_html(item) for item in finding.mitre)))
    if finding.tags:
        meta_rows.append(
            ("Étiquettes", ", ".join(f"<code>{strip_html(tag)}</code>" for tag in finding.tags))
        )
    meta_html = "".join(f"<dt>{key}</dt><dd>{value}</dd>" for key, value in meta_rows)

    risk = finding.evidence.get("risk") or {}
    risk_block = ""
    if risk:
        steps = "".join(f"<li>{strip_html(step)}</li>" for step in risk.get("steps") or [])
        risk_block = (
            "<h2>Calcul du score de risque</h2>"
            f"<pre>{strip_html(risk.get('formula', ''))}</pre><ul>{steps}</ul>"
        )

    evidence_block = ""
    samples = finding.evidence.get("samples") or []
    if samples:
        rows = []
        for sample in samples[-10:]:
            labels = sample.get("labels") or {}
            payload = sample.get("payload") or {}
            cells = "".join(
                f"<tr><td><code>{strip_html(key)}</code></td><td><code>{strip_html(value)}</code></td></tr>"
                for key, value in sorted({**labels, **payload}.items())
            )
            rows.append(
                f"<h3><code>{strip_html(sample.get('kind', ''))}</code> — "
                f"{strip_html(sample.get('ts', ''))}</h3><table>{cells}</table>"
            )
        evidence_block = "<h2>Preuves (échantillon)</h2>" + "".join(rows)

    actions_block = ""
    if actions:
        rows = "".join(
            f"<tr><td><code>{strip_html(action.action_id)}</code></td>"
            f"<td><code>{strip_html(action.playbook)}</code></td>"
            f"<td>{strip_html(action.status)}</td>"
            f"<td>{'oui' if action.dry_run else '<strong>non</strong>'}</td>"
            f"<td><code>{strip_html(str(action.target))}</code></td></tr>"
            for action in actions
        )
        actions_block = (
            "<h2>Actions déclenchées</h2><table><tr><th>action</th><th>playbook</th>"
            f"<th>statut</th><th>dry-run</th><th>cible</th></tr>{rows}</table>"
        )

    audit_block = ""
    if audit:
        rows = "".join(
            f"<tr><td>{record.seq}</td><td>{iso_z(record.ts)}</td>"
            f"<td><code>{strip_html(record.actor)}</code></td>"
            f"<td><code>{strip_html(record.action)}</code></td></tr>"
            for record in audit[:25]
        )
        audit_block = (
            "<h2>Piste d'audit</h2><table><tr><th>seq</th><th>horodatage</th><th>acteur</th>"
            f"<th>action</th></tr>{rows}</table>"
            "<p>Intégrité vérifiable par chaîne de hachage : "
            "<code>thotsecure audit verify</code>.</p>"
        )

    dry_run_banner = ""
    if tenant is not None and tenant.dry_run:
        dry_run_banner = (
            '<div class="warn"><strong>Mode simulation actif.</strong> Les actions décrites '
            "ci-dessous n'ont pas eu d'effet réel sur l'infrastructure "
            "(<code>THOT_DRY_RUN=true</code>).</div>"
        )

    score = finding.risk_score
    gauge_color = (
        "#dc2626"
        if score >= 85
        else "#ea580c"
        if score >= 70
        else "#ca8a04"
        if score >= 45
        else "#0891b2"
    )

    return HTML_TEMPLATE.format(
        title=strip_html(finding.title),
        severity=strip_html(finding.severity),
        risk_score=finding.risk_score,
        risk_pct=min(100.0, max(2.0, score)),
        band=strip_html(risk_band(score)),
        gauge_color=gauge_color,
        meta=meta_html,
        dry_run_banner=dry_run_banner,
        description=strip_html(finding.description) or "<em>Aucune description fournie.</em>",
        remediation=strip_html(finding.remediation) or "<em>Aucune remédiation documentée.</em>",
        risk_block=risk_block,
        evidence_block=evidence_block,
        actions_block=actions_block,
        audit_block=audit_block,
        tool=TOOL_NAME,
        version=TOOL_VERSION,
        generated_at=iso_z(utcnow()),
        btc=FUNDING_ADDRESSES["BTC"],
        sol=FUNDING_ADDRESSES["SOL"],
    )


# --------------------------------------------------------------------------------------
# JSON / SARIF / CEF
# --------------------------------------------------------------------------------------


def finding_to_json(
    finding: Finding, *, tenant: Tenant | None = None, actions: list[Action] | None = None
) -> str:
    payload: dict[str, Any] = {
        "finding": finding.model_dump(mode="json"),
        "generated_at": iso_z(utcnow()),
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "url": TOOL_URL},
    }
    if tenant is not None:
        payload["tenant"] = tenant.model_dump(mode="json")
    if actions:
        payload["actions"] = [action.model_dump(mode="json") for action in actions]
    return json.dumps(payload, indent=2, ensure_ascii=False)


def findings_to_sarif(findings: list[Finding], *, tenant_id: str | None = None) -> str:
    """Export SARIF 2.1.0 pour GitHub Code Scanning et la plupart des IDE."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.rule_name or finding.rule_id},
                "fullDescription": {
                    "text": finding.description or finding.rule_name or finding.rule_id
                },
                "help": {
                    "text": finding.remediation or "Aucune remédiation documentée.",
                    "markdown": finding.remediation or "Aucune remédiation documentée.",
                },
                "defaultConfiguration": {"level": SARIF_LEVELS.get(finding.severity, "warning")},
                "properties": {
                    "tags": list(finding.tags),
                    "security-severity": f"{finding.risk_score / 10:.1f}",
                },
            }
        sample_host = ""
        samples = finding.evidence.get("samples") or []
        if samples:
            source = samples[-1].get("source") or {}
            sample_host = str(
                source.get("host") or (samples[-1].get("labels") or {}).get("host") or ""
            )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVELS.get(finding.severity, "warning"),
                "message": {
                    "text": f"{finding.title} (score de risque {finding.risk_score:.1f}/100)"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": sample_host or (tenant_id or finding.tenant_id),
                                "description": {"text": "actif concerné"},
                            }
                        },
                        "logicalLocations": [
                            {"fullyQualifiedName": finding.finding_id, "kind": "finding"}
                        ],
                    }
                ],
                "partialFingerprints": {
                    "thotSecureFindingId/v1": finding.finding_id,
                    "thotSecureDedup/v1": finding.dedup_key or finding.finding_id,
                },
                "properties": {
                    "tenant_id": finding.tenant_id,
                    "finding_id": finding.finding_id,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "count": finding.count,
                    "first_seen": iso_z(finding.first_seen),
                    "last_seen": iso_z(finding.last_seen),
                    "mitre": list(finding.mitre),
                },
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URL,
                        "rules": sorted(rules.values(), key=lambda item: item["id"]),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": iso_z(utcnow()),
                        "properties": {"tenant_id": tenant_id or ""},
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def finding_to_cef(finding: Finding) -> str:
    """Ligne CEF pour un SIEM (ArcSight, QRadar, Splunk via connecteur CEF)."""
    severity_map = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
    level = severity_map.get(finding.severity, 5)
    extension_parts = [
        f"rt={_cef(iso_z(finding.last_seen))}",
        f"externalId={_cef(finding.finding_id)}",
        f"cs1Label=tenant cs1={_cef(finding.tenant_id)}",
        f"cs2Label=ruleId cs2={_cef(finding.rule_id)}",
        f"cs3Label=riskScore cs3={finding.risk_score}",
        f"cs4Label=status cs4={_cef(finding.status)}",
        f"cs5Label=tags cs5={_cef(','.join(finding.tags))}",
        f"cnt={finding.count}",
        f"msg={_cef(finding.title)}",
        f"cs6Label=remediation cs6={_cef(finding.remediation[:300])}",
    ]
    return (
        f"CEF:0|ThotSecure|ThotSecure|{TOOL_VERSION}|{_cef(finding.rule_id)}"
        f"|{_cef(finding.rule_name or finding.rule_id)}|{level}|{' '.join(extension_parts)}"
    )


def findings_to_cef(findings: list[Finding]) -> str:
    return "\n".join(finding_to_cef(finding) for finding in findings)


def findings_to_jsonl(findings: list[Finding]) -> str:
    return "\n".join(canonical_json(finding.model_dump(mode="json")) for finding in findings)


def _cef(value: str) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def render(
    finding: Finding,
    fmt: str = "md",
    *,
    tenant: Tenant | None = None,
    actions: list[Action] | None = None,
    audit: list[AuditRecord] | None = None,
) -> tuple[str, str]:
    """Retourne ``(contenu, type MIME)`` pour le format demandé."""
    normalized = (fmt or "md").lower()
    if normalized in {"md", "markdown"}:
        return finding_to_markdown(
            finding, tenant=tenant, actions=actions, audit=audit
        ), "text/markdown; charset=utf-8"
    if normalized in {"html", "htm"}:
        return finding_to_html(
            finding, tenant=tenant, actions=actions, audit=audit
        ), "text/html; charset=utf-8"
    if normalized == "json":
        return finding_to_json(finding, tenant=tenant, actions=actions), "application/json"
    if normalized == "sarif":
        return findings_to_sarif([finding], tenant_id=finding.tenant_id), "application/sarif+json"
    if normalized == "cef":
        return finding_to_cef(finding), "text/plain; charset=utf-8"
    raise ValueError(f"format de rapport non supporté: {fmt}")


__all__ = [
    "SARIF_LEVELS",
    "TOOL_NAME",
    "TOOL_URL",
    "TOOL_VERSION",
    "finding_to_cef",
    "finding_to_html",
    "finding_to_json",
    "finding_to_markdown",
    "findings_to_cef",
    "findings_to_jsonl",
    "findings_to_sarif",
    "render",
]
