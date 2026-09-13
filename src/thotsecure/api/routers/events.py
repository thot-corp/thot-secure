"""Ingestion et consultation des événements."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Query, Request, status
from pydantic import ValidationError as PydanticValidationError

from ...core.errors import ValidationError
from ...core.models import Event
from ...core.util import parse_dt
from ..deps import PrincipalDep, ServiceDep, client_identifier, require

router = APIRouter(prefix="/api/v1/events", tags=["événements"])


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingérer un ou plusieurs événements",
    response_model=None,
)
def ingest_events(
    request: Request,
    service: ServiceDep,
    principal: PrincipalDep,
    payload: Any = Body(
        ...,
        openapi_examples={
            "evenement_unique": {
                "summary": "Un événement",
                "value": {
                    "kind": "http.request",
                    "source": {"type": "webhook", "host": "shop.acme.fr"},
                    "labels": {"src_ip": "203.0.113.9", "path": "/login?id=1 UNION SELECT 1--"},
                    "payload": {"status": 403},
                },
            },
            "lot": {
                "summary": "Un lot d'événements",
                "value": {"events": [{"kind": "log.line", "labels": {"message": "test"}}]},
            },
        },
    ),
) -> dict[str, Any]:
    """Ingère des événements et retourne les findings, décisions et actions déclenchés.

    Points de conception :

    * le ``tenant_id`` est **imposé par la clé API** : un collecteur ne peut pas écrire dans le
      tenant d'un autre, même en le demandant explicitement ;
    * les erreurs de validation sont **collectées** (et non bloquantes) : un lot de 500
      événements dont un est malformé ne doit pas être perdu en entier ;
    * la réponse contient le résultat complet du pipeline — l'appelant sait immédiatement si
      son événement a déclenché une action.
    """
    require("write:events")(principal)

    # Limitation de débit : l'ingestion est le point d'entrée le plus exposé au volume.
    service.rate_limiter.check(client_identifier(request, principal))

    raw_events = _extract_events(payload)
    if not raw_events:
        raise ValidationError("aucun événement fourni")
    if len(raw_events) > service.settings.max_ingest_batch:
        raise ValidationError(
            f"lot trop volumineux : {len(raw_events)} > {service.settings.max_ingest_batch}",
            details={"max_batch": service.settings.max_ingest_batch},
        )

    events: list[Event] = []
    errors: list[dict[str, Any]] = []
    for index, item in enumerate(raw_events):
        if not isinstance(item, dict):
            errors.append({"index": index, "error": "not_an_object"})
            continue
        # Le tenant est forcé depuis la clé : aucune confiance n'est accordée au client.
        candidate = {**item, "tenant_id": principal.tenant_id}
        try:
            events.append(Event(**candidate))
        except PydanticValidationError as exc:
            errors.append(
                {
                    "index": index,
                    "error": "validation_error",
                    "details": [
                        {"location": ".".join(str(part) for part in error.get("loc", ())), "message": error.get("msg")}
                        for error in exc.errors()[:5]
                    ],
                }
            )

    if errors and not events:
        raise ValidationError("aucun événement valide dans le lot", details={"errors": errors[:20]})

    outcome = service.pipeline.ingest(
        events, actor=principal.actor, actor_role=principal.role
    )
    service.metrics.inc("thotsecure_events_ingested_total", len(events), tenant=principal.tenant_id)
    if outcome.result.rejected:
        service.metrics.inc(
            "thotsecure_events_rejected_total", outcome.result.rejected, tenant=principal.tenant_id
        )
    for finding in outcome.findings:
        service.metrics.inc(
            "thotsecure_findings_total", 1, tenant=finding.tenant_id, severity=finding.severity
        )
    for decision in outcome.decisions:
        service.metrics.inc("thotsecure_decisions_total", 1, decision=decision.decision)

    response = outcome.result.model_dump(mode="json")
    if errors:
        response["errors"] = [*response.get("errors", []), *errors[:50]]
    response["actions"] = [
        {
            "action_id": action.action_id,
            "playbook": action.playbook,
            "status": action.status,
            "dry_run": action.dry_run,
        }
        for action in outcome.actions
    ]
    return response


@router.get("", summary="Lister les événements")
def list_events(
    service: ServiceDep,
    principal: PrincipalDep,
    kind: list[str] | None = Query(default=None),
    source_type: list[str] | None = Query(default=None),
    since: str | None = None,
    until: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = None,
) -> dict[str, Any]:
    require("read:events")(principal)
    events, next_cursor = service.store.query_events(
        principal.tenant_id,
        kinds=kind,
        source_types=source_type,
        since=parse_dt(since),
        until=parse_dt(until),
        q=q,
        limit=limit,
        cursor=cursor,
    )
    return {
        "items": [event.model_dump(mode="json") for event in events],
        "count": len(events),
        "next_cursor": next_cursor,
    }


@router.get("/{event_id}", summary="Détail d'un événement")
def get_event(event_id: str, service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:events")(principal)
    from ...core.errors import NotFoundError

    event = service.store.get_event(principal.tenant_id, event_id)
    if event is None:
        # Un événement d'un autre tenant est indistinguable d'un événement inexistant :
        # on ne révèle jamais l'existence d'une ressource hors périmètre.
        raise NotFoundError(f"événement introuvable: {event_id}", details={"event_id": event_id})
    return event.model_dump(mode="json")


def _extract_events(payload: Any) -> list[Any]:
    """Accepte un événement seul, une liste, ou un objet ``{"events": [...]}``."""
    if isinstance(payload, dict):
        if "events" in payload and isinstance(payload["events"], list):
            return list(payload["events"])
        return [payload]
    if isinstance(payload, list):
        return list(payload)
    return []


__all__ = ["router"]
