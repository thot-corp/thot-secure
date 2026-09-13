"""Limitation de débit des appels API (garde-fou anti-abus).

Objectif : qu'un client fautif (ou un collecteur mal configuré) ne puisse pas saturer le
service. Un seau à jetons par clé API, en mémoire, sans dépendance externe.

Choix assumé : la limite est **par processus**. En déploiement multi-réplicas, chaque réplique
applique sa propre limite — soit ``N x THOT_RATE_LIMIT_PER_MIN``. C'est documenté
explicitement dans ``docs/operations/deployment.md`` : mieux vaut une limite approximative
documentée qu'une limite exacte qui exige Redis.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from ..core.errors import RateLimitedError


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float
    capacity: float


class RateLimiter:
    """Seau à jetons par identifiant (clé API, adresse IP du client…)."""

    def __init__(self, *, per_minute: int = 600, burst: int | None = None) -> None:
        self.per_minute = max(1, int(per_minute))
        self.rate_per_second = self.per_minute / 60.0
        self.burst = float(burst if burst is not None else max(10, self.per_minute // 6))
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self.allowed = 0
        self.rejected = 0

    def check(self, identifier: str, *, cost: float = 1.0) -> None:
        """Consomme ``cost`` jetons. Lève ``RateLimitedError`` si le seau est vide."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(identifier)
            if bucket is None:
                bucket = _Bucket(tokens=self.burst, updated_at=now, capacity=self.burst)
                self._buckets[identifier] = bucket
            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(bucket.capacity, bucket.tokens + elapsed * self.rate_per_second)
            bucket.updated_at = now

            # Purge opportuniste : sans cela, un attaquant qui varie son identifiant ferait
            # croître la mémoire indéfiniment (fuite mémoire déclenchable à distance).
            if len(self._buckets) > 10_000:
                self._evict_stale(now)

            if bucket.tokens < cost:
                self.rejected += 1
                retry_after = max(1, int((cost - bucket.tokens) / self.rate_per_second))
                raise RateLimitedError(
                    "trop de requêtes : ralentissez ou augmentez THOT_RATE_LIMIT_PER_MIN",
                    retry_after=retry_after,
                    details={"limit_per_minute": self.per_minute},
                )
            bucket.tokens -= cost
            self.allowed += 1

    def _evict_stale(self, now: float) -> None:
        stale = [key for key, bucket in self._buckets.items() if now - bucket.updated_at > 300]
        for key in stale:
            self._buckets.pop(key, None)

    def stats(self) -> dict[str, int]:
        return {
            "allowed": self.allowed,
            "rejected": self.rejected,
            "tracked_identifiers": len(self._buckets),
            "limit_per_minute": self.per_minute,
        }


__all__ = ["RateLimiter"]
