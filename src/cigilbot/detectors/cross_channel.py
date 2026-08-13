"""Cross-Channel Bot Fingerprint (направление 03 master-plan.html).

Аккаунт, забаненный на одном канале оператора, получает risk-boost при
появлении на другом. known_bad_actor_ids приходит уже готовым множеством
в DetectionContext (см. base.py) — детектор сам не делает I/O, только
сверяет event.user_id с тем, что движок закешировал через
sync_known_bad_actors(). SignalFamily.HISTORY, не отдельное семейство:
бан на другом канале — тот же факт "что было раньше", что и
prior_timeouts/prior_warnings, просто зафиксированный не здесь.
"""

from __future__ import annotations

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "cross_channel"


def detect(ctx: DetectionContext) -> list[Signal]:
    cfg = ctx.config.detectors.cross_channel
    if not cfg.enabled:
        return []

    if ctx.event.user_id not in ctx.known_bad_actor_ids:
        return []

    return [
        Signal(
            name="known_bad_actor",
            family=SignalFamily.HISTORY,
            weight=ctx.config.weight("known_bad_actor").weight,
            value=1.0,
            evidence="аккаунт уже забанен на другом канале оператора",
        )
    ]
