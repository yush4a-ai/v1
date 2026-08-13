"""Ссылки: сам факт, шортенеры, известные скам-домены, общие ссылки у многих.

link_present сам по себе имеет умеренный вес — зрители легитимно кидают
ссылки на клипы, соцсети, ролики. Опасность — не ссылка, а то, что её же
только что писали несколько РАЗНЫХ пользователей подряд (shared_link_multi_user).
"""

from __future__ import annotations

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "links"


def detect(ctx: DetectionContext) -> list[Signal]:
    cfg = ctx.config.detectors.links
    if not cfg.enabled or not ctx.fingerprint.has_links:
        return []

    signals: list[Signal] = []
    domains = ctx.fingerprint.domains

    scam_hit = next((d for d in domains if d in cfg.known_scam_domains), None)
    if scam_hit:
        signals.append(
            Signal(
                name="known_scam_domain",
                family=SignalFamily.CONTENT,
                weight=ctx.config.weight("known_scam_domain").weight,
                value=1.0,
                evidence=f"ссылка на известный скам-домен {scam_hit}",
            )
        )
    else:
        signals.append(
            Signal(
                name="link_present",
                family=SignalFamily.CONTENT,
                weight=ctx.config.weight("link_present").weight,
                value=1.0,
                evidence=f"сообщение содержит ссылку ({', '.join(domains)})",
            )
        )

    if any(link.is_shortener for link in ctx.fingerprint.links):
        signals.append(
            Signal(
                name="url_shortener",
                family=SignalFamily.CONTENT,
                weight=ctx.config.weight("url_shortener").weight,
                value=1.0,
                evidence="ссылка через сокращатель — настоящий адрес скрыт",
            )
        )

    recent = ctx.window.recent(cfg.shared_link_window_seconds, now=ctx.event.timestamp)
    for domain in domains:
        users_with_domain = {
            e.event.user_id
            for e in recent
            if e.event.user_id != ctx.event.user_id and domain in e.fingerprint.domains
        }
        if len(users_with_domain) + 1 >= cfg.shared_link_min_users:
            signals.append(
                Signal(
                    name="shared_link_multi_user",
                    family=SignalFamily.NETWORK,
                    weight=ctx.config.weight("shared_link_multi_user").weight,
                    value=min(1.0, (len(users_with_domain) + 1) / (cfg.shared_link_min_users * 2)),
                    evidence=(
                        f"ссылку на {domain} за {cfg.shared_link_window_seconds:.0f} сек "
                        f"написали ещё {len(users_with_domain)} пользователей"
                    ),
                )
            )
            break  # одного сработавшего домена достаточно для сигнала

    return signals
