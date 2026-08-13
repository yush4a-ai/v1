"""Группировка пользователей, действующих согласованно.

Detectors в cigilbot/detectors/ оценивают ОДНО сообщение. Здесь —
другая задача: найти связи МЕЖДУ РАЗНЫМИ пользователями за окно времени и
объединить их в компоненты связности (union-find). Result — ClusterInfo,
который engine.py потом подмешивает как NETWORK-сигналы в вердикт каждого
участника (см. cigilbot/types.py).

Ребро между сообщениями A и B (от разных пользователей) есть, если:
  - совпадает домен ссылки, ИЛИ
  - схожесть minhash >= similarity_threshold, ИЛИ
  - совпадает skeleton при длине >= min_content_length_for_edge.

Короткие сообщения ("+", "гг", "лол") НЕ формируют content-рёбра вообще —
это единственное, что отделяет "сто разных зрителей радуются одновременно"
от "кластер ботов". Без этой защиты любой хайп-момент выглядел бы как атака.

ВАЖНО про cluster_id: на этом этапе (до store.py, этап 4) id — просто
порядковый номер компонент связности В ПРЕДЕЛАХ ОДНОГО ВЫЗОВА find_clusters.
Он НЕ стабилен между вызовами: один и тот же реальный кластер, выросший с
12 до 17 участников на следующем сообщении, получит новый номер. Стабильные
идентификаторы кластеров, которые можно отследить во времени в панели —
работа mod_clusters (store.py), а не этого модуля.
"""

from __future__ import annotations

from cigilbot.detectors.keyword_overlap import significant_words
from cigilbot.domain.confidence import confidence as compute_confidence
from cigilbot.domain.config import ClusterConfig, KeywordOverlapConfig, ModerationConfig
from cigilbot.domain.normalize import MessageFingerprint, similarity
from cigilbot.domain.scoring import risk_score as compute_risk_score
from cigilbot.domain.types import ChannelContext, ClusterInfo, Signal, SignalFamily, UserState
from cigilbot.domain.window import SlidingWindow, WindowEntry


class _UnionFind:
    """Классический disjoint-set с сжатием пути и объединением по рангу.

    Отдельный маленький класс, а не готовая библиотека: алгоритм — 15 строк,
    а внешняя зависимость ради него добавила бы больше веса, чем экономит.
    """

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def add(self, x: str) -> None:
        self._parent.setdefault(x, x)
        self._rank.setdefault(x, 0)

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1

    def groups(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for x in self._parent:
            result.setdefault(self.find(x), []).append(x)
        return result


def _has_edge(
    a: MessageFingerprint, b: MessageFingerprint, cfg: ClusterConfig, kw_cfg: KeywordOverlapConfig
) -> bool:
    # Общий домен ссылки — самый надёжный признак, работает независимо от
    # длины текста и стоп-листа: ссылку не спамят "случайно всей толпой".
    if a.domains and b.domains and set(a.domains) & set(b.domains):
        return True

    if a.is_empty or b.is_empty:
        return False

    # Короткие фразы исключены из content-рёбер целиком — см. докстринг модуля.
    if len(a.matching) < cfg.min_content_length_for_edge:
        return False
    if len(b.matching) < cfg.min_content_length_for_edge:
        return False
    if a.matching in cfg.excluded_phrases or b.matching in cfg.excluded_phrases:
        return False

    if similarity(a.minhash, b.minhash) >= cfg.similarity_threshold:
        return True

    if len(a.skeleton) >= cfg.min_content_length_for_edge and a.skeleton == b.skeleton:
        return True

    # Перефразированный спам ("го стрим глянь" / "у меня тоже стрим го
    # смотреть") не даёт совпадения ни по minhash (символьные триграммы),
    # ни по skeleton (структура разная) — но делит значимые слова. Без
    # этой ветки кластеризация не видела такую атаку как единую группу,
    # даже когда keyword_overlap-детектор уже подтвердил связь на уровне
    # отдельных сообщений (проверено прогоном: 12 перефразировок одной
    # self-promo фразы растянуто на 90 сек — 0 кластеров без этой ветки).
    if kw_cfg.enabled:
        words_a = significant_words(a.original)
        words_b = significant_words(b.original)
        if len(words_a) >= kw_cfg.min_significant_words and len(words_b) >= kw_cfg.min_significant_words:
            union = words_a | words_b
            if union and len(words_a & words_b) / len(union) >= kw_cfg.overlap_threshold:
                return True

    return False


def _first_entry_per_user(entries: list[WindowEntry]) -> dict[str, WindowEntry]:
    """Самое раннее в окне сообщение каждого пользователя.

    Используется для оценки момента появления — если человек уже давно
    пишет в чат и его последнее сообщение случайно попало под рёбра
    кластера, важен момент, когда он начал эту серию, а не когда написал
    сообщение, совпавшее с чужим.
    """
    first: dict[str, WindowEntry] = {}
    for entry in entries:
        uid = entry.event.user_id
        if uid not in first or entry.event.timestamp < first[uid].event.timestamp:
            first[uid] = entry
    return first


def _is_new_account(
    entry: WindowEntry, config: ModerationConfig, user_states: dict[str, UserState] | None
) -> bool:
    """Признак "новый" для конкретного участника кластера.

    Если у engine.py уже есть UserState с известным возрастом аккаунта
    (Helix успел ответить) — используем его, по тому же порогу, что и
    detectors/account.py (единый источник истины). Иначе — более слабая,
    но мгновенно доступная замена: тег first-msg из IRC.
    """
    user = user_states.get(entry.event.user_id) if user_states else None
    if user is not None and user.account_age_days is not None:
        return user.account_age_days < config.detectors.account.new_account_days
    return entry.event.is_first_message


def _cluster_signals(
    *,
    size: int,
    arrival_window: float,
    first_message_ratio: float,
    similarity_score: float,
    shared_domains: tuple[str, ...],
    config: ModerationConfig,
) -> list[Signal]:
    cfg = config.cluster
    signals: list[Signal] = []

    # Чем теснее окно прибытия относительно порога, тем выше значение —
    # 17 человек за 2 секунды подозрительнее, чем за 19 из лимита в 20.
    arrival_value = max(0.0, min(1.0, 1.0 - arrival_window / cfg.arrival_window_seconds))
    signals.append(
        Signal(
            name="synchronized_arrival",
            family=SignalFamily.TIMING,
            weight=config.weight("synchronized_arrival").weight,
            value=arrival_value,
            evidence=f"{size} пользователей появились за {arrival_window:.1f} сек",
        )
    )

    membership_value = min(1.0, size / (cfg.min_users * 3))
    evidence = f"группа из {size} пользователей, схожесть сообщений {similarity_score:.0%}"
    if shared_domains:
        evidence += f", общие ссылки: {', '.join(shared_domains[:3])}"
    signals.append(
        Signal(
            name="cluster_membership",
            family=SignalFamily.NETWORK,
            weight=config.weight("cluster_membership").weight,
            value=membership_value,
            evidence=evidence,
        )
    )

    if first_message_ratio >= cfg.mass_first_message_ratio_threshold:
        signals.append(
            Signal(
                name="mass_first_messages",
                family=SignalFamily.NETWORK,
                weight=config.weight("mass_first_messages").weight,
                value=first_message_ratio,
                evidence=f"{first_message_ratio:.0%} участников группы пишут впервые на канале",
            )
        )

    return signals


def find_clusters(
    window: SlidingWindow,
    config: ModerationConfig,
    *,
    user_states: dict[str, UserState] | None = None,
    channel_context: ChannelContext | None = None,
    now: float | None = None,
) -> list[ClusterInfo]:
    """Найти группы пользователей, действующих согласованно, в окне чата.

    Возвращает только группы, прошедшие валидацию (раздел "Cluster
    Detection" в docs/moderation-plan.md): достаточный размер, достаточно
    узкое окно появления. Группы без общих рёбер (одиночные пользователи)
    в результат не попадают вообще — это не "кластеры размера 1".
    """
    cfg = config.cluster
    channel_context = channel_context or ChannelContext()
    if not cfg.enabled:
        return []

    entries = window.recent(cfg.window_seconds, now=now)
    if len(entries) < cfg.min_users:
        return []

    uf = _UnionFind()
    for entry in entries:
        uf.add(entry.event.user_id)

    # Рёбра ищем по всем парам сообщений в окне. При реальной атаке в окне
    # обычно десятки-сотни сообщений — O(n^2) на это приемлемо; если станет
    # узким местом, можно сначала группировать по домену/skeleton и сравнивать
    # только внутри групп, но усложнять раньше, чем это стало проблемой, не нужно.
    for i, a in enumerate(entries):
        for b in entries[i + 1 :]:
            if a.event.user_id == b.event.user_id:
                continue
            if _has_edge(a.fingerprint, b.fingerprint, cfg, config.detectors.keyword_overlap):
                uf.union(a.event.user_id, b.event.user_id)

    first_by_user = _first_entry_per_user(entries)

    clusters: list[ClusterInfo] = []
    cluster_id = 0
    for member_ids in uf.groups().values():
        if len(member_ids) < cfg.min_users:
            continue

        member_entries = [first_by_user[uid] for uid in member_ids if uid in first_by_user]
        if not member_entries:
            continue

        arrival_times = [e.event.timestamp for e in member_entries]
        arrival_window = max(arrival_times) - min(arrival_times)
        if arrival_window > cfg.arrival_window_seconds:
            # Появились в одном компоненте связности, но растянуто по
            # времени — это не "синхронное появление", отбрасываем группу.
            continue

        cluster_id += 1

        first_message_count = sum(1 for e in member_entries if e.event.is_first_message)
        first_message_ratio = first_message_count / len(member_entries)

        new_account_count = sum(
            1 for e in member_entries if _is_new_account(e, config, user_states)
        )
        new_account_ratio = new_account_count / len(member_entries)

        pairwise_similarities = [
            similarity(a.fingerprint.minhash, b.fingerprint.minhash)
            for idx, a in enumerate(member_entries)
            for b in member_entries[idx + 1 :]
            if not a.fingerprint.is_empty and not b.fingerprint.is_empty
        ]
        avg_similarity = (
            sum(pairwise_similarities) / len(pairwise_similarities)
            if pairwise_similarities
            else 0.0
        )

        shared_domains = tuple(
            sorted(
                set.intersection(*(set(e.fingerprint.domains) for e in member_entries))
                if all(e.fingerprint.domains for e in member_entries)
                else set()
            )
        )

        signals = _cluster_signals(
            size=len(member_entries),
            arrival_window=arrival_window,
            first_message_ratio=first_message_ratio,
            similarity_score=avg_similarity,
            shared_domains=shared_domains,
            config=config,
        )

        clusters.append(
            ClusterInfo(
                cluster_id=cluster_id,
                user_ids=tuple(e.event.user_id for e in member_entries),
                logins=tuple(e.event.login for e in member_entries),
                similarity_score=avg_similarity,
                arrival_window_sec=arrival_window,
                first_message_ratio=first_message_ratio,
                new_account_ratio=new_account_ratio,
                shared_domains=shared_domains,
                signals=tuple(signals),
                risk_score=compute_risk_score(signals, config, sensitivity=config.sensitivity),
                confidence=compute_confidence(
                    signals, config, channel_context, sample_size=len(member_entries)
                ),
                created_at=now if now is not None else max(arrival_times),
            )
        )

    return clusters
