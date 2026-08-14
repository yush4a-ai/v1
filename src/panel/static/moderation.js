// Панель модерации: Live (активные кластеры + лента) и Audit.
// Без сборки, как и index.html — обычный vanilla JS.
//
// Роль и логин больше не выбираются вручную в UI — они приходят с сервера
// после входа через Twitch (panel/auth.py), через GET /auth/me. cookie-
// сессия ходит с каждым запросом автоматически (same-origin), никаких
// заголовков вроде X-Panel-Role добавлять не нужно. Любой ответ 401
// означает "сессия истекла или не было входа" — показываем экран логина.

const state = {
  role: "VIEWER",
  login: "",
  ws: null,
  wsRetryMs: 1000,
  contentWs: null,
};

const el = (id) => document.getElementById(id);

// Единственный источник истины для "какой канал сейчас выбран" —
// <select id="profile-select">.value, не отдельная переменная в state.
// Раньше "текущий канал" хранился отдельно в state.profile и синхронизировался вручную в
// 5 разных местах (loadProfiles, selectChannel, deep-link, клик по карточке,
// change на select) — расхождение между тем, что видел пользователь в
// интерфейсе, и тем, что реально уходило на сервер, было вопросом времени:
// действие подтверждалось для одного канала, а исполнялось на другом
// (2026-08-13, "почему не находит пасту" → таймаут ушёл не на тот канал,
// который был на экране). currentProfile() читает DOM напрямую в момент
// вызова — то, что видит глаз, физически совпадает с тем, что отправляется.
function currentProfile() {
  return el("profile-select").value || localStorage.getItem("mod.profile") || "main";
}

// Человекочитаемые названия сигналов детекторов (см. config/moderation.yml
// для полного списка и весов) — движок и API работают с английскими
// именами (стабильные идентификаторы для конфига/аудита/feedback), здесь
// только отображение в UI переведено, сами данные не меняются.
const SIGNAL_LABELS = {
  user_message_burst: "всплеск сообщений от юзера",
  channel_message_burst: "всплеск сообщений в канале",
  exact_duplicate: "точный дубликат",
  near_duplicate: "почти дубликат",
  skeleton_match: "похожий текст (скелет)",
  link_present: "есть ссылка",
  shared_link_multi_user: "одна ссылка у нескольких",
  url_shortener: "сокращённая ссылка",
  known_scam_domain: "известный скам-домен",
  invisible_chars: "невидимые символы",
  homoglyph_mix: "смешанные похожие символы",
  script_mix_in_word: "смешение алфавитов в слове",
  unexpected_language: "неожиданный язык",
  new_account: "новый аккаунт",
  first_message: "первое сообщение",
  no_history: "нет истории",
  generated_username_pattern: "похоже на сген. ник",
  emote_spam: "спам эмодзи",
  zalgo_text_spam: "залго-текст",
  synchronized_arrival: "синхронный приход",
  cluster_membership: "участие в кластере",
  mass_first_messages: "массовые первые сообщения",
};

function signalLabel(name) {
  return SIGNAL_LABELS[name] || name;
}

// verdict.id, отмеченные false positive в этой сессии панели — лента
// приходит целиком заново на каждое сообщение WebSocket (сам вердикт в
// БД никуда не девается, feedback только снижает вес сигнала на будущее),
// без этого списка убранная строка вернулась бы обратно на следующем же
// обновлении.
const dismissedVerdictIds = new Set();

// user_id пользователей, чья группа в ленте вердиктов сейчас развёрнута —
// лента перерисовывается целиком на каждое сообщение WebSocket (несколько
// раз в минуту), без этого набора разворот схлопывался бы сам через пару
// секунд после клика.
const expandedVerdictGroups = new Set();

// "verdictId:signalName" -> "FALSE_POSITIVE" | "CONFIRMED_BOT" — решения по
// сигналам в этой сессии панели, чтобы кнопка feedback оставалась
// подсвеченной после клика и до следующего ответа сервера (сам вердикт в
// БД не меняется, только вес сигнала на будущее).
const signalFeedbackDecisions = new Map();

function toast(message, kind = "info") {
  const stack = el("toast-stack");
  const node = document.createElement("div");
  node.className = `toast ${kind}`;
  node.textContent = message;
  stack.appendChild(node);
  setTimeout(() => node.remove(), 5000);
}

// --- авторизация --------------------------------------------------------

function showLoginScreen() {
  el("login-overlay").style.display = "flex";
  el("app-root").style.display = "none";
  if (state.ws) {
    state.ws.close();
    state.ws = null;
  }
}

function showApp() {
  el("login-overlay").style.display = "none";
  el("app-root").style.display = "flex";
}

async function checkAuth() {
  const resp = await fetch("/auth/me");
  const data = await resp.json();
  if (!data.authenticated) {
    if (data.login_configured === false) {
      el("login-message").textContent =
        "Вход через Twitch не настроен на сервере. Заполните PANEL_TWITCH_CLIENT_ID/SECRET/CHANNEL в .env и перезапустите панель.";
      el("btn-login").disabled = true;
    }
    showLoginScreen();
    return false;
  }
  state.role = data.role;
  state.login = data.login;
  el("user-login").textContent = data.login;
  el("user-avatar").textContent = data.login.slice(0, 2);
  el("user-role-badge").textContent = data.role;
  showApp();
  return true;
}

el("btn-login").addEventListener("click", () => {
  window.location.href = "/auth/login";
});
el("btn-logout").addEventListener("click", async () => {
  await fetch("/auth/logout");
  await checkAuth();
});

// fetch-обёртка: на 401 показывает экран логина вместо тихого падения.
async function apiFetch(url, options = {}) {
  const resp = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (resp.status === 401) {
    showLoginScreen();
    throw new Error("Требуется вход");
  }
  return resp;
}

// --- профили ----------------------------------------------------------

// Кэш последнего списка профилей — используется и рядом-стоящей выпадашкой
// (id="profile-select"), и channel-rail, и экраном "Каналы", чтобы не запрашивать
// /api/moderation/profiles трижды при каждой навигации.
let lastProfiles = [];

async function loadProfiles() {
  const select = el("profile-select");
  try {
    const resp = await fetch("/api/moderation/profiles");
    const profiles = await resp.json();
    lastProfiles = profiles;
    select.innerHTML = "";
    for (const p of profiles) {
      const opt = document.createElement("option");
      opt.value = p.profile;
      // Канал — то, что реально узнаваемо для человека (dobriy_yura,
      // paverpapa); внутренний идентификатор профиля (совпадает с ним же
      // почти всегда) виден в скобках только если отличается, чтобы не
      // дублировать одно и то же дважды в каждой строке списка.
      opt.textContent = p.channel && p.channel !== p.profile ? `${p.channel} (${p.profile})` : p.channel || p.profile;
      select.appendChild(opt);
    }
    const savedProfile = localStorage.getItem("mod.profile");
    if (savedProfile && profiles.some((p) => p.profile === savedProfile)) {
      select.value = savedProfile;
    } else if (profiles.length) {
      select.value = profiles[0].profile;
    }
    localStorage.setItem("mod.profile", select.value);
    await renderChannelRail(profiles);
  } catch {
    select.innerHTML = '<option value="main">main</option>';
  }
}

// --- channel rail --------------------------------------------------------
// Переключение канала без захода в отдельный экран — виден на каждом
// экране панели, не только на "Каналы". Сам переход дублирует то, что
// раньше делала только смена <select id="profile-select">.
async function renderChannelRail(profiles) {
  const rail = el("rail-channels");
  rail.innerHTML = "";
  // Статус запрашивается сразу для всех каналов параллельно — иначе точка
  // навсегда остаётся серой-по-умолчанию (баг: индикатор рисовался, но
  // ничем не красился, см. .rail-dot без модификатора в исходной версии).
  const statuses = await Promise.all(
    profiles.map((p) =>
      fetch(`/api/moderation/attack_mode?profile=${encodeURIComponent(p.profile)}`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null)
    )
  );
  for (let i = 0; i < profiles.length; i++) {
    const p = profiles[i];
    const attack = statuses[i];
    const label = p.channel || p.profile;
    const btn = document.createElement("div");
    btn.className = `rail-channel${p.profile === currentProfile() ? " active" : ""}`;
    btn.title = label;
    btn.setAttribute("role", "button");
    btn.setAttribute("tabindex", "0");
    const dotClass = attack && attack.active ? "attack" : "live";
    btn.innerHTML = `${escapeHtml(label.slice(0, 2).toUpperCase())}<span class="rail-dot ${dotClass}"></span>`;
    const select = () => selectChannel(p.profile);
    btn.addEventListener("click", select);
    btn.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        select();
      }
    });
    rail.appendChild(btn);
  }
}

function selectChannel(profile) {
  el("profile-select").value = profile;
  localStorage.setItem("mod.profile", profile);
  connectWs();
  loadAudit();
  document.querySelectorAll(".rail-channel").forEach((n, i) => n.classList.toggle("active", lastProfiles[i]?.profile === profile));
  switchScreen("live");
}

el("rail-home").addEventListener("click", () => switchScreen("channels"));
el("rail-home").addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    switchScreen("channels");
  }
});

// --- deep-link из Discord-алерта (направление 01 master-plan.html) -------
// /moderation?channel=X&cluster=Y — открывает Live нужного канала и
// подсвечивает нужный кластер, чтобы не искать вручную среди нескольких
// каналов. channel в ссылке — login (человекочитаемый, тот же, что в
// embed'е), а не broadcaster_id: панель хранит канал по login-у в
// lastProfiles, здесь резолвим одно в другое.

let pendingHighlightClusterId = null;

function applyDeepLinkFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const channel = params.get("channel");
  const clusterParam = params.get("cluster");
  if (!channel) return;

  const match = lastProfiles.find((p) => p.channel === channel);
  if (!match) {
    toast(`Канал "${channel}" не найден в списке подключённых`, "error");
    return;
  }

  pendingHighlightClusterId = clusterParam ? Number(clusterParam) : null;
  selectChannel(match.profile);
}

function highlightClusterIfPending() {
  if (pendingHighlightClusterId === null) return;
  const card = document.querySelector(`.cluster-card[data-cluster-id="${pendingHighlightClusterId}"]`);
  pendingHighlightClusterId = null;
  if (!card) return;
  card.scrollIntoView({ behavior: "smooth", block: "center" });
  card.classList.add("cluster-card-highlight");
  setTimeout(() => card.classList.remove("cluster-card-highlight"), 2600);
}

// --- экран "Каналы" (Operator Home, направление 06 master-plan.html) -----
// Один запрос /api/moderation/overview вместо N вызовов attack_mode (по
// одному на карточку, как раньше) — KPI-строка, карточки с метриками и
// лента алертов собираются из одного ответа.

const STATUS_PILL = {
  attack: { cls: "", style: "background:var(--danger-soft);color:var(--danger);", label: "Атака" },
  live: { cls: "running", style: "", label: "Активен" },
  idle: { cls: "running", style: "", label: "Активен" },
  offline: { cls: "stopped", style: "", label: "Офлайн" },
};

function timeAgo(unixSeconds) {
  const diffSec = Math.max(0, Date.now() / 1000 - unixSeconds);
  if (diffSec < 60) return "только что";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} мин назад`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} ч назад`;
  return `${Math.floor(diffSec / 86400)} дн назад`;
}

function renderOverviewKpi(kpi) {
  const tiles = el("overview-kpi").querySelectorAll(".stat-value");
  tiles[0].textContent = kpi.channels_connected;
  tiles[1].textContent = kpi.new_clusters;
  tiles[2].textContent = kpi.would_timeout;
  tiles[3].textContent = kpi.would_ban;
}

function renderOverviewAlerts(alerts) {
  const box = el("overview-alerts");
  if (!alerts.length) {
    box.innerHTML = '<div class="empty">Пока тихо — новых кластеров не было</div>';
    return;
  }
  box.innerHTML = "";
  for (const a of alerts) {
    const row = document.createElement("div");
    row.className = "alert-row";
    row.innerHTML = `
      <div class="alert-icon crit">
        <svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M8 1.5 14.5 13h-13L8 1.5Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 6.2v3M8 11h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
      </div>
      <div class="alert-body">
        <div class="alert-title">${escapeHtml(a.channel)}: ${a.size} ботов, risk ${a.risk_score}</div>
        <div class="alert-meta">${timeAgo(a.created_at)}</div>
      </div>
      <div class="alert-actions"><button class="btn btn-small">Открыть</button></div>
    `;
    row.querySelector("button").addEventListener("click", () => {
      pendingHighlightClusterId = a.cluster_id;
      selectChannel(a.profile);
    });
    box.appendChild(row);
  }
}

async function loadChannels() {
  const grid = el("channels-grid");
  if (!lastProfiles.length) {
    grid.innerHTML = '<div class="empty">Каналов пока нет — добавьте канал в Channel Registry</div>';
    el("overview-alerts").innerHTML = '<div class="empty">Каналов пока нет</div>';
    return;
  }
  grid.innerHTML = '<div class="empty">Загрузка…</div>';

  let overview;
  try {
    const resp = await fetch("/api/moderation/overview");
    if (!resp.ok) throw new Error(String(resp.status));
    overview = await resp.json();
  } catch {
    grid.innerHTML = '<div class="empty">Не удалось загрузить сводку по каналам</div>';
    return;
  }

  renderOverviewKpi(overview.kpi);
  renderOverviewAlerts(overview.alerts);

  const byProfile = new Map(overview.channels.map((c) => [c.profile, c]));
  grid.innerHTML = "";
  for (const p of lastProfiles) {
    const label = p.channel || p.profile;
    const c = byProfile.get(p.profile);
    const pill = STATUS_PILL[c?.status || "offline"];
    const card = document.createElement("div");
    card.className = "channel-card";
    card.innerHTML = `
      <div class="channel-card-head">
        <div class="channel-card-title">
          <div class="channel-avatar">${escapeHtml(label.slice(0, 2).toUpperCase())}</div>
          <div>
            <div class="channel-name">${escapeHtml(label)}</div>
            <div class="channel-id">${escapeHtml(p.profile)}</div>
          </div>
        </div>
        <span class="channel-status-pill ${pill.cls}" style="${pill.style}">${pill.label}</span>
      </div>
      <div class="channel-metrics">
        <div class="channel-metric"><div class="v tabular">${c ? c.active_clusters : "—"}</div><div class="l">Активных кластеров</div></div>
        <div class="channel-metric"><div class="v tabular">${c ? c.new_clusters : "—"}</div><div class="l">Новых, 24ч</div></div>
      </div>
    `;
    card.addEventListener("click", () => selectChannel(p.profile));
    grid.appendChild(card);
  }
  const addCard = document.createElement("a");
  addCard.className = "channel-card channel-card-add";
  addCard.href = "/bots";
  addCard.style.textDecoration = "none";
  addCard.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 16 16" fill="none"><path d="M8 3v10M3 8h10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
    <span style="font-size:12.5px;">Подключить канал</span>
  `;
  grid.appendChild(addCard);
}

// --- навигация ----------------------------------------------------------

const SCREEN_TITLES = {
  channels: "Каналы",
  live: "Прямой эфир — активные кластеры",
  users: "Пользователи — зрители канала",
  trusted: "Доверенные зрители",
  audit: "Аудит — журнал действий модераторов",
  patterns: "Библиотека паттернов",
  attack: "Режим атаки",
  content: "Словарный детектор",
  stats: "Статистика и FP-rate",
  settings: "Настройки — конфигурация и токен бота",
};

function switchScreen(name) {
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.screen === name));
  document.querySelectorAll(".screen").forEach((s) => s.classList.toggle("active", s.id === `screen-${name}`));
  el("rail-home").classList.toggle("active", name === "channels");
  el("screen-title").textContent = SCREEN_TITLES[name] || "";
  if (name === "channels") loadChannels();
  if (name === "users") loadUsers();
  if (name === "trusted") loadTrustedUsers();
  if (name === "audit") loadAudit();
  if (name === "patterns") loadPatterns();
  if (name === "attack") {
    loadAttackMode();
    loadGiveawayMode();
  }
  if (name === "stats") loadStats();
  if (name === "settings") loadSettings();
  if (name === "live") loadPasteWaveRecent();
  if (name === "content") {
    connectContentWs();
  } else {
    disconnectContentWs();
  }
}

function canAdmin() {
  return ["ADMIN", "OWNER"].includes(state.role);
}

// --- рендер: кластеры ----------------------------------------------------

function riskClass(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function renderClusters(clusters) {
  const list = el("cluster-list");
  if (!clusters || clusters.length === 0) {
    list.innerHTML = '<div class="empty">Активных кластеров нет — атак не обнаружено</div>';
    return;
  }
  list.innerHTML = "";
  for (const c of clusters) {
    const card = document.createElement("div");
    const cls = riskClass(c.risk_score);
    card.className = `cluster-card risk-${cls}`;
    card.dataset.clusterId = String(c.id);
    card.innerHTML = `
      <div class="cluster-head">
        <div class="cluster-title">
          <span class="risk-badge ${cls}">${c.risk_score}</span>
          <span class="cluster-size">${c.size} участников</span>
        </div>
        <div class="cluster-meta">окно прихода ${Math.round(c.arrival_window_sec)}с · схожесть ${(c.similarity_score * 100).toFixed(0)}% · уверенность ${(c.confidence * 100).toFixed(0)}%</div>
      </div>
      <div class="signal-chips"></div>
      <div class="cluster-actions"></div>
    `;
    const chips = card.querySelector(".signal-chips");
    const userIds = c.user_ids || [];
    const logins = c.logins || [];
    for (let i = 0; i < Math.min(logins.length, 12); i++) {
      chips.appendChild(userChip(userIds[i], logins[i]));
    }
    if (logins.length > 12) {
      const more = document.createElement("span");
      more.className = "chip";
      more.textContent = `+${logins.length - 12}`;
      chips.appendChild(more);
    }
    const actions = card.querySelector(".cluster-actions");
    actions.appendChild(actionButton("BAN ALL", "btn-danger", () => confirmClusterAction(c, "BAN")));
    actions.appendChild(actionButton("TIMEOUT ALL", "btn-warning", () => confirmClusterAction(c, "TIMEOUT")));
    actions.appendChild(actionButton("IGNORE CLUSTER", "btn-ghost", () => decideCluster(c.id, "ignore")));
    list.appendChild(card);
  }
}

function userChip(userId, login) {
  const chip = document.createElement("span");
  chip.className = "chip chip-clickable";
  chip.textContent = login;
  chip.title = "Пометить как доверенного (не бот)";
  chip.addEventListener("click", () => markUserSafe(userId, login));
  return chip;
}

function actionButton(label, cls, onClick) {
  const btn = document.createElement("button");
  btn.className = `btn ${cls}`;
  btn.textContent = label;
  btn.disabled = !canAct();
  btn.title = canAct() ? "" : "Требуется роль MODERATOR и выше";
  btn.addEventListener("click", onClick);
  return btn;
}

function canAct() {
  return ["MODERATOR", "ADMIN", "OWNER"].includes(state.role);
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

// --- рендер: лента вердиктов ---------------------------------------------

const ACTION_RANK = { NOTHING: 0, OBSERVE: 1, TIMEOUT: 2, BAN: 3 };
const CHEVRON_SVG = '<svg class="verdict-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 6l6 6-6 6"/></svg>';
const ICON_X_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>';
const ICON_CHECK_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>';

// Группирует вердикты по user_id — одна строка на зрителя, не на сообщение
// (см. комментарий у .verdict-group в moderation.html). Порядок вердиктов
// с сервера — created_at DESC, поэтому verdicts[0] в каждой группе уже
// самый свежий и задаёт превью/время строки; худший recommended_action
// среди сообщений группы задаёт её бейдж.
function groupVerdictsByUser(verdicts) {
  const groups = new Map();
  for (const v of verdicts) {
    const key = v.user_id || v.login;
    if (!groups.has(key)) {
      groups.set(key, { userId: v.user_id, login: v.login, verdicts: [] });
    }
    groups.get(key).verdicts.push(v);
  }
  for (const g of groups.values()) {
    g.worstAction = g.verdicts.reduce(
      (worst, v) => (ACTION_RANK[v.recommended_action] > ACTION_RANK[worst] ? v.recommended_action : worst),
      "NOTHING"
    );
    g.inCluster = g.verdicts.some((v) => v.cluster_id != null);
    g.clusterId = g.verdicts.find((v) => v.cluster_id != null)?.cluster_id ?? null;
  }
  // Группы сортируются по времени самого свежего сообщения — тот же порядок,
  // в котором вердикты и так приходят с сервера.
  return [...groups.values()].sort((a, b) => b.verdicts[0].created_at - a.verdicts[0].created_at);
}

function renderVerdicts(allVerdicts) {
  const feed = el("verdict-feed");
  const verdicts = (allVerdicts || []).filter((v) => !dismissedVerdictIds.has(v.id));
  if (verdicts.length === 0) {
    feed.innerHTML = '<div class="empty">Пока тихо — подозрительных сообщений не было</div>';
    return;
  }
  const groups = groupVerdictsByUser(verdicts);
  feed.innerHTML = "";
  for (const g of groups) {
    feed.appendChild(renderVerdictGroup(g));
  }
}

function renderVerdictGroup(g) {
  const groupKey = String(g.userId || g.login);
  const isOpen = expandedVerdictGroups.has(groupKey);
  const latest = g.verdicts[0];

  const group = document.createElement("div");
  group.className = "verdict-group" + (isOpen ? " open" : "");
  group.dataset.groupKey = groupKey;

  // Убирает группу из ленты сразу (мгновенный отклик) и запоминает id
  // вердиктов, чтобы следующий renderVerdicts() из WebSocket (лента
  // приходит целиком заново на каждое сообщение) их тоже отфильтровал.
  function dismissGroup() {
    for (const v of g.verdicts) dismissedVerdictIds.add(v.id);
    expandedVerdictGroups.delete(groupKey);
    group.remove();
    if (!el("verdict-feed").querySelector(".verdict-group")) {
      el("verdict-feed").innerHTML = '<div class="empty">Пока тихо — подозрительных сообщений не было</div>';
    }
  }

  async function trustGroup() {
    const ok = await markUserSafe(g.userId, g.login);
    // Доверенный зритель больше не должен всплывать в ленте подозрительных.
    if (ok) dismissGroup();
  }

  // Мини-кнопки на свёрнутой строке отмечают ВСЕ сигналы ВСЕХ сообщений
  // группы разом — без разворачивания карточки на активном чате, где
  // решение по каждому зрителю нужно принимать за секунды, а не открывать
  // и листать сообщение за сообщением.
  async function confirmGroupAsBot() {
    if (!canAct()) {
      toast("Требуется роль MODERATOR и выше", "error");
      return;
    }
    let anyFailed = false;
    for (const v of g.verdicts) {
      for (const name of v.signal_names || []) {
        const ok = await submitSignalFeedback(v, name, null, "CONFIRMED_BOT", { silent: true });
        if (!ok) anyFailed = true;
      }
    }
    if (anyFailed) {
      toast(`${g.login}: часть сигналов не удалось отметить`, "error");
    } else {
      toast(`${g.login}: все сигналы подтверждены как бот`, "success");
    }
    dismissGroup();
  }

  const head = document.createElement("div");
  head.className = "verdict-group-head";
  head.innerHTML = `
    ${CHEVRON_SVG}
    <span class="verdict-login">${escapeHtml(g.login)}</span>
    <span class="verdict-action ${g.worstAction}">${g.worstAction}</span>
    ${g.inCluster ? '<span class="verdict-cluster-dot" title="Участвует в кластере координации"></span>' : ""}
    <span class="verdict-preview">${
      latest.message_text ? `«${escapeHtml(latest.message_text)}»` : "(текст недоступен)"
    }${g.verdicts.length > 1 ? ` <b>+${g.verdicts.length - 1}</b>` : ""}</span>
    <span class="verdict-count">${g.verdicts.length} сообщ.</span>
    <span class="verdict-time">${formatTime(latest.created_at)}</span>
    <span class="verdict-quick-actions">
      <button class="quick-btn trust" title="Доверять пользователю" ${canAct() ? "" : "disabled"}>${ICON_CHECK_SVG}</button>
      <button class="quick-btn bad" title="Подтвердить все сигналы — это бот" ${canAct() ? "" : "disabled"}>${ICON_X_SVG}</button>
    </span>
  `;
  head.addEventListener("click", () => {
    if (expandedVerdictGroups.has(groupKey)) {
      expandedVerdictGroups.delete(groupKey);
    } else {
      expandedVerdictGroups.add(groupKey);
    }
    group.classList.toggle("open");
  });
  head.querySelector(".quick-btn.trust").addEventListener("click", (e) => {
    e.stopPropagation();
    trustGroup();
  });
  head.querySelector(".quick-btn.bad").addEventListener("click", (e) => {
    e.stopPropagation();
    confirmGroupAsBot();
  });
  group.appendChild(head);

  const body = document.createElement("div");
  body.className = "verdict-body";

  if (g.inCluster) {
    const note = document.createElement("div");
    note.className = "verdict-cluster-note";
    note.textContent = `Участвует в кластере координации #${g.clusterId}`;
    body.appendChild(note);
  }

  for (const v of g.verdicts) {
    body.appendChild(renderVerdictMessage(v));
  }

  const actions = document.createElement("div");
  actions.className = "verdict-group-actions";
  const trustBtn = document.createElement("button");
  trustBtn.className = "btn btn-trust btn-sm";
  trustBtn.textContent = "Доверять пользователю";
  trustBtn.disabled = !canAct();
  trustBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    trustGroup();
  });
  actions.appendChild(trustBtn);
  if (g.inCluster) {
    const clusterBtn = document.createElement("button");
    clusterBtn.className = "btn btn-ghost btn-sm";
    clusterBtn.textContent = `Открыть кластер #${g.clusterId}`;
    clusterBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      pendingHighlightClusterId = g.clusterId;
      switchScreen("live");
      highlightClusterIfPending();
    });
    actions.appendChild(clusterBtn);
  }
  body.appendChild(actions);

  group.appendChild(body);
  return group;
}

function renderVerdictMessage(v) {
  const row = document.createElement("div");
  row.className = "verdict-msg";
  const messageHtml = v.message_text
    ? `<div class="verdict-message">«${escapeHtml(v.message_text)}»</div>`
    : `<div class="verdict-message verdict-message-missing">(текст сообщения недоступен)</div>`;
  row.innerHTML = `
    <span class="verdict-msg-time">${formatTime(v.created_at)}</span>
    ${messageHtml}
    <div class="verdict-reason">${escapeHtml(v.reason)}</div>
    <div class="sig-list"></div>
  `;
  const sigList = row.querySelector(".sig-list");
  const evidenceList = v.signal_evidence || [];
  (v.signal_names || []).forEach((name, i) => {
    sigList.appendChild(renderSignalRow(v, name, evidenceList[i]));
  });
  return row;
}

function renderSignalRow(verdict, signalName, evidence) {
  const key = `${verdict.id}:${signalName}`;
  const decision = signalFeedbackDecisions.get(key);
  const sigRow = document.createElement("div");
  sigRow.className = "sig-row" + (decision === "FALSE_POSITIVE" ? " marked-fp" : "") + (decision === "CONFIRMED_BOT" ? " marked-bot" : "");
  sigRow.innerHTML = `
    <span class="sig-name">${escapeHtml(signalLabel(signalName))}</span>
    ${evidence ? `<span class="sig-evidence" title="${escapeHtml(evidence)}">${escapeHtml(evidence)}</span>` : ""}
    <span class="sig-fb">
      <button class="sig-btn fp" title="Ложное срабатывание" ${canAct() ? "" : "disabled"}>${ICON_X_SVG}</button>
      <button class="sig-btn bot" title="Подтвердить — это бот" ${canAct() ? "" : "disabled"}>${ICON_CHECK_SVG}</button>
    </span>
  `;
  const fpBtn = sigRow.querySelector(".sig-btn.fp");
  const botBtn = sigRow.querySelector(".sig-btn.bot");
  fpBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    submitSignalFeedback(verdict, signalName, sigRow, "FALSE_POSITIVE");
  });
  botBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    submitSignalFeedback(verdict, signalName, sigRow, "CONFIRMED_BOT");
  });
  return sigRow;
}

async function submitSignalFeedback(verdict, signalName, rowEl, decision = "FALSE_POSITIVE", { silent = false } = {}) {
  if (!canAct()) {
    if (!silent) toast("Требуется роль MODERATOR и выше", "error");
    return false;
  }
  try {
    const resp = await apiFetch("/api/moderation/feedback", {
      method: "POST",
      body: JSON.stringify({
        profile: currentProfile(),
        signal_name: signalName,
        decision,
        verdict_id: verdict.id,
        cluster_id: verdict.cluster_id,
        user_id: verdict.user_id,
        pattern_id: verdict.pattern_id,
      }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    if (!silent) {
      const verb = decision === "CONFIRMED_BOT" ? "подтверждено как бот" : "ложное срабатывание";
      toast(`Отмечено: "${signalLabel(signalName)}" — ${verb}`, "success");
    }
    // Отмечаем сигнал, а не удаляем сообщение из ленты целиком — одно
    // сообщение обычно несёт несколько сигналов, и решение по одному не
    // должно прятать остальные до следующего обновления с сервера.
    signalFeedbackDecisions.set(`${verdict.id}:${signalName}`, decision);
    if (rowEl) {
      rowEl.classList.toggle("marked-fp", decision === "FALSE_POSITIVE");
      rowEl.classList.toggle("marked-bot", decision === "CONFIRMED_BOT");
    }
    return true;
  } catch (e) {
    if (!silent) toast(`Ошибка: ${e.message}`, "error");
    return false;
  }
}

function formatTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// --- действия: подтверждение и вызов API ---------------------------------

let pendingConfirm = null;

function confirmClusterAction(cluster, action) {
  const verb = action === "BAN" ? "забанить" : "выдать таймаут";
  el("modal-title").textContent = `${action} ALL — подтвердите`;
  el("modal-body").textContent =
    `Вы собираетесь ${verb} ~${cluster.size} пользователей из кластера #${cluster.id} ` +
    `(риск ${cluster.risk_score}/100). Точный список подтвердит сервер на момент ` +
    `исполнения — если кластер успел измениться, действие применится к его текущему ` +
    `составу, а не к тому, что видно на экране. Действие попадёт в аудит от имени "${state.login}".`;
  pendingConfirm = async () => {
    try {
      const resp = await apiFetch("/api/moderation/actions", {
        method: "POST",
        body: JSON.stringify({
          profile: currentProfile(),
          action,
          // target_user_ids всё ещё отправляется для точечных действий без
          // cluster_id, но сервер игнорирует это поле, когда cluster_id
          // указан, и сам подставляет актуальный состав из БД (BUG-001
          // аудита) — здесь оставлено для совместимости и как fallback.
          target_user_ids: cluster.user_ids,
          reason: `Кластер #${cluster.id}, риск ${cluster.risk_score}`,
          cluster_id: cluster.id,
        }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail || resp.statusText);
      }
      const result = await resp.json();
      toast(
        `Задание поставлено в очередь (${action} ALL, кластер #${cluster.id}, целей: ${result.target_count ?? "?"})`,
        "success"
      );
    } catch (e) {
      toast(`Ошибка: ${e.message}`, "error");
    }
  };
  el("modal-overlay").classList.add("open");
}

async function decideCluster(clusterId, decision) {
  try {
    const resp = await apiFetch(`/api/moderation/clusters/${clusterId}/${decision}`, {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile() }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast(`Кластер #${clusterId}: ${decision}`, "success");
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
}

async function markUserSafe(userId, login) {
  if (!canAct()) {
    toast("Требуется роль MODERATOR и выше", "error");
    return false;
  }
  try {
    const resp = await apiFetch(`/api/moderation/users/${encodeURIComponent(userId)}/mark_safe`, {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile(), reason: "отмечен в панели как не бот" }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast(`${login} отмечен как доверенный`, "success");
    return true;
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
    return false;
  }
}

// "Зачистить пасту" свёрнута по умолчанию (#2611-подобная жалоба: блок
// занимал весь верх экрана Live постоянно, хотя используется от случая к
// случаю) — состояние в localStorage, не только в памяти вкладки, чтобы
// решение не сбрасывалось при каждом заходе на экран.
const PASTE_WAVE_OPEN_KEY = "mod.pasteWaveOpen";
if (localStorage.getItem(PASTE_WAVE_OPEN_KEY) === "1") {
  el("paste-wave-section").classList.add("open");
}
el("paste-wave-toggle").addEventListener("click", () => {
  const section = el("paste-wave-section");
  const isOpen = section.classList.toggle("open");
  localStorage.setItem(PASTE_WAVE_OPEN_KEY, isOpen ? "1" : "0");
});

el("modal-cancel").addEventListener("click", () => {
  pendingConfirm = null;
  el("modal-overlay").classList.remove("open");
});
el("modal-confirm").addEventListener("click", async () => {
  const fn = pendingConfirm;
  pendingConfirm = null;
  el("modal-overlay").classList.remove("open");
  if (fn) await fn();
});

// --- Зачистить пасту (пользователь 2026-08-13: сценарий "весь чат кидает
// одну и ту же пасту, стримеру это не нравится") -------------------------

function updatePasteWaveChannelBadge() {
  const profile = currentProfile();
  const match = lastProfiles.find((p) => p.profile === profile);
  el("paste-wave-channel-badge").textContent = `канал: ${match?.channel || profile}`;
}

async function loadPasteWaveRecent() {
  updatePasteWaveChannelBadge();
  const container = el("paste-wave-recent");
  try {
    const resp = await apiFetch(`/api/moderation/recent_messages?profile=${encodeURIComponent(currentProfile())}&limit=15`);
    if (!resp.ok) throw new Error(resp.statusText);
    const messages = await resp.json();
    if (messages.length === 0) {
      container.innerHTML = '<div class="note" style="padding:8px 10px;">Сообщений пока нет</div>';
      return;
    }
    // Клик на текст, а не отдельная кнопка — сообщение и так короткое, вся
    // строка кликабельна (пользователь 2026-08-13: "нажал и паста вставилась,
    // чтобы не копировать и вставлять").
    container.innerHTML = messages
      .map(
        (m) => `
        <div class="paste-wave-recent-row" data-text="${escapeHtml(m.text)}">
          <span class="paste-wave-recent-login">${escapeHtml(m.login)}</span>
          <span class="paste-wave-recent-text">${escapeHtml(m.text)}</span>
        </div>`
      )
      .join("");
  } catch (e) {
    container.innerHTML = '<div class="note" style="padding:8px 10px;">Не удалось загрузить сообщения</div>';
  }
}

el("paste-wave-recent").addEventListener("click", (e) => {
  const row = e.target.closest(".paste-wave-recent-row");
  if (!row) return;
  // data-text экранирован через escapeHtml при рендере — берём из textContent
  // соответствующего узла, а не из атрибута напрямую, чтобы получить текст
  // уже РАСэкранированным (браузер сам декодирует сущности при чтении DOM).
  const span = row.querySelector(".paste-wave-recent-text");
  el("paste-wave-sample").value = span.textContent;
  el("paste-wave-sample").focus();
});

let lastPasteWaveMatches = [];

el("btn-find-paste-wave").addEventListener("click", async () => {
  const sample = el("paste-wave-sample").value.trim();
  const results = el("paste-wave-results");
  if (!sample) {
    toast("Вставьте текст пасты перед поиском", "error");
    return;
  }
  try {
    const resp = await apiFetch(
      `/api/moderation/paste_wave?profile=${encodeURIComponent(currentProfile())}&sample_text=${encodeURIComponent(sample)}`
    );
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    lastPasteWaveMatches = await resp.json();
    renderPasteWaveResults();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

function renderPasteWaveResults() {
  const results = el("paste-wave-results");
  if (lastPasteWaveMatches.length === 0) {
    results.innerHTML = '<div class="note">Совпадений за последние 2 минуты не найдено.</div>';
    return;
  }
  const rows = lastPasteWaveMatches
    .map(
      (m) => `
      <label style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border-soft);">
        <input type="checkbox" class="paste-wave-check" data-user-id="${escapeHtml(m.user_id)}" checked>
        <span style="font-weight:600;">${escapeHtml(m.login)}</span>
        <span class="cluster-meta" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(m.text)}</span>
        <span class="cluster-meta">${Math.round(m.similarity * 100)}%</span>
      </label>`
    )
    .join("");
  const durationBtns = CONTENT_TIMEOUT_OPTIONS.map(
    (opt) => `<button class="btn btn-ghost btn-small paste-wave-timeout" data-duration="${opt.seconds}">${opt.label}</button>`
  ).join("");
  results.innerHTML = `
    <div class="note" style="margin-bottom:8px;">Найдено ${lastPasteWaveMatches.length} — снимите галочку, чтобы исключить из наказания.</div>
    ${rows}
    <div style="display:flex;align-items:center;gap:8px;margin-top:12px;">
      <span class="cluster-meta">Таймаут выбранным:</span>
      ${durationBtns}
    </div>
  `;
}

el("paste-wave-results").addEventListener("click", (e) => {
  const btn = e.target.closest(".paste-wave-timeout");
  if (!btn) return;
  const duration = Number(btn.dataset.duration);
  const durationLabel = CONTENT_TIMEOUT_OPTIONS.find((o) => o.seconds === duration)?.label || "10м";
  const selectedIds = Array.from(document.querySelectorAll(".paste-wave-check:checked")).map(
    (cb) => cb.dataset.userId
  );
  if (selectedIds.length === 0) {
    toast("Выберите хотя бы одного пользователя", "error");
    return;
  }

  el("modal-title").textContent = "Зачистить пасту — подтвердите";
  el("modal-body").textContent =
    `Вы собираетесь выдать таймаут на ${durationLabel} для ${selectedIds.length} ` +
    `пользователей, написавших похожий текст. Действие попадёт в аудит от имени "${state.login}".`;
  pendingConfirm = async () => {
    try {
      const resp = await apiFetch("/api/moderation/actions", {
        method: "POST",
        body: JSON.stringify({
          profile: currentProfile(),
          action: "TIMEOUT",
          target_user_ids: selectedIds,
          duration_seconds: duration,
          reason: "Зачистка волны копипасты (ручное модерирование)",
        }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail || resp.statusText);
      }
      toast(`Таймаут выдан ${selectedIds.length} пользователям`, "success");
      lastPasteWaveMatches = [];
      el("paste-wave-results").innerHTML = "";
      el("paste-wave-sample").value = "";
      await loadPasteWaveRecent();
    } catch (err) {
      toast(`Ошибка: ${err.message}`, "error");
    }
  };
  el("modal-overlay").classList.add("open");
});

// --- users -----------------------------------------------------------

async function loadUsers() {
  const body = el("users-body");
  const empty = el("users-empty");
  const search = el("users-search").value.trim();
  try {
    const params = new URLSearchParams({ profile: currentProfile() });
    if (search) params.set("search", search);
    const resp = await apiFetch(`/api/moderation/users?${params.toString()}`);
    const rows = await resp.json();
    if (!rows.length) {
      body.innerHTML = "";
      empty.style.display = "block";
      return;
    }
    empty.style.display = "none";
    body.innerHTML = rows
      .map((u) => {
        const trustCell = u.marked_safe
          ? `<span class="trust-tag ${escapeHtml(u.trust_level)}">${escapeHtml(u.trust_level)}</span> <span class="safe-tag">✓ safe</span>`
          : `<span class="trust-tag ${escapeHtml(u.trust_level)}">${escapeHtml(u.trust_level)}</span>`;
        return `
        <tr>
          <td>${escapeHtml(u.login)}</td>
          <td>${u.message_count}</td>
          <td>${trustCell}</td>
          <td>${formatTime(u.first_seen)}</td>
          <td>${formatTime(u.last_seen)}</td>
          <td>${u.prior_timeouts}</td>
        </tr>`;
      })
      .join("");
  } catch {
    body.innerHTML = "";
    empty.style.display = "block";
  }
}

el("btn-users-search").addEventListener("click", () => loadUsers());
el("users-search").addEventListener("keydown", (e) => {
  if (e.key === "Enter") loadUsers();
});

// --- доверенные зрители (направление 04 master-plan.html) ----------------

async function loadTrustedUsers() {
  const body = el("trusted-body");
  const empty = el("trusted-empty");
  try {
    const resp = await apiFetch(`/api/moderation/trusted?profile=${encodeURIComponent(currentProfile())}`);
    const rows = await resp.json();
    if (!rows.length) {
      body.innerHTML = "";
      empty.style.display = "block";
      return;
    }
    empty.style.display = "none";
    body.innerHTML = rows
      .map(
        (r) => `
        <tr>
          <td>${escapeHtml(r.login || r.user_id)}</td>
          <td>${r.message_count ?? "—"}</td>
          <td>${formatTime(r.added_at)}</td>
          <td>${escapeHtml(r.added_by)}</td>
          <td>${escapeHtml(r.reason || "—")}</td>
          <td><button class="btn btn-ghost btn-small" data-unmark="${escapeHtml(r.user_id)}" data-login="${escapeHtml(r.login || r.user_id)}">Снять</button></td>
        </tr>`
      )
      .join("");
    body.querySelectorAll("[data-unmark]").forEach((btn) => {
      btn.addEventListener("click", () => unmarkTrusted(btn.dataset.unmark, btn.dataset.login));
    });
  } catch {
    body.innerHTML = "";
    empty.style.display = "block";
  }
}

async function unmarkTrusted(userId, login) {
  if (!canAct()) {
    toast("Требуется роль MODERATOR и выше", "error");
    return;
  }
  try {
    const resp = await apiFetch(`/api/moderation/users/${encodeURIComponent(userId)}/unmark_safe`, {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile() }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast(`${login || userId}: пометка снята`, "success");
    loadTrustedUsers();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
}

// --- audit ----------------------------------------------------------

async function loadAudit() {
  const body = el("audit-body");
  const empty = el("audit-empty");
  try {
    const resp = await apiFetch(`/api/moderation/audit?profile=${encodeURIComponent(currentProfile())}`);
    const rows = await resp.json();
    if (!rows.length) {
      body.innerHTML = "";
      empty.style.display = "block";
      return;
    }
    empty.style.display = "none";
    body.innerHTML = rows
      .map(
        (r) => `
        <tr>
          <td>${formatTime(r.created_at)}</td>
          <td>${escapeHtml(r.actor)}</td>
          <td><span class="role-tag">${escapeHtml(r.actor_role)}</span></td>
          <td>${escapeHtml(r.action)}</td>
          <td>${escapeHtml(r.scope)}${r.cluster_id ? ` #${r.cluster_id}` : ""}</td>
          <td>${escapeHtml(r.reason || "")}</td>
          <td>${r.succeeded}/${r.succeeded + r.failed} успешно</td>
        </tr>`
      )
      .join("");
  } catch {
    body.innerHTML = "";
    empty.style.display = "block";
  }
}

// --- patterns (Bot Pattern Library, этап 9b) ------------------------------

async function loadPatterns() {
  el("patterns-admin-hint").style.display = canAdmin() ? "none" : "block";
  el("new-pattern-card").style.display = canAdmin() ? "block" : "none";

  const list = el("pattern-list");
  try {
    const resp = await apiFetch(`/api/moderation/patterns?profile=${encodeURIComponent(currentProfile())}`);
    const patterns = await resp.json();
    if (!patterns.length) {
      list.innerHTML = '<div class="empty">Паттернов нет</div>';
      return;
    }
    list.innerHTML = "";
    for (const p of patterns) {
      const row = document.createElement("div");
      row.className = `pattern-row${p.enabled ? "" : " disabled"}`;
      const metaParts = [];
      if (p.required_signal_names.length) metaParts.push(`сигналы: ${p.required_signal_names.map(signalLabel).join(", ")}`);
      if (p.min_families) metaParts.push(`семейств ≥ ${p.min_families}`);
      if (p.min_risk_score) metaParts.push(`risk ≥ ${p.min_risk_score}`);
      if (p.min_confidence) metaParts.push(`confidence ≥ ${p.min_confidence}`);
      if (p.min_cluster_size) metaParts.push(`размер кластера ≥ ${p.min_cluster_size}`);
      row.innerHTML = `
        <span class="pattern-name">${escapeHtml(p.name)}</span>
        <span class="pattern-meta">${escapeHtml(p.description || "")}${p.description ? " — " : ""}${escapeHtml(metaParts.join(" · "))}</span>
      `;
      const actions = document.createElement("div");
      actions.className = "pattern-actions";
      if (canAdmin()) {
        const toggleBtn = document.createElement("button");
        toggleBtn.className = "btn btn-ghost btn-small";
        toggleBtn.textContent = p.enabled ? "Отключить" : "Включить";
        toggleBtn.addEventListener("click", () => togglePattern(p.id, !p.enabled));
        actions.appendChild(toggleBtn);

        const deleteBtn = document.createElement("button");
        deleteBtn.className = "btn btn-danger btn-small";
        deleteBtn.textContent = "Удалить";
        deleteBtn.addEventListener("click", () => deletePattern(p.id, p.name));
        actions.appendChild(deleteBtn);
      }
      row.appendChild(actions);
      list.appendChild(row);
    }
  } catch (e) {
    list.innerHTML = '<div class="empty">Не удалось загрузить паттерны</div>';
  }
}

async function togglePattern(patternId, enabled) {
  try {
    const resp = await apiFetch(`/api/moderation/patterns/${patternId}/enabled`, {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile(), enabled }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    await loadPatterns();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
}

async function deletePattern(patternId, name) {
  try {
    const resp = await apiFetch(`/api/moderation/patterns/${patternId}/delete`, {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile() }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast(`Паттерн "${name}" удалён`, "success");
    await loadPatterns();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
}

el("btn-create-pattern").addEventListener("click", async () => {
  const name = el("np-name").value.trim();
  if (!name) {
    toast("Укажите имя паттерна", "error");
    return;
  }
  const signals = el("np-signals").value.split(",").map((s) => s.trim()).filter(Boolean);
  const payload = {
    profile: currentProfile(),
    name,
    description: el("np-description").value.trim(),
    required_signal_names: signals,
    min_families: parseInt(el("np-min-families").value, 10) || 0,
    min_risk_score: parseInt(el("np-min-risk").value, 10) || 0,
    min_confidence: parseFloat(el("np-min-confidence").value) || 0,
    min_cluster_size: parseInt(el("np-min-cluster").value, 10) || 0,
    weight: parseFloat(el("np-weight").value) || 1.0,
  };
  try {
    const resp = await apiFetch("/api/moderation/patterns", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast(`Паттерн "${name}" создан`, "success");
    el("np-name").value = "";
    el("np-description").value = "";
    el("np-signals").value = "";
    el("np-min-families").value = "0";
    el("np-min-risk").value = "0";
    el("np-min-confidence").value = "0";
    el("np-min-cluster").value = "0";
    el("np-weight").value = "1";
    await loadPatterns();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

// --- attack mode (этап 9c) ------------------------------------------------

function formatDuration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}м ${rem}с`;
}

async function loadAttackMode() {
  try {
    const resp = await apiFetch(`/api/moderation/attack_mode?profile=${encodeURIComponent(currentProfile())}`);
    const data = await resp.json();
    renderAttackStatus(data);
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
}

function renderAttackStatus(data) {
  const label = el("attack-state-label");
  const meta = el("attack-state-meta");
  const banner = el("attack-banner");
  const remaining = el("attack-remaining");
  const activateBtn = el("btn-attack-activate");
  const deactivateBtn = el("btn-attack-deactivate");
  const durationRow = el("attack-duration-row");

  if (data.active) {
    label.textContent = "ВКЛЮЧЁН";
    label.className = "big-state on";
    meta.textContent = `Активирован ${escapeHtml(data.activated_by || "?")}, осталось ${formatDuration(data.seconds_remaining || 0)}`;
    banner.style.display = "flex";
    remaining.textContent = formatDuration(data.seconds_remaining || 0);
    durationRow.style.display = "none";
    activateBtn.style.display = "none";
    deactivateBtn.style.display = canAdmin() ? "inline-block" : "none";
  } else {
    label.textContent = "ВЫКЛЮЧЕН";
    label.className = "big-state off";
    meta.textContent = "Обычные пороги детекции";
    banner.style.display = "none";
    durationRow.style.display = "flex";
    activateBtn.style.display = canAdmin() ? "inline-block" : "none";
    deactivateBtn.style.display = "none";
  }
  if (!canAdmin()) {
    activateBtn.style.display = "none";
    deactivateBtn.style.display = "none";
  }
}

el("btn-attack-activate").addEventListener("click", () => {
  const duration = parseInt(el("attack-duration").value, 10) || 1800;
  el("modal-title").textContent = "Включить Attack Mode?";
  el("modal-body").textContent =
    `Пороги детекции будут снижены для ВСЕГО канала на ${formatDuration(duration)}. ` +
    `BAN всё равно требует 2+ независимых семейства сигналов — этот инвариант Attack Mode обойти не может.`;
  pendingConfirm = async () => {
    try {
      const resp = await apiFetch("/api/moderation/attack_mode/activate", {
        method: "POST",
        body: JSON.stringify({ profile: currentProfile(), duration_seconds: duration }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail || resp.statusText);
      }
      toast("Attack Mode включён", "success");
      await loadAttackMode();
      await renderChannelRail(lastProfiles);
    } catch (e) {
      toast(`Ошибка: ${e.message}`, "error");
    }
  };
  el("modal-overlay").classList.add("open");
});

el("btn-attack-deactivate").addEventListener("click", async () => {
  try {
    const resp = await apiFetch("/api/moderation/attack_mode/deactivate", {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile() }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast("Attack Mode выключен", "success");
    await loadAttackMode();
    await renderChannelRail(lastProfiles);
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

// --- giveaway mode (FALSE-BAN-001 аудита) ---------------------------------

async function loadGiveawayMode() {
  try {
    const resp = await apiFetch(`/api/moderation/giveaway_mode?profile=${encodeURIComponent(currentProfile())}`);
    const data = await resp.json();
    renderGiveawayStatus(data);
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
}

function renderGiveawayStatus(data) {
  const label = el("giveaway-state-label");
  const meta = el("giveaway-state-meta");
  const activateBtn = el("btn-giveaway-activate");
  const deactivateBtn = el("btn-giveaway-deactivate");
  const durationRow = el("giveaway-duration-row");

  if (data.active) {
    label.textContent = "ВКЛЮЧЁН";
    label.className = "big-state on";
    meta.textContent = `Активирован ${escapeHtml(data.activated_by || "?")}, осталось ${formatDuration(data.seconds_remaining || 0)}`;
    durationRow.style.display = "none";
    activateBtn.style.display = "none";
    deactivateBtn.style.display = canAdmin() ? "inline-block" : "none";
  } else {
    label.textContent = "ВЫКЛЮЧЕН";
    label.className = "big-state off";
    meta.textContent = "Обычные пороги детекции";
    durationRow.style.display = "flex";
    activateBtn.style.display = canAdmin() ? "inline-block" : "none";
    deactivateBtn.style.display = "none";
  }
  if (!canAdmin()) {
    activateBtn.style.display = "none";
    deactivateBtn.style.display = "none";
  }
}

el("btn-giveaway-activate").addEventListener("click", () => {
  const duration = parseInt(el("giveaway-duration").value, 10) || 900;
  el("modal-title").textContent = "Включить Giveaway Mode?";
  el("modal-body").textContent =
    `Чувствительность детекции будет снижена для ВСЕГО канала на ${formatDuration(duration)} — ` +
    `используйте перед стартом розыгрыша, чтобы массовые "!giveaway" не выглядели как атака.`;
  pendingConfirm = async () => {
    try {
      const resp = await apiFetch("/api/moderation/giveaway_mode/activate", {
        method: "POST",
        body: JSON.stringify({ profile: currentProfile(), duration_seconds: duration }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail || resp.statusText);
      }
      toast("Giveaway Mode включён", "success");
      await loadGiveawayMode();
    } catch (e) {
      toast(`Ошибка: ${e.message}`, "error");
    }
  };
  el("modal-overlay").classList.add("open");
});

el("btn-giveaway-deactivate").addEventListener("click", async () => {
  try {
    const resp = await apiFetch("/api/moderation/giveaway_mode/deactivate", {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile() }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast("Giveaway Mode выключен", "success");
    await loadGiveawayMode();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

// Баннер в topbar виден на любом экране, не только на screen-attack — лёгкий
// фоновый опрос раз в 15 сек достаточен (панель узнаёт об изменении и через
// переход на сам экран Attack Mode, здесь только фоновая индикация).
async function pollAttackBanner() {
  try {
    const resp = await fetch(`/api/moderation/attack_mode?profile=${encodeURIComponent(currentProfile())}`);
    if (resp.status === 401) return;
    const data = await resp.json();
    const banner = el("attack-banner");
    const remaining = el("attack-remaining");
    if (data.active) {
      banner.style.display = "flex";
      remaining.textContent = formatDuration(data.seconds_remaining || 0);
    } else {
      banner.style.display = "none";
    }
  } catch {
    // тихая фоновая проверка — не мешаем пользователю тостами
  }
}

// --- stats (этап 9d) -------------------------------------------------

async function loadStats() {
  const tiles = el("stats-tiles");
  const fpBody = el("fp-stats-body");
  const fpEmpty = el("fp-stats-empty");
  try {
    const resp = await apiFetch(`/api/moderation/stats/daily?profile=${encodeURIComponent(currentProfile())}&days=30`);
    const days = await resp.json();
    const totals = days.reduce(
      (acc, d) => {
        acc.total_messages += d.total_messages || 0;
        acc.suspicious += d.suspicious || 0;
        acc.would_timeout += d.would_timeout || 0;
        acc.would_ban += d.would_ban || 0;
        acc.actual_timeouts += d.actual_timeouts || 0;
        acc.actual_bans += d.actual_bans || 0;
        acc.clusters += d.clusters || 0;
        acc.false_positives += d.false_positives || 0;
        return acc;
      },
      { total_messages: 0, suspicious: 0, would_timeout: 0, would_ban: 0, actual_timeouts: 0, actual_bans: 0, clusters: 0, false_positives: 0 }
    );
    const tileData = [
      ["Сообщений (30д)", totals.total_messages],
      ["Подозрительных", totals.suspicious],
      ["would_timeout", totals.would_timeout],
      ["would_ban", totals.would_ban],
      ["Реальных таймаутов", totals.actual_timeouts],
      ["Реальных банов", totals.actual_bans],
      ["Кластеров", totals.clusters],
      ["False positives", totals.false_positives],
    ];
    tiles.innerHTML = tileData
      .map(([label, value]) => `<div class="stat-tile"><div class="stat-value">${value}</div><div class="stat-label">${label}</div></div>`)
      .join("");
  } catch (e) {
    tiles.innerHTML = '<div class="empty">Не удалось загрузить статистику</div>';
  }

  try {
    const resp = await apiFetch(`/api/moderation/feedback?profile=${encodeURIComponent(currentProfile())}&limit=500`);
    const feedback = await resp.json();
    const bySignal = new Map();
    for (const f of feedback) {
      const entry = bySignal.get(f.signal_name) || { total: 0, fp: 0 };
      entry.total += 1;
      if (f.decision === "FALSE_POSITIVE") entry.fp += 1;
      bySignal.set(f.signal_name, entry);
    }
    const rows = [...bySignal.entries()]
      .map(([name, e]) => ({ name, total: e.total, fp: e.fp, rate: e.total ? e.fp / e.total : 0 }))
      .sort((a, b) => b.rate - a.rate);
    if (!rows.length) {
      fpBody.innerHTML = "";
      fpEmpty.style.display = "block";
    } else {
      fpEmpty.style.display = "none";
      fpBody.innerHTML = rows
        .map(
          (r) => `
          <tr>
            <td>${escapeHtml(r.name)}</td>
            <td>${r.total}</td>
            <td>${r.fp}</td>
            <td>
              <div style="display:flex;align-items:center;gap:8px;">
                <div class="fp-bar-track"><div class="fp-bar-fill" style="--fill:${r.rate};"></div></div>
                <span>${(r.rate * 100).toFixed(0)}%</span>
              </div>
            </td>
          </tr>`
        )
        .join("");
    }
  } catch (e) {
    fpBody.innerHTML = "";
    fpEmpty.style.display = "block";
  }
}

// --- settings: токен бота + config/moderation.yml ---------------------

async function loadSettings() {
  await Promise.all([
    loadBotTokenStatus(),
    loadChatTokenStatus(),
    loadConfig(),
    loadDiscordWebhook(),
    loadContentModeration(),
  ]);
}

// --- Discord-webhook (направление 01 master-plan.html) --------------------

async function loadDiscordWebhook() {
  const urlInput = el("discord-webhook-url");
  const status = el("discord-webhook-status");
  const toggleBtn = el("btn-toggle-discord-webhook");
  const thresholdRow = el("discord-alert-threshold-row");
  try {
    const resp = await apiFetch(`/api/moderation/discord_webhook?profile=${encodeURIComponent(currentProfile())}`);
    const data = await resp.json();
    if (data.configured) {
      urlInput.placeholder = data.url;
      status.textContent = data.enabled ? "подключено" : "выключено";
      status.style.color = data.enabled ? "var(--success)" : "var(--text-faint)";
      toggleBtn.textContent = data.enabled ? "Выключить" : "Включить";
      toggleBtn.style.display = canAdmin() ? "inline-block" : "none";
      toggleBtn.dataset.enabled = String(data.enabled);
      toggleBtn.dataset.url = data.url;
      thresholdRow.style.display = "block";
      const pct = Math.round((data.alert_confidence_threshold ?? 0.9) * 100);
      el("discord-alert-threshold").value = String(pct);
      el("discord-alert-threshold-value").textContent = `${pct}%`;
    } else {
      status.textContent = "не настроено";
      status.style.color = "var(--text-faint)";
      toggleBtn.style.display = "none";
      thresholdRow.style.display = "none";
    }
  } catch (e) {
    toast(`Ошибка загрузки настроек Discord: ${e.message}`, "error");
  }
  const canEdit = canAdmin();
  urlInput.disabled = !canEdit;
  el("btn-save-discord-webhook").disabled = !canEdit;
  el("btn-save-discord-webhook").title = canEdit ? "" : "Требуется роль ADMIN и выше";
  el("discord-alert-threshold").disabled = !canEdit;
  el("btn-save-alert-threshold").disabled = !canEdit;
}

el("btn-save-discord-webhook").addEventListener("click", async () => {
  const url = el("discord-webhook-url").value.trim();
  if (!url) {
    toast("Вставьте адрес webhook перед сохранением", "error");
    return;
  }
  try {
    const resp = await apiFetch("/api/moderation/discord_webhook", {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile(), url, enabled: true }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    el("discord-webhook-url").value = "";
    toast("Discord-webhook сохранён", "success");
    await loadDiscordWebhook();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

el("btn-toggle-discord-webhook").addEventListener("click", async () => {
  const btn = el("btn-toggle-discord-webhook");
  const nowEnabled = btn.dataset.enabled !== "true";
  try {
    const resp = await apiFetch("/api/moderation/discord_webhook", {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile(), url: btn.dataset.url, enabled: nowEnabled }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast(nowEnabled ? "Уведомления включены" : "Уведомления выключены", "success");
    await loadDiscordWebhook();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

el("discord-alert-threshold").addEventListener("input", (e) => {
  el("discord-alert-threshold-value").textContent = `${e.target.value}%`;
});

el("btn-save-alert-threshold").addEventListener("click", async () => {
  const pct = Number(el("discord-alert-threshold").value);
  try {
    const resp = await apiFetch("/api/moderation/discord_webhook/alert_threshold", {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile(), threshold: pct / 100 }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast(`Порог алерта сохранён: ${pct}%`, "success");
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

// --- Модерация контента: словарный детектор (Rule Engine) -----------------
//
// content_moderation_enabled управляет только тем, выполняется ли действие —
// совпадения со словарём видны в аудите независимо от переключателя (см.
// cigilbot/content/policy.py, режим наблюдателя).

const CONTENT_CATEGORY_LABELS = {
  racism: "Расизм/оскорбления",
  threats: "Угрозы насилия",
  advertising: "Реклама/спам",
};

async function loadContentModeration() {
  await Promise.all([loadContentSettings(), loadContentRules()]);
}

async function loadContentSettings() {
  const checkbox = el("content-moderation-enabled");
  const status = el("content-moderation-status");
  try {
    const resp = await apiFetch(`/api/moderation/content_settings?profile=${encodeURIComponent(currentProfile())}`);
    if (!resp.ok) {
      const errBody = await resp.json().catch(() => ({}));
      throw new Error(errBody.detail || resp.statusText);
    }
    const data = await resp.json();
    checkbox.checked = data.enabled;
    status.textContent = data.enabled
      ? "Действия выполняются автоматически"
      : "Только наблюдение — действия не выполняются";
    status.style.color = data.enabled ? "var(--success)" : "var(--text-faint)";
  } catch (e) {
    toast(`Ошибка загрузки настроек модерации контента: ${e.message}`, "error");
  }
  checkbox.disabled = !canAdmin();
}

el("content-moderation-enabled").addEventListener("change", async (e) => {
  const enabled = e.target.checked;
  try {
    const resp = await apiFetch("/api/moderation/content_settings", {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile(), enabled }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    toast(enabled ? "Модерация контента включена" : "Модерация контента выключена", "success");
    await loadContentSettings();
  } catch (err) {
    e.target.checked = !enabled;
    toast(`Ошибка: ${err.message}`, "error");
  }
});

async function loadContentRules() {
  const body = el("content-rules-body");
  const empty = el("content-rules-empty");
  const canEdit = canAdmin();
  try {
    const resp = await apiFetch(`/api/moderation/content_rules?profile=${encodeURIComponent(currentProfile())}`);
    if (!resp.ok) {
      const errBody = await resp.json().catch(() => ({}));
      throw new Error(errBody.detail || resp.statusText);
    }
    const rules = await resp.json();
    if (rules.length === 0) {
      body.innerHTML = "";
      empty.style.display = "block";
    } else {
      empty.style.display = "none";
      body.innerHTML = rules
        .map(
          (r) => `
          <tr>
            <td>${escapeHtml(CONTENT_CATEGORY_LABELS[r.category] || r.category)}</td>
            <td>${escapeHtml(r.phrase)}</td>
            <td style="color:${r.enabled ? "var(--success)" : "var(--text-faint)"}">${r.enabled ? "включено" : "выключено"}</td>
            <td style="text-align:right;white-space:nowrap;">
              <button class="btn btn-ghost btn-small content-rule-toggle" data-id="${r.id}" data-enabled="${r.enabled}" ${canEdit ? "" : "disabled"}>${r.enabled ? "Выключить" : "Включить"}</button>
              <button class="btn btn-ghost btn-small content-rule-delete" data-id="${r.id}" ${canEdit ? "" : "disabled"}>Удалить</button>
            </td>
          </tr>`
        )
        .join("");
    }
  } catch (e) {
    body.innerHTML = "";
    empty.style.display = "block";
    toast(`Ошибка загрузки правил: ${e.message}`, "error");
  }
  el("content-rule-category").disabled = !canEdit;
  el("content-rule-phrase").disabled = !canEdit;
  el("btn-add-content-rule").disabled = !canEdit;
}

el("content-rules-body").addEventListener("click", async (e) => {
  const toggleBtn = e.target.closest(".content-rule-toggle");
  const deleteBtn = e.target.closest(".content-rule-delete");
  if (toggleBtn) {
    const id = toggleBtn.dataset.id;
    const nowEnabled = toggleBtn.dataset.enabled !== "true";
    try {
      const resp = await apiFetch(`/api/moderation/content_rules/${id}/enabled`, {
        method: "POST",
        body: JSON.stringify({ profile: currentProfile(), enabled: nowEnabled }),
      });
      if (!resp.ok) throw new Error((await resp.json().catch(() => ({}))).detail || resp.statusText);
      await loadContentRules();
    } catch (err) {
      toast(`Ошибка: ${err.message}`, "error");
    }
  } else if (deleteBtn) {
    const id = deleteBtn.dataset.id;
    try {
      const resp = await apiFetch(`/api/moderation/content_rules/${id}/delete`, {
        method: "POST",
        body: JSON.stringify({ profile: currentProfile() }),
      });
      if (!resp.ok) throw new Error((await resp.json().catch(() => ({}))).detail || resp.statusText);
      toast("Правило удалено", "success");
      await loadContentRules();
    } catch (err) {
      toast(`Ошибка: ${err.message}`, "error");
    }
  }
});

el("btn-add-content-rule").addEventListener("click", async () => {
  const category = el("content-rule-category").value;
  const phrase = el("content-rule-phrase").value.trim();
  if (!phrase) {
    toast("Введите слово или фразу перед добавлением", "error");
    return;
  }
  try {
    const resp = await apiFetch("/api/moderation/content_rules", {
      method: "POST",
      body: JSON.stringify({ profile: currentProfile(), category, phrase }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || resp.statusText);
    }
    el("content-rule-phrase").value = "";
    toast("Правило добавлено", "success");
    await loadContentRules();
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

async function loadBotTokenStatus() {
  const badge = el("token-status-badge");
  const meta = el("token-status-meta");
  const btn = el("btn-get-bot-token");
  try {
    const resp = await fetch("/auth/bot/status");
    const data = await resp.json();
    if (data.configured) {
      badge.textContent = `настроен (${data.bot_login})`;
      badge.className = "token-status-badge ok";
      meta.textContent = "Executor может выполнять реальные действия этим токеном.";
    } else {
      badge.textContent = "не настроен";
      badge.className = "token-status-badge missing";
      meta.textContent = "Executor не сможет выполнять реальные действия, пока токен не получен.";
    }
  } catch {
    badge.textContent = "неизвестно";
    badge.className = "token-status-badge missing";
  }
  btn.disabled = !canAdmin();
  btn.title = canAdmin() ? "" : "Требуется роль ADMIN и выше";
}

el("btn-get-bot-token").addEventListener("click", () => {
  el("modal-title").textContent = "Получить токен бота?";
  // innerHTML — единственное место в файле (везде остальном textContent,
  // см. остальные modal-body): текст статичный литерал, не пользовательский
  // ввод, нужен только чтобы дать ссылку на twitch.tv/logout и жирный текст.
  el("modal-body").innerHTML =
    "На следующем экране войдите на Twitch <b>ПОД АККАУНТОМ БОТА</b> (не под своим личным) — " +
    "именно этот аккаунт получит права на реальные баны/таймауты. Аккаунт бота также " +
    "должен быть модератором канала.<br><br>" +
    "<b>Если вы только что входили в панель под другим Twitch-аккаунтом:</b> Twitch " +
    "запомнил его в этом браузере и может подставить его автоматически, минуя выбор " +
    'аккаунта. Сначала выйдите из Twitch — <a href="https://www.twitch.tv/logout" ' +
    'target="_blank" rel="noopener">twitch.tv/logout</a> (откроется в новой вкладке), ' +
    "затем возвращайтесь сюда и жмите «Продолжить».";
  pendingConfirm = async () => {
    window.location.href = "/auth/bot/login";
  };
  el("modal-overlay").classList.add("open");
});

async function loadChatTokenStatus() {
  const badge = el("chat-token-status-badge");
  const meta = el("chat-token-status-meta");
  const btn = el("btn-get-chat-token");
  try {
    const resp = await fetch("/auth/bot/chat_status");
    const data = await resp.json();
    if (data.configured) {
      badge.textContent = `настроен (${data.bot_login})`;
      badge.className = "token-status-badge ok";
      meta.textContent = "Отправка сообщений из панели доходит до чата этим токеном.";
    } else {
      badge.textContent = "не настроен";
      badge.className = "token-status-badge missing";
      meta.textContent = "Отправка сообщений из панели не будет доходить до чата, пока токен не получен.";
    }
  } catch {
    badge.textContent = "неизвестно";
    badge.className = "token-status-badge missing";
  }
  btn.disabled = !canAdmin();
  btn.title = canAdmin() ? "" : "Требуется роль ADMIN и выше";
}

el("btn-get-chat-token").addEventListener("click", () => {
  el("modal-title").textContent = "Получить чат-токен бота?";
  el("modal-body").innerHTML =
    "На следующем экране войдите на Twitch <b>ПОД АККАУНТОМ БОТА</b> (не под своим личным) — " +
    "именно этот аккаунт будет писать сообщения в чат от панели. В отличие от токена банов " +
    "выше, права модератора здесь не обязательны — достаточно, чтобы бот мог писать в чат.<br><br>" +
    "<b>Если вы только что входили в панель под другим Twitch-аккаунтом:</b> Twitch " +
    "запомнил его в этом браузере и может подставить его автоматически, минуя выбор " +
    'аккаунта. Сначала выйдите из Twitch — <a href="https://www.twitch.tv/logout" ' +
    'target="_blank" rel="noopener">twitch.tv/logout</a> (откроется в новой вкладке), ' +
    "затем возвращайтесь сюда и жмите «Продолжить».";
  pendingConfirm = async () => {
    window.location.href = "/auth/bot/chat_login";
  };
  el("modal-overlay").classList.add("open");
});

let configLoaded = false;

async function loadConfig() {
  el("cfg-parse-error").classList.remove("show");
  el("cfg-restart-notice").classList.remove("show");
  try {
    const resp = await apiFetch("/api/moderation/config");
    if (resp.status === 404) {
      el("settings-not-loaded").style.display = "block";
      configLoaded = false;
      return;
    }
    el("settings-not-loaded").style.display = "none";
    const data = await resp.json();

    el("cfg-yaml-editor").value = data.yaml_text;
    if (data.parse_error) {
      el("cfg-parse-error").textContent = `Текущий файл не парсится: ${data.parse_error}`;
      el("cfg-parse-error").classList.add("show");
    }
    if (data.mode) el("cfg-mode").value = data.mode;
    if (data.risk_thresholds) {
      el("cfg-risk-observe").value = data.risk_thresholds.observe;
      el("cfg-risk-timeout").value = data.risk_thresholds.timeout;
      el("cfg-risk-ban").value = data.risk_thresholds.ban;
    }
    configLoaded = true;
  } catch (e) {
    toast(`Ошибка загрузки конфига: ${e.message}`, "error");
  }
  const canEdit = canAdmin();
  el("cfg-yaml-editor").disabled = !canEdit;
  el("btn-save-config").disabled = !canEdit;
  el("btn-save-config").title = canEdit ? "" : "Требуется роль ADMIN и выше";
}

// Быстрые поля (mode/пороги) — это удобный редактор поверх того же текста
// в yaml-editor, не отдельный источник правды: при изменении полей
// подставляем значения прямо в YAML-текст простой строковой заменой команд
// верхнего уровня, а не пересобираем весь YAML — так ручные правки
// остального файла в textarea не теряются.
function applyQuickFieldsToYaml() {
  let text = el("cfg-yaml-editor").value;
  const mode = el("cfg-mode").value;
  const observe = el("cfg-risk-observe").value;
  const timeout = el("cfg-risk-timeout").value;
  const ban = el("cfg-risk-ban").value;

  if (/^mode:.*$/m.test(text)) {
    text = text.replace(/^mode:.*$/m, `mode: ${mode}`);
  } else {
    text = `mode: ${mode}\n${text}`;
  }

  const thresholdsBlock = `risk_thresholds:\n  observe: ${observe}\n  timeout: ${timeout}\n  ban: ${ban}`;
  if (/^risk_thresholds:\n(?:[ \t].*\n?)*/m.test(text)) {
    text = text.replace(/^risk_thresholds:\n(?:[ \t].*\n?)*/m, `${thresholdsBlock}\n`);
  } else {
    text = `${text}\n${thresholdsBlock}\n`;
  }

  el("cfg-yaml-editor").value = text;
}

["cfg-mode", "cfg-risk-observe", "cfg-risk-timeout", "cfg-risk-ban"].forEach((id) => {
  el(id).addEventListener("change", () => {
    if (configLoaded) applyQuickFieldsToYaml();
  });
});

el("btn-reload-config").addEventListener("click", () => loadConfig());

el("btn-save-config").addEventListener("click", async () => {
  el("cfg-parse-error").classList.remove("show");
  el("cfg-restart-notice").classList.remove("show");
  try {
    const resp = await apiFetch("/api/moderation/config", {
      method: "POST",
      body: JSON.stringify({ yaml_text: el("cfg-yaml-editor").value }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      el("cfg-parse-error").textContent = body.detail || resp.statusText;
      el("cfg-parse-error").classList.add("show");
      return;
    }
    el("cfg-restart-notice").classList.add("show");
    toast("Конфиг сохранён", "success");
  } catch (e) {
    toast(`Ошибка: ${e.message}`, "error");
  }
});

// --- WebSocket live-обновления ---------------------------------------

function connectWs() {
  if (state.ws) {
    state.ws.close();
  }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/moderation/ws`);
  state.ws = ws;

  ws.addEventListener("open", () => {
    ws.send(currentProfile());
    setConnStatus(true);
    state.wsRetryMs = 1000;
  });
  ws.addEventListener("message", (ev) => {
    try {
      const data = JSON.parse(ev.data);
      renderClusters(data.clusters);
      renderVerdicts(data.verdicts);
      highlightClusterIfPending();
    } catch {
      // игнорируем нераспарсенные сообщения — не роняем соединение
    }
  });
  ws.addEventListener("close", () => {
    setConnStatus(false);
    if (el("app-root").style.display !== "none") {
      setTimeout(connectWs, state.wsRetryMs);
      state.wsRetryMs = Math.min(state.wsRetryMs * 1.5, 15000);
    }
  });
  ws.addEventListener("error", () => ws.close());
}

function setConnStatus(on) {
  el("conn-dot").className = `conn-dot ${on ? "on" : "off"}`;
  el("conn-label").textContent = on ? "live" : "переподключение…";
}

// --- Content: живая лента срабатываний словарного детектора --------------
// Отдельный WebSocket от основного /ws (пользователь 2026-08-13: "не хочу
// смешивать спам атаку и модерацию вместе") — подключается только пока
// открыт экран Content, не постоянно, как основной канал.

const CONTENT_CATEGORY_FEED_LABELS = {
  racism: "Расизм/оскорбления",
  threats: "Угрозы насилия",
  advertising: "Реклама/спам",
};

// Набор длительностей для ручного таймаута из ленты Content (пользователь
// 2026-08-13: "нужно сделать отдельный таймаут на разное кол-во времени") —
// без этого TIMEOUT всегда уходил с duration_seconds=null, и executor.py
// молча подставлял свои дефолтные 10 минут независимо от тяжести нарушения.
const CONTENT_TIMEOUT_OPTIONS = [
  { label: "1м", seconds: 60 },
  { label: "5м", seconds: 300 },
  { label: "10м", seconds: 600 },
  { label: "1ч", seconds: 3600 },
  { label: "1д", seconds: 86400 },
  { label: "2нед", seconds: 1209600 },
];

const MANUAL_ACTION_LABELS = {
  TIMEOUT: "таймаут выдан",
  BAN: "бан выдан",
  DELETE_MESSAGES: "сообщение удалено",
};

function renderContentEvents(events) {
  const body = el("content-events-body");
  const empty = el("content-events-empty");
  if (!events || events.length === 0) {
    body.innerHTML = "";
    empty.style.display = "block";
    return;
  }
  empty.style.display = "none";
  const canModerate = ["MODERATOR", "ADMIN", "OWNER"].includes(state.role);
  body.innerHTML = events
    .map((e) => {
      const when = new Date(e.created_at * 1000).toLocaleTimeString();
      const actionClass = e.action.toLowerCase();
      const enforcedNote = e.enforced
        ? ""
        : `<div class="content-enforced-note">не выполнено${e.blocked_by ? ` (${escapeHtml(e.blocked_by)})` : ""}</div>`;
      const userId = escapeHtml(e.user_id);
      const login = escapeHtml(e.login);

      // Пользователь 2026-08-13: "можем как-то помечать сообщения (которое
      // было забанено/удалено/таймаут)... может цвет более тусклым делать".
      // manual_action переживает обновление страницы (см. миграцию 016) —
      // строка гаснет и кнопки заменяются меткой того, что уже сделано.
      if (e.manual_action) {
        const label = MANUAL_ACTION_LABELS[e.manual_action] || e.manual_action;
        return `
          <tr class="content-row-resolved">
            <td>${escapeHtml(when)}</td>
            <td>${login}</td>
            <td>${escapeHtml(CONTENT_CATEGORY_FEED_LABELS[e.category] || e.category)}</td>
            <td>${escapeHtml(e.matched_phrase)}</td>
            <td><span class="content-action-pill ${actionClass}">${escapeHtml(e.action)}</span></td>
            <td>${enforcedNote}</td>
            <td class="content-manual-actions"><span class="content-resolved-note">✓ ${escapeHtml(label)}${e.manual_action_by ? ` — ${escapeHtml(e.manual_action_by)}` : ""}</span></td>
          </tr>`;
      }

      const deleteBtn = e.twitch_message_id
        ? `<button class="btn btn-ghost btn-small content-manual-action" data-event-id="${e.id}" data-action="DELETE_MESSAGES" data-user-id="${userId}" data-login="${login}" data-message-id="${escapeHtml(e.twitch_message_id)}" ${canModerate ? "" : "disabled"}>Удалить</button>`
        : "";
      const timeoutBtns = CONTENT_TIMEOUT_OPTIONS.map(
        (opt) =>
          `<button class="btn btn-ghost btn-small content-manual-action" data-event-id="${e.id}" data-action="TIMEOUT" data-user-id="${userId}" data-login="${login}" data-duration="${opt.seconds}" ${canModerate ? "" : "disabled"}>${opt.label}</button>`
      ).join("");
      return `
        <tr>
          <td>${escapeHtml(when)}</td>
          <td>${login}</td>
          <td>${escapeHtml(CONTENT_CATEGORY_FEED_LABELS[e.category] || e.category)}</td>
          <td>${escapeHtml(e.matched_phrase)}</td>
          <td><span class="content-action-pill ${actionClass}">${escapeHtml(e.action)}</span></td>
          <td>${enforcedNote}</td>
          <td class="content-manual-actions">
            ${deleteBtn}
            ${timeoutBtns}
            <button class="btn btn-danger btn-small content-manual-action" data-event-id="${e.id}" data-action="BAN" data-user-id="${userId}" data-login="${login}" ${canModerate ? "" : "disabled"}>Бан</button>
          </td>
        </tr>`;
    })
    .join("");
}

function confirmContentManualAction(eventId, action, userId, login, messageId, durationSeconds) {
  const durationLabel = CONTENT_TIMEOUT_OPTIONS.find((o) => o.seconds === durationSeconds)?.label;
  const verbs = {
    BAN: "забанить",
    TIMEOUT: `выдать таймаут на ${durationLabel || "10м"}`,
    DELETE_MESSAGES: "удалить сообщение",
  };
  el("modal-title").textContent = `${action} — подтвердите`;
  el("modal-body").textContent =
    action === "DELETE_MESSAGES"
      ? `Вы собираетесь удалить сообщение пользователя ${login} (ручное модерирование из ленты Content). ` +
        `Действие попадёт в аудит от имени "${state.login}".`
      : `Вы собираетесь ${verbs[action]} пользователю ${login} (ручное модерирование из ленты Content, ` +
        `автоматические действия сейчас выключены — это решение принимаете лично вы). ` +
        `Действие попадёт в аудит от имени "${state.login}".`;
  pendingConfirm = async () => {
    try {
      const resp = await apiFetch("/api/moderation/actions", {
        method: "POST",
        body: JSON.stringify({
          profile: currentProfile(),
          action,
          target_user_ids: action === "DELETE_MESSAGES" ? [] : [userId],
          message_ids: action === "DELETE_MESSAGES" ? [messageId] : [],
          duration_seconds: action === "TIMEOUT" ? durationSeconds : null,
          reason: `Ручное модерирование из ленты Content (${login})`,
        }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail || resp.statusText);
      }
      toast(`Задание поставлено в очередь (${action}, ${login})`, "success");
      // Пометка "разобрано" — не критична для самого действия (оно уже в
      // очереди), поэтому сбой здесь не должен выглядеть как ошибка всей
      // операции, только тихо не погасить строку до следующего WS-снимка.
      try {
        await apiFetch(`/api/moderation/content_events/${eventId}/manual_action`, {
          method: "POST",
          body: JSON.stringify({ profile: currentProfile(), action }),
        });
      } catch {
        // см. комментарий выше
      }
    } catch (e) {
      toast(`Ошибка: ${e.message}`, "error");
    }
  };
  el("modal-overlay").classList.add("open");
}

el("content-events-body").addEventListener("click", (e) => {
  const btn = e.target.closest(".content-manual-action");
  if (!btn) return;
  const duration = btn.dataset.duration ? Number(btn.dataset.duration) : undefined;
  confirmContentManualAction(
    Number(btn.dataset.eventId), btn.dataset.action, btn.dataset.userId, btn.dataset.login,
    btn.dataset.messageId, duration
  );
});

function connectContentWs() {
  if (state.contentWs) {
    state.contentWs.close();
  }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/moderation/content_ws`);
  state.contentWs = ws;

  ws.addEventListener("open", () => {
    ws.send(currentProfile());
  });
  ws.addEventListener("message", (ev) => {
    try {
      const data = JSON.parse(ev.data);
      renderContentEvents(data.events);
    } catch {
      // игнорируем нераспарсенные сообщения — не роняем соединение
    }
  });
  ws.addEventListener("close", () => {
    if (state.contentWs === ws && el("screen-content").classList.contains("active")) {
      setTimeout(connectContentWs, 2000);
    }
  });
  ws.addEventListener("error", () => ws.close());
}

function disconnectContentWs() {
  if (state.contentWs) {
    state.contentWs.close();
    state.contentWs = null;
  }
}

// --- инициализация ----------------------------------------------------

document.querySelectorAll(".nav-item").forEach((item) => {
  item.addEventListener("click", () => switchScreen(item.dataset.screen));
  // role="button" на div не даёт активацию по Enter/Space бесплатно, как
  // у нативной <button> — добавляем вручную для клавиатурной доступности.
  item.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      switchScreen(item.dataset.screen);
    }
  });
});

el("profile-select").addEventListener("change", () => {
  localStorage.setItem("mod.profile", currentProfile());
  connectWs();
  loadAudit();
});

// --- статус и управление чат-ботом (main.py, twitch-bots) --------------
// Отдельно от запуска профилей на экране "Боты": там процесс поднимается
// по профилю (свой .env.<profile>, свой INSTANCE), здесь — ровно один
// мульти-канальный бот модерации. Раньше это были ещё и разные процессы
// панели на разных портах, и оговорка "не проксируя через 8765" имела
// смысл; теперь оба экрана в одном приложении (см. panel/server.py).

async function refreshChatbotStatus() {
  const pulse = el("chatbotPulse");
  const text = el("chatbotStatusText");
  if (!pulse || !text) return;
  try {
    const resp = await apiFetch("/api/registry/bot/status");
    const s = await resp.json();
    pulse.classList.toggle("on", s.running);
    text.textContent = s.running ? `работает (pid ${s.pid})` : "остановлен";
  } catch {
    text.textContent = "нет данных";
  }
}

el("btn-chatbot-start").addEventListener("click", async () => {
  el("btn-chatbot-start").disabled = true;
  try {
    const resp = await apiFetch("/api/registry/bot/start", { method: "POST" });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      alert(err.detail || "Не удалось запустить бота");
    }
  } finally {
    el("btn-chatbot-start").disabled = false;
    await refreshChatbotStatus();
  }
});

el("btn-chatbot-stop").addEventListener("click", async () => {
  el("btn-chatbot-stop").disabled = true;
  try {
    await apiFetch("/api/registry/bot/stop", { method: "POST" });
  } finally {
    el("btn-chatbot-stop").disabled = false;
    await refreshChatbotStatus();
  }
});

(async function init() {
  const ok = await checkAuth();
  if (!ok) return;
  await loadProfiles();
  const hasDeepLink = new URLSearchParams(window.location.search).has("channel");
  if (hasDeepLink) {
    applyDeepLinkFromUrl();
  } else {
    connectWs();
    await loadChannels();
  }
  await pollAttackBanner();
  setInterval(pollAttackBanner, 15000);
  await refreshChatbotStatus();
  setInterval(refreshChatbotStatus, 5000);
})();
