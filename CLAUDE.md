# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language

Code comments, docstrings, log messages, user-facing strings, and commit messages in this
repository are written in **Russian**. Match that when editing — do not translate existing
Russian prose to English, and write new comments in Russian.

## Repository layout

One project, one process pair. Packages live under `src/`, with `cigilbot/` split into layers.

```
src/
  bot/            chat bot: Twitch IRC, DeepSeek replies, voice input
  cigilbot/       moderation engine, by layer:
    domain/         pure logic — types, scoring, confidence, policy, clustering, config
    storage/        SQLite — three independent store+migrations pairs
    integrations/   Twitch Helix, Discord webhooks, bot process control
    orchestration/  engine/pipeline/executor — wire the layers together
    detectors/      spam/bot detectors, a vertical slice (unchanged internally)
    content/        banned-word rule engine, a vertical slice (unchanged internally)
  panel/          web panel (port 8766), two screens, one login
  paths.py        the single source of truth for where things live — outside all three
                   packages, a package itself (not a bare module) so editable install
                   redirects it to src/ instead of copying it into site-packages
config/         detector thresholds and per-channel profiles
prompts/        saved bot prompts
scripts/        one-offs: registry import, replay, reports, admin merge
tests/          615 tests, one suite
docs/           plans and per-area descriptions
main.py         entry point: chat + moderation (imported by run.py, not run directly)
run.py          the one command: chat bot, moderation, panel, voice
voice_main.py   entry point: voice input (child process)
var/            runtime state — databases, logs, pids (gitignored)
```

It used to be three directories under `apps/`, and that boundary generated code: `sys.path`
inserts in `main.py`, a bootstrap module in `panel/__init__.py` whose only job was fixing
imports, three `paths.py` with duplicated constants plus a test guarding their agreement, and
three `pyproject.toml` with `mypy_path` reaching through `../`. All of it is gone.

Packages later moved under `src/`, and `cigilbot/` gained layers inside — not a return to three
directories: one `pip install -e .`, one `.venv`, one `pyproject.toml`. Imports are unchanged
(`import cigilbot`, `import bot`, `import panel`, `import paths`); only what's on disk moved.
`paths.py` is a package (`src/paths/__init__.py`), not a bare file — hatchling's editable
install *copies* single force-included files into site-packages, which breaks
`Path(__file__).resolve()`; a package with one `__init__.py` gets an honest redirect instead,
the same guarantee the other three packages get.

| | `bot` | `cigilbot` | `panel` |
|---|---|---|---|
| Purpose | AI chat companion (DeepSeek) + voice input | Anti-spam moderation engine | Web panel for both, port 8766 |
| Type-checked | no | yes, strict | yes except `bots_api.py` |

**Moderation runs inside the bot process.** It used to be a separate process per channel
(`consumer.py`) fed by a `mod_inbox` table on disk, under a supervisor. That boundary is gone:
`main.py` builds a `ModerationHub` (`cigilbot/orchestration/pipeline.py`) that holds one
`ModerationEngine` per channel and reconciles the set against the Channel Registry itself.

What survived the merge, and must keep surviving:

- **Reading chat never waits for moderation.** `hub.submit()` is *not* a coroutine — it drops
  the event into an in-memory queue and returns. Make it `async` and every chat message starts
  paying for a SQLite write and a Helix round-trip.
- **Per-channel state stays separate** — one engine, one queue, one `mod.<id>.db` per channel.
  The engine is stateful (sliding window, clusters); one shared engine would be wrong, not
  merely slower.
- **Strict ordering inside a channel** — a single consumer task per queue, no parallelism.

What it cost, deliberately: the queue no longer survives a crash and is no longer unbounded.
`mod_inbox` lived on disk and piled up harmlessly while moderation was down; the in-memory
queue is capped at `QUEUE_MAXSIZE` and **drops** events when full, because waiting would push
backpressure into the IRC read. Drops are counted and logged. Crash isolation is likewise
gone — mitigated by every background loop catching its own exceptions, so one channel failing
does not disturb the others, but they now share a process.

**The panel is deliberately a separate process.** It computes and executes nothing, only
writing `desired_state`, patterns and Attack Mode into the databases the bot reads — so it can
crash and restart without touching moderation. That used to be false: the supervisor lived
inside the panel, so closing it stopped restart-on-crash for consumers.

Two processes total: the bot (chat + moderation) and the panel. One `.venv`, one `.env`, both
in the repo root. Voice dependencies (~600 MB) are optional, in `requirements-voice.txt`.

Python 3.12 on Windows. `pyproject.toml` has a minimal `[build-system]`/`[project]` — not to
publish a package (`dependencies` is deliberately empty; `requirements*.txt` stays the single
source of truth), but so `pip install -e .` makes `src/bot`, `src/cigilbot`, `src/panel`,
`src/paths` importable at all. Python only adds the launched script's own directory to
`sys.path` (the repo root, where `run.py`/`main.py` live), not `src/`.

## Commands

One venv in the repo root, shared by everything. `.venv/` is gitignored, so on a fresh clone
it must be created first. Everything runs from the repo root — there are no per-project
directories to `cd` into any more.

```powershell
# Setup (once)
python -m venv .venv
.\.venv\Scripts\pip install -r requirements-dev.txt   # includes requirements.txt
.\.venv\Scripts\pip install -e . --no-deps             # makes src/bot, src/cigilbot, src/panel, src/paths importable
copy .env.example .env
.\.venv\Scripts\pip install -r requirements-voice.txt # only if VOICE_ENABLED=true

# Checks
.\.venv\Scripts\pytest
.\.venv\Scripts\pytest tests/test_engine.py                    # one file
.\.venv\Scripts\pytest tests/test_engine.py::test_name -x      # one test
.\.venv\Scripts
uff check .
.\.venv\Scripts\mypy                                           # config-driven, no args
```

`pytest` is configured with `asyncio_mode = "auto"` — async tests need no decorator.
`filterwarnings` turns `DeprecationWarning` from own code into an error. A `slow` marker is
registered but currently unused. The suite takes ~35 s but the process lingers for about a
minute afterwards before exiting; this predates all of the recent restructuring and is not a
hang.

`bot/` is not type-checked: it was written without annotations and is excluded on purpose,
along with `panel/bots_api.py` (the same unannotated code, formerly the bots panel). Both are
pulled in under `follow_imports = "skip"` so mypy does not wander into them from checked code.

Running the stack — **one command**:

```powershell
.\.venv\Scripts\python run.py
```

`run.py` starts the chat bot, the moderation engines, the panel (8766) and, when
`VOICE_ENABLED=true`, `voice_main.py` as a child process. Ctrl+C stops all of it.

Two OS processes, and the split has a reason. Bot, moderation and panel share one event loop —
`Bot.start()` and `uvicorn.Server.serve()` are both coroutines, so there is nothing to gain by
separating them. Voice stays a child process because faster-whisper and sounddevice in the
same process as twitchio crashed it without a traceback (native-thread conflict, recorded in
`bot/voice_queue.py`); that boundary is an incident report, not a preference.

Neither half kills the other. A dead bot (expired token) leaves the panel up — the panel is
where you fix the token. A dead panel (port taken) leaves the bot reading chat. Each failure
is logged the moment it happens, so a half-working process never looks healthy.

Inside `run.py` the panel gets `app.state.in_bot_process = True`, and the Registry screen's
start/stop bot buttons answer 409 instead of spawning a **second** `main.py` — that would mean
a second `ModerationHub` on the same `mod.<id>.db` and the same action queue, i.e. duplicated
verdicts and, once execution is enabled, duplicated bans. The per-channel pid-lock that used
to prevent this disappeared with the consumer processes.

Separate entry points remain for development — restarting the panel alone keeps the bot's IRC
connection and the engines' warm state (sliding window, user cache, clusters):

```powershell
.\.venv\Scripts\python -m panel.server   # panel only
.\.venv\Scripts\python run.py --bot-only # bot + moderation only
```

## Architecture

### How chat reaches the engine

In-process, through an `asyncio.Queue`:

```
main.py                  cigilbot/orchestration/pipeline.py (same process)
  reads Twitch IRC                          ModerationHub, one engine per channel
  hub.submit(event)      --queue-->         consumer task analyses, writes
  (returns immediately)                      verdicts into mod.<broadcaster_id>.db
```

`submit()` routes by channel login (twitchio only knows the login) into the pipeline keyed by
`broadcaster_id` (stable across renames); `_reconcile` keeps that mapping fresh. Unknown
channel → `False` and a counter, not an exception: the bot may sit in a channel whose
moderation is switched off in the panel.

There is **no** HTTP anywhere between components, and no `mod_inbox` table. Channel Registry
mirroring is gone too — `POST /api/registry/channels` survives in `panel/registry_api.py`,
still token-guarded, purely as an entry point for an external caller.

### Databases — five distinct file families, easy to confuse

| File | Owner | Contents |
|---|---|---|
| `var/bot/bot.db` | twitch-bots | viewers, chat history |
| `var/registry.db` | shared | Channel Registry — the **only** copy: which channels exist and their `desired_state` |
| `var/cigilbot/mod.db` | cigilbot | only `mod_panel_users` — ADMIN role overrides for **both** panel screens |
| `var/cigilbot/mod.<broadcaster_id>.db` | cigilbot | all moderation state — **one file per channel**, because the engine is stateful |

`panel_admins` in `bot.db` is gone: with one panel there is one list of ADMINs, and it lives
in `mod_panel_users`. `bot/database.py` no longer creates the table, but does not drop it
either — `scripts/merge_panel_admins.py` is the one-off that moves existing rows
across (higher role wins on conflict, never downgrades).

### `var/` — all runtime state, outside the source trees

```
var/registry.db    Channel Registry — shared, belongs to neither engine
var/bot/   bot.db, usage.json, voice_input.txt, logs/, run/, panel_state/
var/cigilbot/      mod.db, mod.<broadcaster_id>.db, logs/, run/
```

The whole directory is one line in `.gitignore`, replacing a list of masks (`*.db`, `*.pid`,
`logs/`, `usage*.json`, …) that had to grow with every new kind of working file, where a miss
meant a live database or a secret in a commit.

One module defines these paths — `paths.py` (`src/paths/__init__.py`), imported the same way
by `bot`, `cigilbot`, `panel`, and the entry points. This used to be three separate copies
(`bot/paths.py`, `cigilbot/paths.py`, `panel/paths.py`) with a test guarding that they hadn't
drifted; the copies and the test are both gone along with the `apps/` boundary that forced
them to exist.

Paths are absolute. `bot/config.py` used to return `"bot.db"` relative to the current
directory, which worked only because the panel always launched `main.py` with
`cwd=apps/twitch-bots`; from anywhere else the same code silently created a fresh empty
database instead of opening the existing one.

`ensure_dirs()` is called before anything opens a file under `var/` — on a fresh clone the
directory does not exist at all. Note it must run **before** taking a pid-lock, not inside it:
the lock file itself lives in `var/*/run/`.

`bot.db` may carry an `INSTANCE` suffix (`bot.<instance>.db`) under the legacy profile model
— see below. `bot/database.py` runs `executescript` on every connect with no versioning;
`registry.db` and `mod.*.db` use real migrations (`PRAGMA user_version` /
`cigilbot/storage/migrations.py`).

### Channel identity

Channels are keyed by **`broadcaster_id`** (the stable numeric Twitch ID), never by `login`,
which changes when a channel is renamed. One bot account serves all channels at once —
`main.py::_load_initial_channels()` reads the active list from `registry.db` and passes it to
twitchio's `initial_channels`; `cfg.channel` from `.env` is only a fallback for an empty
registry.

The `profile` parameter throughout `panel/moderation_api.py` is **historical naming** — its
value is a `broadcaster_id`. It was left unrenamed so the frontend (`moderation.js`) did not
have to change.

### Moderation pipeline (`cigilbot/`)

`engine.py::observe(event) -> Verdict` orchestrates:

```
Normalizer -> Detectors -> Cluster Detection -> Risk Score -> Confidence -> Policy -> Audit
```

Structural rules that hold the design together:

- **`types.py` imports nothing capable of I/O** — no aiosqlite, httpx, or twitchio. A detector
  therefore *cannot* ban anyone; the detection/action split is enforced by the import graph,
  not by convention.
- **`policy.py` hardcodes the safety invariants as module constants**, deliberately not read
  from YAML, so they cannot be weakened by editing config — not even in `AGGRESSIVE`/`ATTACK`
  sensitivity:
  - `MIN_FAMILIES_FOR_BAN = 2` — no BAN without two independent signal families
  - no BAN on a provisional verdict (Helix has not returned account age yet) → downgraded to TIMEOUT
  - moderators/VIPs/the broadcaster and users marked safe never get more than OBSERVE
  - TIMEOUT and BAN each require their confidence floor
  - every downgrade is recorded in `Verdict.blocked_by`
- **`Signal` requires non-empty `evidence`** and rejects values outside `[0,1]` in
  `__post_init__` — an unexplainable verdict is not representable.
- **`SignalFamily`** exists so two detectors describing the same fact ("exact duplicate" and
  "near duplicate") do not count as independent confirmation.
- Detectors read the sliding window *before* the current message is added; clustering reads it
  *after*. `engine.observe` inserts into the window strictly between those two steps.
- Panel-driven state (Attack Mode, Giveaway Mode, Pattern Library, FP penalties) is **cached in
  the engine and refreshed by explicit `reload_*`/`sync_*` calls** from the consumer's poll
  loop, never re-read per message. The panel is a separate process writing to the same DB.
- Config loading (`config.py`) rejects unknown YAML keys with `ConfigError` at startup rather
  than silently ignoring a typo.

The system runs in **SHADOW mode**: verdicts are computed and persisted, but nothing is
executed in Twitch until a moderator token is obtained through the panel's Settings screen.
`executor.py` only drains `mod_action_queue`; it never decides anything.

### The panel (`panel/`)

One FastAPI app on 8766 with two screens: `/moderation` (default, also `/`) and `/bots`.
`panel/__init__.py` used to hold a `sys.path` bootstrap for reaching the engines in their own
`apps/` directories; the packages are siblings now and it is empty.

`app.state.panel_roots` carries a `PanelRoots` (in `paths.py`) with two fields — `repo` and
`var`. It exists so tests can point every root at one tmp directory; production code reads the
module constants directly. The pair that matters most: **`_write_env_values` writes
`TWITCH_MOD_*` into `repo/.env` and the moderation pipeline reads them from there.** If those
ever diverge, the panel reports a token was obtained while every ban fails with 401.

Roles are derived from Twitch on every login, not stored: broadcaster → `OWNER`, channel
moderator (Helix `GET /moderation/moderators`) → `MODERATOR`, anyone else → `VIEWER`. `ADMIN`
is the only manual override, one list for both screens (`mod_panel_users`). Every route is
guarded by `Depends(require_role_min(...))` — in `panel/bots_api.py` the auth import sits
above the first route specifically so the dependency exists when decorators are evaluated
(`SEC-001`; routes there previously had no authorization at all).

`panel/auth.py` used to exist as an independent copy in each project, and they had drifted —
the same `httpx.ConnectTimeout` bug in `_resolve_roles_by_channel` was fixed twice. One copy
now. `_list_profile_channels` returns the **union** of both channel models, because
`role_for_profile` receives a `broadcaster_id` from `moderation_api` and a profile name from
the bots screen; Registry wins on key collision.

The panel controls `main.py` directly via subprocess (`cigilbot/integrations/bot_process_control.py`),
because twitchio cannot join a new channel without a reconnect. Auto-restart is deliberately
not implemented there: one `main.py` serves every channel, so restarting it would drop
moderation on channels that are live right now.

### Two coexisting channel models

`main.py` uses the Registry model (one account, all channels). `panel/bots_api.py` still
implements the older per-profile model in full: `list_profiles()` scans `.env.<profile>`
files, `new_profile_from_template()` creates them, and `_start()`/`db_path()` fan processes
and databases out by `INSTANCE`. Cigilbot dropped profiles in Phase 1; twitch-bots did not,
and the panel merge deliberately did not change that — the job was one login and one port,
not redoing how bots are created. Both paths work — check which one a change actually affects
before editing. Note that profile `main` now reads the **repo-root** `.env`, while named
profiles stay in `.env.<profile>`.

## Conventions

- **Docstrings and comments explain *why this and not the alternative***, usually naming the
  concrete incident that motivated it (`BUG-002`, `BUG-003`, `BUG-004`, `SEC-001`,
  `FALSE-BAN-001`, `FALSE-BAN-002`) and what the code used to do instead. Ruff per-file
  ignores in `pyproject.toml` carry the same justification. Keep this up — a change that
  reverses one of these decisions should update the comment that explains it.
- There are **zero** TODO/FIXME/HACK markers in the codebase.
- Line length 100, `E501` disabled (formatter's job), `B008` disabled (FastAPI `Depends`).
- Failures in moderation/audit paths are logged with `log.exception` and swallowed — losing a
  verdict record must never drop a chat message.
- mypy is `strict` over `cigilbot/`, `paths.py`, `tests/` and the annotated half of `panel/`.
  `bot/` and `panel/bots_api.py` are excluded — written without annotations, intentionally —
  and pulled in under `follow_imports = "skip"` so mypy does not wander into them.
- `.gitattributes` normalizes to LF in the repo, CRLF in the working tree.

## Git

- **Do not add `Co-Authored-By: Claude` (or any other co-author trailer) to commit messages.**
  This overrides the default Claude Code behaviour. No commit in this repository's history has
  one, and it should stay that way.
- Commit messages are Russian, subject line in the imperative or `topic: what changed`
  (`mypy: починить конфиг и типы, которые он не проверял`). Non-trivial commits carry a body
  of bullets explaining *why* each change was made, and close with a `Проверено:` line stating
  what was actually run and its result.

## Documentation

- `docs/moderation-plan.md` — moderation engine architecture, safety invariants, stages 0–10.
  The code references its sections by number ("раздел 23 ТЗ").
- `docs/master-plan.html` — roadmap, phases 1–9, direction 00 (Channel Registry).
- `docs/phase1-plan.html` — what Phase 1 built, its security review, and its incidents.

Phase 1 is closed and verified on live channels; Phase 2 (Alerts) is next.

## Known inconsistencies

Findings from a full read of the tree — worth fixing, and worth knowing about before trusting
a comment or a template:

1. `docs/*.html` and `docs/moderation-plan.md` still describe the two-panel split and the
   `mod_inbox` handoff as current. They are the design record for Phase 1 and were not
   rewritten; read them as history, not as the present shape.
2. `scripts/import_registry.py` is a one-off from the Registry migration. It imports
   `bot.registry.ChannelRegistry`, which does not exist — `bot/` has no `registry.py`. Broken
   independently of the `src/` move (confirmed both before and after); the `sys.path` insert
   was deliberately left in place rather than "fixed" toward a script that still can't run.
3. `registry_store.py` still carries comments saying `process_status` is written "only by
   supervisor.py". The writer is now `ModerationHub`; the rule (one writer, and never the
   panel) is unchanged.
4. `bot.db` keeps its `mod_inbox` table and `panel_admins` table on existing installs. Nothing
   reads either; both are safe to drop by hand once `merge_panel_admins.py` has run.

Earlier entries here are fixed and gone: missing `streamlink`/`av` (now pinned in the root
`requirements.txt`/`requirements-voice.txt`), undocumented `.env` keys (the root
`.env.example` documents every key both engines read, `INTERNAL_SYNC_TOKEN` included),
stale pre-monorepo paths in comments (`bot/moderation/...`, `mod.<profile>.db`,
`../TWITCH BOTS`), the dead per-project `.venv`, and runtime state living inside the
source trees — all state now lives in `var/`, see below. The `src/` migration (bot/,
cigilbot/, panel/, paths.py moved; cigilbot/ split into domain/storage/integrations/
orchestration/detectors/content) is complete — every import, config path, and doc
reference in this file already reflects it, not a pending item.
