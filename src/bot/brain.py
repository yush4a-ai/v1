import difflib
import json
import logging
import re
import time
from pathlib import Path

from openai import AsyncOpenAI

log = logging.getLogger("twitchbot.brain")

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
MAX_REPLY_CHARS = 450  # запас под лимит сообщения Twitch-чата (500 символов)
# Без явного таймаута SDK ждёт 10 минут. При обрыве связи это вешало бота:
# голосовая очередь стоит, а потом он отвечает на реплики минутной давности.
REQUEST_TIMEOUT_SECONDS = 20.0
MAX_RETRIES = 1

# Модель возвращает этот маркер вместо ответа, когда решает промолчать —
# так молчание встроено в тот же запрос, а не требует второго вызова API.
SKIP_MARKER = "://SKIP"
# Модель не всегда воспроизводит маркер побуквенно (может обернуть в кавычки,
# написать "/SKIP" или "SKIP" без слэшей) — точное совпадение подстроки это
# пропускало, и отказ отвечать утекал в чат как обычное сообщение. Поэтому
# проверяем мягче: если в коротком ответе есть слово SKIP — это отказ.
SKIP_PATTERN = re.compile(r"skip", re.IGNORECASE)
# Модель иногда вместо служебного маркера отвечает СЛОВАМИ о том, что решила
# промолчать ("молчу", "не буду отвечать", "всё сказал") — то есть буквально
# нарушает инструкцию "не пиши ничего", но остаётся в пределах того же
# намерения. Такой текст тоже нельзя пускать в чат: ловим короткие фразы
# именно про молчание/отказ отвечать.
SILENCE_PATTERN = re.compile(
    r"^(молчу|промолчу|я молчу|всё сказал|все сказал|не буду отвечать|"
    r"пропущу|воздержусь|не отвечаю|мимо)\.?!?$",
    re.IGNORECASE,
)

# Модель без напоминания склонна скатываться в одни и те же удобные шаблоны
# ("да вы ебанутые", "я зожник, клеш рояль моя жизнь" и т.п.) — с яркими
# фразами в характере это особенно заметно. Держим свои последние ответы
# и прямо перечисляем их в промпте как "уже говорил, не повторяй".
OWN_REPLY_HISTORY = 8
# Если даже с запретом в промпте новый ответ вышел почти такой же, как один
# из последних своих — просим модель попробовать ещё раз, другими словами.
REPEAT_SIMILARITY_THRESHOLD = 0.72

# DeepSeek-chat, цены на вход/выход за 1M токенов в USD (без кэш-скидки —
# грубая верхняя оценка, точная цифра зависит от cache hit rate у DeepSeek)
PRICE_PER_1M_INPUT_USD = 0.27
PRICE_PER_1M_OUTPUT_USD = 1.10


def _strip_formatting(text: str) -> str:
    text = re.sub(r"[*_`]", "", text)
    # Тире — характерный маркер текста от ИИ, живые люди в Twitch-чате его
    # почти не используют. Промпт просит модель не писать его, но это не
    # надёжно, поэтому дополнительно подчищаем на выходе: длинное/среднее
    # тире с пробелами по бокам меняем на запятую (типичная человеческая
    # замена), одиночное — на дефис.
    text = re.sub(r"\s+[—–]\s+", ", ", text)
    text = text.replace("—", "-").replace("–", "-")
    text = text.strip().strip('"').strip("«»").strip()
    return text


def _is_skip_reply(reply: str) -> bool:
    """Отказ отвечать — либо служебный маркер, либо модель проговорила
    решение молчать словами вместо того, чтобы прислать пустой маркер."""
    if not reply:
        return True
    if len(reply) <= 20 and SKIP_PATTERN.search(reply):
        return True
    if len(reply) <= 30 and SILENCE_PATTERN.match(reply.strip()):
        return True
    return False


class Brain:
    def __init__(
        self,
        api_key: str,
        personality: str,
        channel: str,
        usage_path: str | None = None,
        streamer_context: str = "",
    ):
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=DEEPSEEK_BASE_URL,
            timeout=REQUEST_TIMEOUT_SECONDS,
            max_retries=MAX_RETRIES,
        )
        # Панель управления читает этот файл, чтобы показать примерную
        # стоимость сессии — считаем токены по каждому запросу и копим их
        # на диск сразу (а не только в памяти), чтобы цифра не терялась
        # при перезапуске процесса.
        self._usage_path = Path(usage_path) if usage_path else None
        self._usage = self._load_usage()
        # Бота можно подключать к разным каналам (см. INSTANCE в config.py),
        # включая канал, чьё имя совпадает с ником самого бота — тогда
        # стример на этом канале не он сам, а кто-то другой, использующий
        # похожий/тот же ник. Явно сообщаем модели, где она сейчас находится,
        # чтобы она не путала "себя" с личностью стримера этого канала.
        self._personality = personality + (
            f"\nТы сейчас находишься в Twitch-чате канала {channel} — "
            f"это твоя текущая площадка, здесь ты общаешься со стримером "
            f"этого канала и его зрителями. Учитывай, кто именно стример "
            f"здесь, не путай его с собой, даже если ник похож на твой."
        )
        if streamer_context.strip():
            # Короткая вводная про самого стримера (пол/имя/город/тематика) —
            # заполняется при подключении к новому каналу. Без неё модель
            # угадывает пол и биографию стримера вслепую (реальный случай:
            # Ари на канале-девушке решила, что стример — парень).
            self._personality += (
                f"\nВот что тебе известно про стримера этого канала: "
                f"{streamer_context.strip()}. Учитывай это в разговоре "
                f"(например, правильный род/пол в обращениях), но не "
                f"пересказывай эти факты чату без повода — это твои "
                f"фоновые знания, а не тема для каждого сообщения."
            )
        self._own_recent_replies: list[str] = []

    async def reply(
        self,
        username: str,
        message: str,
        chat_context: list[tuple[str, str]],
        viewer_note: str | None,
    ) -> str:
        system_prompt = self._personality + (
            "\nТы общаешься в чате Twitch-стрима. Отвечай ТОЛЬКО одним коротким "
            "сообщением (максимум 1-2 предложения), без markdown, без списков, "
            "без тире (—/–) — живые люди в чате тире почти не используют, "
            "вместо него ставь запятую или просто новое предложение."
        ) + self._no_repeat_instruction()
        if viewer_note:
            system_prompt += f"\nЧто ты знаешь про зрителя {username}: {viewer_note}"

        context_lines = "\n".join(f"{name}: {text}" for name, text in chat_context)

        user_prompt = (
            f"Последние сообщения в чате:\n{context_lines}\n\n"
            f"Зритель {username} написал тебе: {message}\n"
            f"Ответь ему."
        )

        reply = await self._complete_avoiding_repeats(system_prompt, user_prompt)
        reply = reply[:MAX_REPLY_CHARS]
        self._remember_own_reply(reply)
        return reply

    async def maybe_reply_in_chat(
        self,
        username: str,
        message: str,
        chat_context: list[tuple[str, str]],
        viewer_note: str | None,
        reply_parent: tuple[str, str] | None = None,
    ) -> str | None:
        """Как reply(), но с правом промолчать даже на прямое обращение.

        В чате (в отличие от голоса стримера) промолчать на обращение —
        не баг, а часть характера: не каждое сообщение заслуживает ответа.

        reply_parent — (автор, текст) сообщения, на которое зритель ответил
        через Twitch-функцию "Reply", если она использовалась. Без этого
        сообщение вида "@Шинра согласен!!" не имеет смысла без исходного
        поста, на который отвечали.
        """
        system_prompt = self._personality + (
            "\nТы общаешься в чате Twitch-стрима. Тебе НАПРЯМУЮ написал "
            "зритель, но у тебя есть право промолчать, если по твоему "
            "характеру отвечать не хочется или нечего добавить — тогда "
            f"ответь ровно '{SKIP_MARKER}' и больше ничего. НИКОГДА не "
            "пиши словами о том, что решил промолчать/пропустить/не "
            "отвечать ('молчу', 'пропущу', 'воздержусь' и т.п.) — либо "
            f"пиши обычный ответ, либо ровно '{SKIP_MARKER}', третьего не "
            "дано. Если решил ответить — ТОЛЬКО одним коротким сообщением, "
            "без markdown, без списков, без тире (—/–) — вместо него запятая "
            "или новое предложение."
        ) + self._no_repeat_instruction()
        if viewer_note:
            system_prompt += f"\nЧто ты знаешь про зрителя {username}: {viewer_note}"

        context_lines = "\n".join(f"{name}: {text}" for name, text in chat_context)

        reply_note = ""
        if reply_parent:
            parent_author, parent_text = reply_parent
            reply_note = (
                f'\n(Это ответ (reply) на сообщение {parent_author}: "{parent_text}")'
            )

        user_prompt = (
            f"Последние сообщения в чате:\n{context_lines}\n\n"
            f"Зритель {username} написал тебе: {message}{reply_note}\n"
            f"Твой ответ (или {SKIP_MARKER}):"
        )

        reply = await self._complete_avoiding_repeats(system_prompt, user_prompt)
        if _is_skip_reply(reply):
            return None
        reply = reply[:MAX_REPLY_CHARS]
        self._remember_own_reply(reply)
        return reply

    async def maybe_reply_to_voice(
        self,
        streamer_name: str,
        speech: str,
        chat_context: list[tuple[str, str]],
        viewer_note: str | None,
    ) -> str | None:
        """Решает сам, реагировать ли на речь стримера, без внешнего кулдауна.

        Речь стримера — это поток мыслей вслух, не обращение к чату по
        умолчанию, поэтому вместо жёсткого лимита "раз в N секунд" отдаём
        решение самой модели: пусть встревает, когда реплика реально просит
        ответа или интересна, и молчит на остальное (игровые команды тиммейту,
        случайные слова, техническую болтовню).
        """
        system_prompt = self._personality + (
            "\nТы слышишь речь стримера во время эфира — это его поток мыслей "
            "вслух, а не сообщение специально для тебя. Отвечай ТОЛЬКО если "
            "это уместно: он явно шутит, задаёт риторический вопрос в чат, "
            "жалуется, или происходит что-то, на что твой персонаж не смог "
            "бы промолчать. На бытовые реплики, игровые команды тиммейту, "
            f"обрывки без смысла — молчи, ответь ровно '{SKIP_MARKER}' и "
            "больше ничего. НИКОГДА не пиши словами о том, что решил "
            "промолчать/пропустить/не отвечать ('молчу', 'пропущу', "
            f"'воздержусь' и т.п.) — либо пиши обычный ответ, либо ровно "
            f"'{SKIP_MARKER}', третьего не дано. Не молчи вообще всегда — "
            "иногда встревай, но редко, не чаще одного раза на несколько "
            "его реплик. Когда отвечаешь — один короткий смешной "
            "комментарий (1 предложение), без markdown, без тире (—/–) — "
            "вместо него запятая или новое предложение."
        ) + self._no_repeat_instruction()
        if viewer_note:
            system_prompt += f"\nЧто ты знаешь про {streamer_name}: {viewer_note}"

        context_lines = "\n".join(f"{name}: {text}" for name, text in chat_context)
        user_prompt = (
            f"Последние сообщения в чате:\n{context_lines}\n\n"
            f"{streamer_name} только что сказал(а) вслух: {speech}\n"
            f"Твоя реакция (или {SKIP_MARKER}):"
        )

        reply = await self._complete_avoiding_repeats(system_prompt, user_prompt)
        if _is_skip_reply(reply):
            return None
        reply = reply[:MAX_REPLY_CHARS]
        self._remember_own_reply(reply)
        return reply

    def _no_repeat_instruction(self) -> str:
        if not self._own_recent_replies:
            return ""
        recent = "\n".join(f'- "{r}"' for r in self._own_recent_replies)
        return (
            "\nВАЖНО: ты уже недавно писал в этот чат следующее — "
            "НЕ повторяй эти фразы и обороты, даже похожие по смыслу, "
            f"придумай реально другой ответ:\n{recent}"
        )

    def _remember_own_reply(self, reply: str) -> None:
        self._own_recent_replies.append(reply)
        self._own_recent_replies = self._own_recent_replies[-OWN_REPLY_HISTORY:]

    def _is_repeat_of_own(self, reply: str) -> bool:
        return any(
            difflib.SequenceMatcher(None, reply.lower(), prev.lower()).ratio()
            >= REPEAT_SIMILARITY_THRESHOLD
            for prev in self._own_recent_replies
        )

    async def _complete_avoiding_repeats(self, system_prompt: str, user_prompt: str) -> str:
        reply = await self._complete(system_prompt, user_prompt)
        if reply and self._is_repeat_of_own(reply):
            log.info("Ответ похож на недавний свой, прошу перефразировать: %s", reply)
            retry_prompt = (
                system_prompt
                + f"\nТы только что собирался написать: \"{reply}\" — это слишком "
                "похоже на то, что ты уже говорил. Придумай другой ответ, с другими "
                "словами и другой шуткой."
            )
            reply = await self._complete(retry_prompt, user_prompt)
        return reply

    async def _complete(self, system_prompt: str, user_prompt: str) -> str:
        started = time.monotonic()
        response = await self._client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=120,
            temperature=0.9,
            extra_body={
        "thinking": {
            "type": "disabled"
        }
    }
        )
        elapsed = time.monotonic() - started
        if elapsed > 5:
            log.warning("DeepSeek отвечал %.1f сек — бот заметно тормозит", elapsed)

        if response.usage:
            self._record_usage(response.usage.prompt_tokens, response.usage.completion_tokens)

        return _strip_formatting(response.choices[0].message.content)

    def _load_usage(self) -> dict:
        default = {"requests": 0, "input_tokens": 0, "output_tokens": 0}
        if not self._usage_path or not self._usage_path.exists():
            return default
        try:
            return json.loads(self._usage_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return default

    def _record_usage(self, input_tokens: int, output_tokens: int) -> None:
        self._usage["requests"] += 1
        self._usage["input_tokens"] += input_tokens
        self._usage["output_tokens"] += output_tokens
        if self._usage_path:
            try:
                self._usage_path.write_text(json.dumps(self._usage), encoding="utf-8")
            except OSError:
                log.warning("Не удалось записать usage.json")
