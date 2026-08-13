import asyncio
import logging
from collections.abc import Awaitable, Callable

import numpy as np
from faster_whisper import WhisperModel

from bot.audio_source import BLOCK_MS, MicrophoneSource, TwitchStreamSource

log = logging.getLogger("twitchbot.voice")

SILENCE_BLOCKS_TO_STOP = 8  # ~0.8с тишины после речи = конец фразы
MIN_SPEECH_BLOCKS = 3  # минимум ~0.3с звука, чтобы не ловить щелчки
# Верхний предел длины фразы. В звуке стрима фон (музыка, игра) не даёт
# тишины, по которой можно было бы понять, что человек договорил, — без
# этого предела фраза не закончилась бы никогда и бот молчал бы вечно.
MAX_PHRASE_BLOCKS = int(15_000 / BLOCK_MS)  # 15 секунд

# "small" — хороший баланс скорости/точности для CPU и русской речи.
# Модель скачивается один раз (~500 МБ) и кэшируется локально.
WHISPER_MODEL_SIZE = "small"


class VoiceListener:
    def __init__(
        self,
        on_transcript: Callable[[str], Awaitable[None]],
        source: MicrophoneSource | TwitchStreamSource,
        silence_threshold: int = 500,
    ):
        self._on_transcript = on_transcript
        self._source = source
        self._silence_threshold = silence_threshold
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._model: WhisperModel | None = None

    async def start(self) -> None:
        try:
            self._loop = asyncio.get_event_loop()

            log.info("Загружаю локальную модель распознавания речи (%s)...", WHISPER_MODEL_SIZE)
            self._model = await self._loop.run_in_executor(
                None, lambda: WhisperModel(WHISPER_MODEL_SIZE, device="cpu", compute_type="int8")
            )
            log.info("Модель загружена, источник звука: %s", self._source.name)

            self._source.start(self._loop, self._queue.put_nowait)
            asyncio.create_task(self._consume_loop())
        except Exception:
            log.exception("Не удалось запустить голосовой ввод")

    async def _consume_loop(self) -> None:
        speech_blocks: list[bytes] = []
        silence_run = 0
        speaking = False

        while True:
            block = await self._queue.get()
            rms = _rms_int16(block)

            if rms >= self._silence_threshold:
                speech_blocks.append(block)
                silence_run = 0
                speaking = True
            elif speaking:
                silence_run += 1
                speech_blocks.append(block)

            if not speaking:
                continue

            phrase_ended = silence_run >= SILENCE_BLOCKS_TO_STOP
            too_long = len(speech_blocks) >= MAX_PHRASE_BLOCKS
            if not (phrase_ended or too_long):
                continue

            if len(speech_blocks) - silence_run >= MIN_SPEECH_BLOCKS:
                await self._transcribe_and_dispatch(b"".join(speech_blocks))
            speech_blocks = []
            silence_run = 0
            speaking = False

    async def _transcribe_and_dispatch(self, audio: bytes) -> None:
        try:
            # Запись НЕ останавливаем: пауза на время распознавания съедала
            # ~1.3 секунды после каждой фразы, и обращения к боту, сказанные
            # сразу после предыдущей реплики, терялись целиком. Аудио копится
            # в очереди, распознавание идёт по одной фразе за раз (цикл
            # последовательный) и работает быстрее реального времени.
            samples = np.frombuffer(audio, dtype=np.int16).astype(np.float32) / 32768.0

            segments, _ = await self._loop.run_in_executor(
                None,
                lambda: self._model.transcribe(samples, language="ru", vad_filter=True),
            )
            text = "".join(segment.text for segment in segments).strip()

            if text:
                log.info("Распознано: %s", text)
                await self._on_transcript(text)
        except Exception:
            log.exception("Ошибка распознавания речи")


def _rms_int16(block: bytes) -> float:
    samples = np.frombuffer(block, dtype=np.int16)
    if samples.size == 0:
        return 0.0
    return float(np.sqrt(np.mean(samples.astype(np.float64) ** 2)))
