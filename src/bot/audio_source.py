"""Источники звука для распознавания: микрофон или аудиодорожка Twitch-стрима.

Оба отдают одно и то же — блоки 16-битного моно PCM 16 кГц по 100 мс,
поэтому дальше по конвейеру (VAD + whisper в voice.py) им всё равно,
откуда пришёл звук.
"""

import asyncio
import logging
import threading
import time
from collections.abc import Callable

import av
import numpy as np
import sounddevice as sd
import streamlink

log = logging.getLogger("twitchbot.audio")

SAMPLE_RATE = 16000
CHANNELS = 1
BLOCK_MS = 100
BLOCK_SIZE = int(SAMPLE_RATE * BLOCK_MS / 1000)
BLOCK_BYTES = BLOCK_SIZE * 2  # int16

# Канал оффлайн или связь оборвалась — ждём столько перед новой попыткой
STREAM_RETRY_SECONDS = 30
STREAM_OPEN_TIMEOUT = 15


class MicrophoneSource:
    """Системный микрофон (устройство по умолчанию)."""

    name = "микрофон"

    def __init__(self) -> None:
        self._stream: sd.InputStream | None = None

    def start(self, loop: asyncio.AbstractEventLoop, on_block: Callable[[bytes], None]) -> None:
        def callback(indata, frames, time_info, status):
            if status:
                log.warning("Audio status: %s", status)
            loop.call_soon_threadsafe(on_block, bytes(indata))

        self._stream = sd.InputStream(
            samplerate=SAMPLE_RATE,
            channels=CHANNELS,
            dtype="int16",
            blocksize=BLOCK_SIZE,
            callback=callback,
        )
        self._stream.start()
        log.info("Слушаю микрофон")

    def stop(self) -> None:
        if self._stream:
            self._stream.stop()
            self._stream.close()


class TwitchStreamSource:
    """Аудиодорожка чужого Twitch-стрима.

    streamlink достаёт ссылку на аудиопоток канала, PyAV его декодирует
    (внешний ffmpeg не нужен, PyAV несёт декодер внутри). Всё это блокирующее,
    поэтому крутится в отдельном потоке и складывает блоки в event loop.

    Канал может быть оффлайн или уйти в оффлайн посреди стрима — тогда просто
    ждём и пробуем снова, процесс из-за этого не падает.
    """

    def __init__(self, channel: str) -> None:
        self.channel = channel
        self.name = f"стрим twitch.tv/{channel}"
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self, loop: asyncio.AbstractEventLoop, on_block: Callable[[bytes], None]) -> None:
        self._thread = threading.Thread(
            target=self._run, args=(loop, on_block), name="twitch-audio", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self, loop: asyncio.AbstractEventLoop, on_block: Callable[[bytes], None]) -> None:
        session = streamlink.Streamlink()
        session.set_option("twitch-disable-ads", True)

        while not self._stop.is_set():
            try:
                url = self._resolve_audio_url(session)
                if url is None:
                    log.info("Канал %s оффлайн, жду %d сек", self.channel, STREAM_RETRY_SECONDS)
                    self._stop.wait(STREAM_RETRY_SECONDS)
                    continue

                log.info("Подключаюсь к звуку канала %s", self.channel)
                self._pump(url, loop, on_block)
            except Exception:
                log.exception("Обрыв звука канала %s", self.channel)

            if not self._stop.is_set():
                self._stop.wait(STREAM_RETRY_SECONDS)

    def _resolve_audio_url(self, session: streamlink.Streamlink) -> str | None:
        streams = session.streams(f"https://twitch.tv/{self.channel}")
        if not streams:
            return None
        # audio_only — самый дешёвый вариант, видео нам не нужно совсем
        stream = streams.get("audio_only") or streams.get("worst")
        return stream.url if stream else None

    def _pump(
        self,
        url: str,
        loop: asyncio.AbstractEventLoop,
        on_block: Callable[[bytes], None],
    ) -> None:
        container = av.open(url, timeout=STREAM_OPEN_TIMEOUT)
        resampler = av.AudioResampler(format="s16", layout="mono", rate=SAMPLE_RATE)
        buffer = bytearray()
        started = time.monotonic()
        log.info("Звук канала %s пошёл", self.channel)

        try:
            for frame in container.decode(audio=0):
                if self._stop.is_set():
                    return

                for chunk in resampler.resample(frame):
                    buffer.extend(chunk.to_ndarray().astype(np.int16).tobytes())

                # Режем на блоки того же размера, что даёт микрофон, чтобы
                # дальше по конвейеру источники были неотличимы.
                while len(buffer) >= BLOCK_BYTES:
                    block = bytes(buffer[:BLOCK_BYTES])
                    del buffer[:BLOCK_BYTES]
                    loop.call_soon_threadsafe(on_block, block)
        finally:
            container.close()
            log.info(
                "Звук канала %s прервался после %.0f сек", self.channel, time.monotonic() - started
            )


def build_source(source: str, channel: str) -> MicrophoneSource | TwitchStreamSource:
    if source == "twitch":
        return TwitchStreamSource(channel)
    return MicrophoneSource()
