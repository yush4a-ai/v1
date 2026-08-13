from pathlib import Path

import paths

# paths.REPO_ROOT, не свой пересчёт Path(__file__).parent.parent — та
# формула завязана на глубину вложенности этого файла и однажды уже
# разъезжалась, когда её копии жили в bot/, cigilbot/, panel/ по отдельности
# (см. paths.py). Файл лежит в корне репозитория, не в var/bot/ — это
# расхождение с CLAUDE.md, существовавшее до переезда на src/, сохранено
# как есть: смена самого пути — отдельная задача, не часть этой миграции.
PROJECT_DIR = paths.REPO_ROOT
QUEUE_FILE = PROJECT_DIR / "voice_input.txt"


class VoiceQueue:
    """Простая передача текста между процессами через файл на диске.

    voice_main.py (отдельный процесс) дописывает сюда строки с распознанной
    речью, main.py (Twitch-бот) их читает и удаляет. Разделение на два
    процесса нужно, потому что faster-whisper/sounddevice в одном процессе
    с twitchio приводили к падению без трассировки (вероятно, конфликт
    нативных потоков/event loop).
    """

    def __init__(self, path: Path | str = QUEUE_FILE):
        # Имя файла (из конфига) считаем относительным папке проекта, чтобы
        # запуск из другой директории не создавал очередь где попало.
        self.path = Path(path) if Path(path).is_absolute() else PROJECT_DIR / path
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def push(self, text: str) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(text.replace("\n", " ").strip() + "\n")

    def pop_all(self) -> list[str]:
        """Забрать всё разом и очистить файл.

        Бот отвечает на живую речь, поэтому копить очередь бессмысленно: если
        пока он думал, накопилось несколько фраз, отвечать надо на свежую, а
        не разгребать всё подряд с отставанием.
        """
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return []
        self.path.write_text("", encoding="utf-8")
        return [line.strip() for line in lines if line.strip()]

    def pop(self) -> str | None:
        if not self.path.exists():
            return None
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return None
        first, *rest = lines
        self.path.write_text("\n".join(rest) + ("\n" if rest else ""), encoding="utf-8")
        return first.strip() or None
