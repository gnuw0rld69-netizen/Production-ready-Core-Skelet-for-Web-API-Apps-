from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


SUPPORTED_LANGS = {"ru", "en"}
I18N_DIR = Path(__file__).resolve().parents[1] / "i18n"


def normalize_lang(lang: str | None) -> str:
    if not lang:
        return "ru"
    lang = lang.lower()
    return lang if lang in SUPPORTED_LANGS else "ru"


@lru_cache(maxsize=4)
def get_translations(lang: str) -> dict[str, str]:
    lang = normalize_lang(lang)
    path = I18N_DIR / f"{lang}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))
