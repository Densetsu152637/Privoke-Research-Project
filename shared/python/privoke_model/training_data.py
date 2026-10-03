"""Compare experiment texts before separating training and evaluation data."""

import re
import unicodedata


def training_text_key(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower()
    text = text.replace("[at]", "@").replace("(at)", "@")
    text = re.sub(r"(?<=\d)[ \t]+(?=\d)", "", text)
    return " ".join(text.split())
