import re # used for pattern matching and text manipulation
import unicodedata # imports unicode functions for normalizing characters

def normalize_text(text: str) -> str:
    # takes a string and returns normalized string
    text = _unicode_normalize(text)       # normalizes Unicode characters to a standard form
    text = _lowercase(text)               # converts all characters in the text to lowercase for uniformity
    text = _fix_common_obfuscations(text) # replaces common obfuscations like "[at]" with "@" and removes spaces in digit sequences
    text = _clean_spaces(text)            # normalizes multiple spaces to a single space and preserves paragraph structure by normalizing newlines
    text = text.strip()
    return text

def _unicode_normalize(text: str) -> str:
    # nfkc normalisation form applies compatability mapping (replaces characters that have the same data just diff appearance)
    return unicodedata.normalize("NFKC", text)

def _lowercase(text: str) -> str:
    return text.lower()

def _fix_common_obfuscations(text: str) -> str:
    # email obfuscation
    text = text.replace("[at]", "@")
    text = text.replace("(at)", "@")

    # fix spaced digits (OTP / phone)
    # removes spaces between digits
    text = re.sub(r'(\d)\s+(?=\d)', r'\1', text)
    return text

def _clean_spaces(text: str) -> str:
    # normalize multiple spaces but preserve structure
    text = re.sub(r'[ \t]+', ' ', text) # only horizontal spaces
    text = re.sub(r'\n+', '\n', text)   # keep paragraph structure
    return text