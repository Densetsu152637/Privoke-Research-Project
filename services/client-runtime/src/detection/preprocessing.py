import re # used for pattern matching and text manipulation
import unicodedata # imports unicode functions for normalizing characters

class TextNormalizer:

    def normalize(self, text: str) -> str: # takes a string and returns normalised string 
        text = self._unicode_normalize(text) # normalizes unicode characters to a standard form
        text = self._lowercase(text) # converts all characters in the text to lowercase for uniformity
        text = self._fix_common_obfuscations(text) # replaces common obfuscations like "[at]" with "@" and removes spaces in digit sequences
        text = self._clean_spaces(text) # normalizes multiple spaces to a single space and preserves paragraph structure by normalizing newlines
        return text.strip() 

    def _unicode_normalize(self, text: str) -> str:
        return unicodedata.normalize("NFKC", text) # nfkc normalisation form applies compatability mapping (replaces characters that have the same data just diff appearance)

    def _lowercase(self, text: str) -> str:
        return text.lower()

    def _fix_common_obfuscations(self, text: str) -> str:
        # email obfuscation
        text = text.replace("[at]", "@")
        text = text.replace("(at)", "@")

        # fix spaced digits (OTP / phone)
        text = re.sub(r'(\d)\s+(?=\d)', r'\1', text) # removes spaces between digits

        return text

    def _clean_spaces(self, text: str) -> str:
        # normalize multiple spaces but preserve structure
        text = re.sub(r'[ \t]+', ' ', text)   # only horizontal spaces
        text = re.sub(r'\n+', '\n', text)     # keep paragraph structure
        return text