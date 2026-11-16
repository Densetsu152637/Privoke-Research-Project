"""NER detection package for the PriVoke client runtime."""

from .ner_detector import EntityNERDetector


def build_ner_detector() -> EntityNERDetector:
    """The NER detector selected by ``PRIVOKE_NER_BACKEND`` (default ``spacy``)."""
    from ..config import GLOBAL_CONFIG

    backend = GLOBAL_CONFIG.ner_backend
    if backend == "spacy":
        return EntityNERDetector()
    if backend == "gliner":
        from .gliner_detector import GlinerEntityDetector

        return GlinerEntityDetector()
    raise ValueError(f"Unknown PRIVOKE_NER_BACKEND {backend!r}; expected 'spacy' or 'gliner'")
