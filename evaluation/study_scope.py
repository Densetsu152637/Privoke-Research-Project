"""Explicit scope gate for legacy studies whose protocols include product detectors."""

PRODUCT_SCOPE_ERROR = (
    "This legacy protocol executes semantic and full-product detector measurements; "
    "it is not an LLM-only study. Refusing before data access or execution. "
    "Use the current semantic-only curriculum-improvement study for LLM testing. "
    "Only for a separately authorized whole-product test or detector analysis, "
    "select --allow-product-pipeline."
)


def add_product_pipeline_argument(parser):
    parser.add_argument(
        "--allow-product-pipeline", action="store_true",
        help="Confirm separately authorized whole-product/detector analysis; retains "
             "the legacy combined-detector protocol and does not produce LLM-only results.",
    )


def require_product_pipeline(args, parser=None):
    """Require explicit scope selection before reading study data or starting work."""
    if getattr(args, "allow_product_pipeline", False) is not True:
        if parser is not None:
            parser.error(PRODUCT_SCOPE_ERROR)
        raise ValueError(PRODUCT_SCOPE_ERROR)
