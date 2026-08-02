from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Pattern, Tuple

from ...classification import Category, Sensitivity, Visibility
from ...detection.context import is_clean_discussion_context


@dataclass(frozen=True)
class SemanticSignal:
    category: Category | None
    sensitivity: Sensitivity
    visibility: Visibility | None
    span: Tuple[int, int]
    phrase: str
    reason: str
    weight: float


@dataclass(frozen=True)
class PatternDefinition:
    category: Category | None
    sensitivity: Sensitivity
    visibility: Visibility | None
    reason: str
    weight: float
    patterns: Tuple[Pattern[str], ...]


def extract_semantic_signals(text: str) -> List[SemanticSignal]:
    signals = []
    seen = set()
    clean_discussion = is_clean_discussion_context(text)

    for definition in _PATTERN_DEFINITIONS:
        if clean_discussion and definition.category is not None:
            continue
        for pattern in definition.patterns:
            for match in pattern.finditer(text):
                key = (
                    definition.category,
                    definition.visibility,
                    match.span(),
                    match.group(0).lower(),
                )
                if key in seen:
                    continue
                seen.add(key)
                signals.append(
                    SemanticSignal(
                        category=definition.category,
                        sensitivity=definition.sensitivity,
                        visibility=definition.visibility,
                        span=match.span(),
                        phrase=match.group(0),
                        reason=definition.reason,
                        weight=definition.weight,
                    )
                )

    return signals


def sensitivity_rank(sensitivity: Sensitivity) -> int:
    return sensitivity.value


def visibility_rank(visibility: Visibility | None) -> int:
    if visibility is None or visibility == Visibility.PU:
        return 0
    return visibility.value


def strongest_sensitivity(signals: Iterable[SemanticSignal]) -> Sensitivity:
    return max(
        (signal.sensitivity for signal in signals),
        key=sensitivity_rank,
        default=Sensitivity.S0,
    )


def strongest_visibility(signals: Iterable[SemanticSignal]) -> Visibility:
    return max(
        (
            signal.visibility
            for signal in signals
            if signal.visibility is not None
        ),
        key=visibility_rank,
        default=Visibility.PU,
    )


def signal_span(signals: Iterable[SemanticSignal], text: str) -> Tuple[int, int] | None:
    spans = [signal.span for signal in signals]
    if not spans:
        return None

    start = max(0, min(span[0] for span in spans))
    end = min(len(text), max(span[1] for span in spans))
    if start >= end:
        return None
    return (start, end)


def signal_excerpt(signals: Iterable[SemanticSignal], text: str) -> str:
    span = signal_span(signals, text)
    if span is None:
        return text
    return text[span[0] : span[1]]


def _compile_many(patterns: Iterable[str]) -> Tuple[Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


_PATTERN_DEFINITIONS: Tuple[PatternDefinition, ...] = (
    PatternDefinition(
        category=Category.HEALTH,
        sensitivity=Sensitivity.S3,
        visibility=None,
        reason="Health or medical context was disclosed.",
        weight=1.45,
        patterns=_compile_many(
            [
                r"\b(?:diagnosed|diagnosis|doctor|hospital|clinic|therapy|therapist)\b",
                r"\b(?:medication|prescription|antidepressant|ssri|insulin|opioid)\b",
                r"\b(?:anxiety|depression|bipolar|ptsd|adhd|autism|cancer|hiv|std)\b",
                r"\b(?:pregnant|miscarriage|fertility|disability|chronic illness)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.POLITICS,
        sensitivity=Sensitivity.S3,
        visibility=None,
        reason="Political belief, affiliation, or activity was disclosed.",
        weight=1.25,
        patterns=_compile_many(
            [
                r"\b(?:voted for|voting for|campaigning for|political party)\b",
                r"\b(?:democrat|republican|libertarian|socialist|conservative|progressive)\b",
                r"\b(?:protest|activism|activist|union organizer)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.RELIGION,
        sensitivity=Sensitivity.S3,
        visibility=None,
        reason="Religious belief, affiliation, or practice was disclosed.",
        weight=1.25,
        patterns=_compile_many(
            [
                r"\b(?:church|mosque|synagogue|temple|worship|prayer group)\b",
                r"\b(?:christian|muslim|jewish|hindu|buddhist|atheist|agnostic)\b",
                r"\b(?:converted to|left my religion|religious community)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.CRIMINAL,
        sensitivity=Sensitivity.S3,
        visibility=None,
        reason="Criminal history or legal exposure was disclosed.",
        weight=1.35,
        patterns=_compile_many(
            [
                r"\b(?:arrested|charged with|convicted|probation|parole)\b",
                r"\b(?:criminal record|restraining order|court date|lawsuit)\b",
                r"\b(?:dui|felony|misdemeanor|police report)\b",
                r"\b(?:protective order|sealed arrest record|case number|hearing)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.FINANCIAL,
        sensitivity=Sensitivity.S2,
        visibility=None,
        reason="Financial circumstances or account context was disclosed.",
        weight=1.05,
        patterns=_compile_many(
            [
                r"\b(?:salary|paycheck|mortgage|rent arrears|debt|bankruptcy)\b",
                r"\b(?:bank account|credit score|loan application|tax return)\b",
                r"\b(?:inheritance|investment portfolio|student loans)\b",
                r"\b(?:salary offer|account number|routing number|sort code)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.SEXUAL,
        sensitivity=Sensitivity.S3,
        visibility=None,
        reason="Sexual orientation or intimate context was disclosed.",
        weight=1.35,
        patterns=_compile_many(
            [
                r"\b(?:sexual orientation|coming out|came out|closeted)\b",
                r"\b(?:gay|lesbian|bisexual|transgender|nonbinary|queer)\b",
                r"\b(?:intimate partner|sexual history|pregnancy scare)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.CHILD,
        sensitivity=Sensitivity.S3,
        visibility=None,
        reason="Child or minor-related information was disclosed.",
        weight=1.25,
        patterns=_compile_many(
            [
                r"\b(?:my child|my kid|my son|my daughter|minor child)\b",
                r"\b(?:school pickup|daycare|custody schedule|child support)\b",
                r"\b(?:underage|minor|teenager|toddler)\b",
                r"\b(?:grade [1-9]|iep meeting|counseling appointment)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.LOCATION,
        sensitivity=Sensitivity.S2,
        visibility=None,
        reason="Private location or routine context was disclosed.",
        weight=1.05,
        patterns=_compile_many(
            [
                r"\b(?:where I live|my apartment|my house|my home address)\b",
                r"\b(?:commute|usual route|walk home|parked outside)\b",
                r"\b(?:near my home|near my office|in my neighborhood)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.IDENTITY,
        sensitivity=Sensitivity.S2,
        visibility=None,
        reason="Indirectly identifying context was disclosed.",
        weight=1.0,
        patterns=_compile_many(
            [
                r"\b(?:I work at|my employer|my workplace|my manager|my team)\b",
                r"\b(?:only person|small team|unique role|job title)\b",
                r"\b(?:my username|my handle|my profile|my account)\b",
                r"\b(?:employee id|student id|performance warning|disciplinary note|transcript)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=Category.THIRD_PARTY,
        sensitivity=Sensitivity.S2,
        visibility=None,
        reason="Information about another person was disclosed.",
        weight=1.0,
        patterns=_compile_many(
            [
                r"\b(?:my wife|my husband|my partner|my friend|my coworker|my boss)\b",
                r"\b(?:my patient|my client|my student|my tenant|my employee)\b",
                r"\b(?:his|her|their) (?:diagnosis|salary|address|phone|email|record)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=None,
        sensitivity=Sensitivity.S0,
        visibility=Visibility.P0,
        reason="Text states that the context is public.",
        weight=0.25,
        patterns=_compile_many(
            [
                r"\b(?:public post|public profile|posted publicly|on twitter|on reddit)\b",
                r"\b(?:visible to everyone|publicly visible)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=None,
        sensitivity=Sensitivity.S0,
        visibility=Visibility.P1,
        reason="Text states that the context is semi-public.",
        weight=0.3,
        patterns=_compile_many(
            [
                r"\b(?:forum thread|community thread|discord server|public channel)\b",
                r"\b(?:community chat|group forum)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=None,
        sensitivity=Sensitivity.S0,
        visibility=Visibility.P2,
        reason="Text states that the context is access restricted.",
        weight=0.35,
        patterns=_compile_many(
            [
                r"\b(?:members only|behind login|authenticated users|restricted page)\b",
                r"\b(?:private account|locked account)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=None,
        sensitivity=Sensitivity.S0,
        visibility=Visibility.P3,
        reason="Text states that the context is group-private.",
        weight=0.45,
        patterns=_compile_many(
            [
                r"\b(?:group chat|direct message|private dm|private channel)\b",
                r"\b(?:slack dm|teams chat|private workspace)\b",
            ]
        ),
    ),
    PatternDefinition(
        category=None,
        sensitivity=Sensitivity.S0,
        visibility=Visibility.P4,
        reason="Text states that the context is personal-private.",
        weight=0.5,
        patterns=_compile_many(
            [
                r"\b(?:private diary|personal diary|journal entry|private note)\b",
                r"\b(?:not shared with anyone|for my eyes only)\b",
            ]
        ),
    ),
)
