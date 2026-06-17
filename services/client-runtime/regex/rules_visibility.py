from typing import List

from classification import Sensitivity, Visibility, initialise_unpacked
from regex.rule_types import RuleDefinition


def visibility_rules() -> List[RuleDefinition]:
    """Visibility-only rules. They add no category until fused with sensitive evidence."""
    return [
        RuleDefinition(
            "visibility_public",
            r"\b(public(?:ly)?|public\s+(?:post|profile|page)|visible\s+to\s+anyone|open\s+internet)\b",
            initialise_unpacked(Sensitivity.S0, Visibility.P0, []),
            "visibility_public",
        ),
        RuleDefinition(
            "visibility_semi_public",
            r"\b(community\s+(?:page|thread|forum)|public\s+thread|members?\s+thread|semi-public)\b",
            initialise_unpacked(Sensitivity.S0, Visibility.P1, []),
            "visibility_semi_public",
        ),
        RuleDefinition(
            "visibility_restricted",
            r"\b(behind\s+(?:login|authentication)|authenticated|restricted|members?\s+only|logged-in\s+users?)\b",
            initialise_unpacked(Sensitivity.S0, Visibility.P2, []),
            "visibility_restricted",
        ),
        RuleDefinition(
            "visibility_group_private",
            r"\b(group\s+(?:chat|dm|message)|shared\s+dm|private\s+(?:group|workspace|channel)|team\s+chat)\b",
            initialise_unpacked(Sensitivity.S0, Visibility.P3, []),
            "visibility_group_private",
        ),
        RuleDefinition(
            "visibility_personal_private",
            r"\b(personal\s+(?:note|diary|journal)|my\s+(?:diary|journal)|diary|journal|only\s+me|not\s+shared|private\s+note|local-only)\b",
            initialise_unpacked(Sensitivity.S0, Visibility.P4, []),
            "visibility_personal_private",
        ),
    ]
