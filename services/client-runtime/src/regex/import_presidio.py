from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.pattern_recognizer import PatternRecognizer

engine = AnalyzerEngine()

for recognizer in engine.registry.recognizers:

    if not isinstance(recognizer, PatternRecognizer):
        continue

    print(f"# {recognizer.name}")

    for pattern in recognizer.patterns:

        print(
f'''RuleDefinition(
    "{pattern.name.lower()}",
    r"""{pattern.regex}""",
    initialise_unpacked(
        Sensitivity.S2,
        Visibility.PU,
        [Category.IDENTITY]
    ),
    "{pattern.name.lower()}",
),
'''
        )