"""Local guard for the SonarQube Cloud cognitive-complexity rule (S3776).

complexipy implements the same cognitive-complexity metric SonarQube uses,
so this test fails before a push would turn the Quality Gate red.
"""
from pathlib import Path

import complexipy  # listed in the dev/test dependencies; install it before running tests

PACKAGE = Path(__file__).parents[1] / "vulcscan"
LIMIT = 15


def test_every_function_stays_within_sonar_cognitive_complexity():
    offenders = [
        f"{path.name}:{function.line_start} {function.name} = {function.complexity}"
        for path in sorted(PACKAGE.glob("*.py"))
        for function in complexipy.file_complexity(str(path)).functions
        if function.complexity > LIMIT
    ]
    assert offenders == [], "Cognitive complexity above 15:\n" + "\n".join(offenders)
