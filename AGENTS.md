# Contributor rules (humans and coding agents)

SonarQube Cloud analyzes every push to `main`. A push that adds a bug, a
vulnerability or a code smell turns the Quality Gate red and emails the
maintainer. Keep the project at zero open issues:

- Run the full test suite before every push. `tests/test_code_quality.py`
  fails on the problems below, so a green run means Sonar stays green.
- Cognitive complexity of every function must stay at 15 or less
  (Sonar rule S3776). Extract small helpers instead of nesting branches.
- Reuse the project's existing validation helpers for any network
  destination or file path that comes from the command line or from scanned
  input (SSRF and path-traversal rules S8703/S8707).
- Regular expressions must be linear: no ambiguous adjacent quantifiers such
  as `\s*\w*\s*`, no nested quantifiers (S8786), complexity under 20 (S5843).
  Use `\w` instead of `[A-Za-z0-9_]` (S6353), with `re.ASCII` when ASCII
  semantics matter.
- No unused local variables (use `_`, S1481), no nested conditional
  expressions (S3358), no `assert` inside `try` blocks that catch
  `AssertionError` (S5779), no redundant exception subclasses in one
  `except` tuple (S5713), only one call that can raise inside
  `pytest.raises` (S5778), split composite `assert a and b` (S9073).
- Never add `# NOSONAR` or other suppressions. Never add AI co-author or
  attribution lines to commits.
