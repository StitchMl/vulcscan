"""Regression tests for regexes rewritten to avoid super-linear backtracking."""

import time

from vulcscan import javascript, lexical, names, patch_guidance, structured


def test_js_headers_keep_captures() -> None:
    assert javascript._FUNCTION_DECLARATION.search("function* gen(a, b)").groups() == ("gen", "a, b")
    assert javascript._ARROW_PARENS.search("handler: async (a, b): T =>").groups() == ("handler", "a, b")
    assert javascript._ARROW_BARE.search("x = async y =>").groups() == ("x", "y")


def test_cors_origin_option_and_set_is_origin_allowed() -> None:
    option = lexical._CORS_REFLECT[0]
    assert [m.group(0) for m in option.finditer("cors({ origin: true })")] == ["cors({ origin: true }"]
    assert [m.group(0) for m in option.finditer("cors({ origin: (o) => true, a: 1 })")] == ["cors({ origin: (o) => true, a: 1 }"]
    assert not list(option.finditer("cors({ origin: 'x' })"))
    assert lexical._CORS_REFLECT[3].search("SetIsOriginAllowed((o) => true)")


def test_components_split() -> None:
    assert names.components("APIKey2Secret") == ["api", "key", "2", "secret"]


def test_callee_and_literal_base() -> None:
    assert patch_guidance._callee("Foo . bar (x)") == "Foo.bar"
    bs = chr(92)
    assert patch_guidance._literal_base(f"C:{bs}a{bs}b.txt") == f"C:{bs}a{bs}"
    assert patch_guidance._literal_base("/x/y") == "/x/"


def test_csharp_parameters_and_shell_read() -> None:
    found = [m.group(1) for m in structured._CS_PARAMETERS.finditer("([FromQuery] Dictionary<string, int> map, [FromBody] Dto body)")]
    assert found == ["map", "body"]
    shell_read = structured.CATALOGS["Shell"].inputs[0][0]
    assert [m.group(1) for m in shell_read.finditer("read -r -p 'x' name; read other")] == ["name", "other"]


def test_long_whitespace_runs_stay_fast() -> None:
    start = time.perf_counter()
    blank = " " * 50000
    javascript._FUNCTION_DECLARATION.search("function" + blank)
    javascript._ARROW_BARE.search("a" * 50000)
    patch_guidance._callee(blank)
    list(structured._CS_PARAMETERS.finditer("[FromQuery] " + blank + "a"))
    assert time.perf_counter() - start < 2
