"""Text helpers shared by the analyzers.

Every analyzer works on the decoded text of one file. Line numbers follow the
editor convention: only LF, CRLF and a lone CR end a line. ``str.splitlines``
also splits on form feeds and Unicode separators, which shifts line numbers,
so analyzers must use :func:`split_lines` instead.
"""

from __future__ import annotations

import bisect
import codecs
import re

_LONE_CR = re.compile(r"\r(?!\n)")


def decode_source(data: bytes) -> str:
    """Decode file bytes; undecodable bytes become U+FFFD, lone CR becomes LF."""
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = data.decode("utf-16", errors="replace")
    else:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace").removeprefix("﻿")
    return _LONE_CR.sub("\n", text)


def split_lines(text: str) -> list[str]:
    """Split on LF only and drop the CR of CRLF endings."""
    lines = text.split("\n")
    return [line[:-1] if line.endswith("\r") else line for line in lines]


class LineIndex:
    """Map character offsets to 1-based (line, column) pairs."""

    def __init__(self, text: str) -> None:
        self._starts = [0]
        self._starts.extend(index + 1 for index, char in enumerate(text) if char == "\n")

    def position(self, offset: int) -> tuple[int, int]:
        line = bisect.bisect_right(self._starts, offset) - 1
        return line + 1, offset - self._starts[line] + 1


def utf8_column_to_char(line: str, byte_offset: int) -> int:
    """Convert a UTF-8 byte offset inside ``line`` to a character offset.

    CPython's ``ast`` reports ``col_offset`` in UTF-8 bytes.
    """
    return len(line.encode("utf-8")[:byte_offset].decode("utf-8", errors="ignore"))


# Comment styles for :func:`blank_comments`.
C_STYLE = "c"  # // and /* */  (Java, C#, Go, C, C++, Rust, Kotlin, Swift)
JS_STYLE = "js"  # C style plus template literals and regex literals
PHP_STYLE = "php"  # C style plus # line comments
HASH_STYLE = "hash"  # # line comments (Ruby, YAML, TOML, Dockerfile, .env)
SHELL_STYLE = "shell"  # # only at a word boundary
POWERSHELL_STYLE = "powershell"  # # and <# #>
PYTHON_STYLE = "python"  # # comments, triple-quoted strings
BATCH_STYLE = "batch"  # REM and :: lines
XML_STYLE = "xml"  # <!-- -->
NO_COMMENTS = "none"

_REGEX_PREFIX_CHARS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_PREFIX_WORDS = {
    "return",
    "typeof",
    "case",
    "do",
    "else",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "yield",
    "await",
}


def comment_style(language: str) -> str:
    return {
        "Python": PYTHON_STYLE,
        "JavaScript": JS_STYLE,
        "TypeScript": JS_STYLE,
        "PHP": PHP_STYLE,
        "Java": C_STYLE,
        "C#": C_STYLE,
        "Go": C_STYLE,
        "C": C_STYLE,
        "C++": C_STYLE,
        "Rust": C_STYLE,
        "Kotlin": C_STYLE,
        "Swift": C_STYLE,
        "Scala": C_STYLE,
        "Ruby": HASH_STYLE,
        "YAML": HASH_STYLE,
        "TOML": HASH_STYLE,
        "Dockerfile": HASH_STYLE,
        "Environment": HASH_STYLE,
        "Configuration": HASH_STYLE,
        "Terraform": HASH_STYLE,
        "HCL": HASH_STYLE,
        "Manifest": HASH_STYLE,
        "Shell": SHELL_STYLE,
        "PowerShell": POWERSHELL_STYLE,
        "Batch": BATCH_STYLE,
        "XML": XML_STYLE,
        "HTML": XML_STYLE,
    }.get(language, NO_COMMENTS)


def blank_comments(text: str, style: str) -> str:
    """Replace comment characters with spaces; keep strings, newlines and offsets."""
    if style == NO_COMMENTS:
        return text
    if style == BATCH_STYLE:
        return "\n".join(
            " " * len(line)
            if line.lstrip().casefold().startswith(("rem ", "::")) or line.strip().casefold() == "rem"
            else line
            for line in text.split("\n")
        )
    if style == XML_STYLE:
        return re.sub(r"<!--.*?-->", lambda match: _spaces(match.group(0)), text, flags=re.DOTALL)
    return "".join(_scan(text, style, keep_comments=False))


def code_mask(text: str, style: str) -> str:
    """Return ``text`` with comments and string contents replaced by spaces.

    Quote characters stay in place so callers can still see string boundaries.
    JavaScript template-literal expressions (``${...}``) remain visible.
    """
    return "".join(_scan(text, style, keep_comments=False, blank_strings=True))


def _spaces(value: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in value)


def _scan(text: str, style: str, *, keep_comments: bool, blank_strings: bool = False) -> list[str]:
    out = list(text)
    length = len(text)
    index = 0
    line_comment = {"//"} if style in {C_STYLE, JS_STYLE, PHP_STYLE} else set()
    hash_comment = style in {HASH_STYLE, PHP_STYLE, POWERSHELL_STYLE, PYTHON_STYLE, SHELL_STYLE}
    block = style in {C_STYLE, JS_STYLE, PHP_STYLE}
    quotes = {"'", '"'}
    if style in {JS_STYLE, C_STYLE}:
        quotes.add("`")
    template_stack: list[int] = []  # brace depth of each open ${ ... } in JS
    brace_depth = 0
    previous_code = ""  # last significant code character (for JS regex detection)
    previous_word = ""

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if out[position] != "\n":
                out[position] = " "

    while index < length:
        char = text[index]
        pair = text[index : index + 2]
        # Line comments.
        if pair in line_comment or (
            hash_comment
            and char == "#"
            and _hash_starts_comment(text, index, style)
        ):
            end = text.find("\n", index)
            end = length if end < 0 else end
            if not keep_comments:
                blank(index, end)
            index = end
            continue
        if block and pair == "/*":
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            if not keep_comments:
                blank(index, end)
            index = end
            continue
        if style == POWERSHELL_STYLE and pair == "<#":
            end = text.find("#>", index + 2)
            end = length if end < 0 else end + 2
            if not keep_comments:
                blank(index, end)
            index = end
            continue
        if style == HASH_STYLE and char == "=" and text.startswith("=begin", index) and (
            index == 0 or text[index - 1] == "\n"
        ):
            end = text.find("\n=end", index)
            end = length if end < 0 else end + 5
            if not keep_comments:
                blank(index, end)
            index = end
            continue
        # JavaScript template expression close.
        if style == JS_STYLE and template_stack and char == "}" and brace_depth == template_stack[-1]:
            template_stack.pop()
            index = _scan_string(text, index + 1, "`", out, blank_strings, template_stack, brace_depth, True)
            previous_code = "`"
            continue
        if char in quotes:
            if style == PYTHON_STYLE and text.startswith(char * 3, index):
                end = text.find(char * 3, index + 3)
                while end > 0 and _escaped(text, end):
                    end = text.find(char * 3, end + 1)
                end = length if end < 0 else end + 3
                if blank_strings:
                    blank(index + 3, max(index + 3, end - 3))
                index = end
            else:
                index = _scan_string(
                    text, index + 1, char, out, blank_strings, template_stack, brace_depth, style == JS_STYLE
                )
            previous_code = char
            previous_word = ""
            continue
        if style == JS_STYLE and char == "/" and _js_regex_allowed(previous_code, previous_word):
            end = _scan_js_regex(text, index)
            if end > index:
                if blank_strings:
                    blank(index + 1, end)
                index = end
                previous_code = "/"
                previous_word = ""
                continue
        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
        if not char.isspace():
            if char.isalnum() or char in "_$":
                previous_word = previous_word + char if previous_code and (
                    previous_code.isalnum() or previous_code in "_$"
                ) else char
            else:
                previous_word = ""
            previous_code = char
        index += 1
    return out


def _hash_starts_comment(text: str, index: int, style: str) -> bool:
    if style == PHP_STYLE and text.startswith("#[", index):
        return False  # PHP 8 attribute
    if style == HASH_STYLE and text.startswith("#{", index):
        return False  # Ruby interpolation inside backticks or %x()
    if style == HASH_STYLE and index > 0 and text[index - 1] not in " \t\n":
        # YAML/Ruby: '#' glued to a word is part of a value (url#frag, $#)
        line_start = text.rfind("\n", 0, index) + 1
        return text[line_start:index].strip() == ""
    if style == SHELL_STYLE and index > 0 and text[index - 1] not in " \t\n;|&(":
        return False  # ${#var}, $#
    return True


def _escaped(text: str, index: int) -> bool:
    backslashes = 0
    position = index - 1
    while position >= 0 and text[position] == "\\":
        backslashes += 1
        position -= 1
    return backslashes % 2 == 1


def _scan_string(
    text: str,
    index: int,
    quote: str,
    out: list[str],
    blank_strings: bool,
    template_stack: list[int],
    brace_depth: int,
    templates: bool,
) -> int:
    """Advance past a string body starting after its opening quote."""
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            if blank_strings:
                out[index] = " "
                if index + 1 < length and text[index + 1] != "\n":
                    out[index + 1] = " "
            index += 2
            continue
        if templates and quote == "`" and text.startswith("${", index):
            template_stack.append(brace_depth)
            return index + 2
        if char == quote:
            return index + 1
        if char == "\n" and quote != "`":
            return index  # unterminated single-line string
        if blank_strings and char != "\n":
            out[index] = " "
        index += 1
    return length


def _js_regex_allowed(previous_code: str, previous_word: str) -> bool:
    if not previous_code:
        return True
    if previous_word in _REGEX_PREFIX_WORDS:
        return True
    return previous_code in _REGEX_PREFIX_CHARS


def _scan_js_regex(text: str, index: int) -> int:
    """Return the end offset of a regex literal starting at ``index`` or ``index``."""
    if text.startswith(("//", "/*"), index):
        return index
    position = index + 1
    in_class = False
    while position < len(text):
        char = text[position]
        if char == "\n":
            return index
        if char == "\\":
            position += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            position += 1
            while position < len(text) and text[position].isalpha():
                position += 1
            return position
        position += 1
    return index


def matching_paren(mask: str, open_index: int) -> int:
    """Return the index of the bracket closing ``mask[open_index]`` or -1.

    ``mask`` must come from :func:`code_mask` so brackets inside strings and
    comments are already blanked.
    """
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[mask[open_index]]]
    for position in range(open_index + 1, len(mask)):
        char = mask[position]
        if char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            if not stack or char != stack[-1]:
                return -1
            stack.pop()
            if not stack:
                return position
    return -1


def split_arguments(mask: str, start: int, end: int) -> list[tuple[int, int]]:
    """Split ``mask[start:end]`` on top-level commas; return trimmed spans."""
    spans: list[tuple[int, int]] = []
    depth = 0
    segment_start = start
    for position in range(start, end):
        char = mask[position]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            spans.append(_trim(mask, segment_start, position))
            segment_start = position + 1
    spans.append(_trim(mask, segment_start, end))
    return [span for span in spans if span[0] < span[1]]


def _trim(mask: str, start: int, end: int) -> tuple[int, int]:
    while start < end and mask[start].isspace():
        start += 1
    while end > start and mask[end - 1].isspace():
        end -= 1
    return start, end
