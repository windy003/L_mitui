"""YAML 输入/输出无需硬依赖。

写入功能完全自包含：我们只输出 mihomo 配置所需的 YAML 子集（嵌套映射、列表、标量），
因此手写序列化器既足够，也能保证行为可预测。

读取时，如果已安装 PyYAML，则优先使用它——订阅内容来自各种不同的提供方；
否则回退到一个小型的块式/流式解析器，支持 Clash/mihomo 订阅文件实际使用的语法。
"""

from __future__ import annotations

import re
from typing import Any

_PLAIN_OK = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-./@ ]*$")
_NUMLIKE = re.compile(r"^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$")
_RESERVED = {"y", "yes", "n", "no", "true", "false", "on", "off", "null", "none", "~", ""}


# --------------------------------------------------------------------------- #
# dump
# --------------------------------------------------------------------------- #
def quote(s: str) -> str:
    """将 Python 字符串渲染为 YAML 标量，仅在必要时添加引号。"""
    if (
        _PLAIN_OK.match(s)
        and s.strip() == s
        and s.lower() not in _RESERVED
        and not _NUMLIKE.match(s)
    ):
        return s
    body = (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\t", "\\t")
        .replace("\r", "\\r")
    )
    return '"%s"' % body


def _scalar(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return repr(v)
    return quote(str(v))


def _is_flat(v: Any) -> bool:
    """True for a short all-scalar sequence, which is rendered inline.

    Long scalar lists (rule sets, filter lists) stay in block style so the
    generated config is still readable in an editor.
    """
    if not all(not isinstance(x, (dict, list, tuple)) for x in v):
        return False
    rendered = len(_flow(v))
    return len(v) <= 8 and rendered <= 100


def _flow(v: Any) -> str:
    return "[%s]" % ", ".join(_scalar(x) for x in v)


def _dump(v: Any, indent: int, out: list) -> None:
    sp = " " * indent
    if isinstance(v, dict):
        for k, val in v.items():
            key = quote(str(k))
            if isinstance(val, dict):
                if not val:
                    out.append("%s%s: {}" % (sp, key))
                else:
                    out.append("%s%s:" % (sp, key))
                    _dump(val, indent + 2, out)
            elif isinstance(val, (list, tuple)):
                if not val:
                    out.append("%s%s: []" % (sp, key))
                elif _is_flat(val):
                    out.append("%s%s: %s" % (sp, key, _flow(val)))
                else:
                    out.append("%s%s:" % (sp, key))
                    _dump(val, indent, out)
            else:
                out.append("%s%s: %s" % (sp, key, _scalar(val)))
    elif isinstance(v, (list, tuple)):
        for item in v:
            if isinstance(item, dict):
                if not item:
                    out.append("%s- {}" % sp)
                    continue
                lines = []
                _dump(item, indent + 2, lines)
                lines[0] = sp + "- " + lines[0][indent + 2:]
                out.extend(lines)
            elif isinstance(item, (list, tuple)):
                if _is_flat(item):
                    out.append("%s- %s" % (sp, _flow(item)))
                else:
                    out.append("%s-" % sp)
                    _dump(item, indent + 2, out)
            else:
                out.append("%s- %s" % (sp, _scalar(item)))
    else:
        out.append(sp + _scalar(v))


def dump(obj: Any) -> str:
    out: list = []
    _dump(obj, 0, out)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# load
# --------------------------------------------------------------------------- #
def load(text: str) -> Any:
    """Parse YAML. Raises ValueError when the text cannot be parsed at all."""
    try:
        import yaml  # type: ignore
    except ImportError:
        pass
    else:
        try:
            return yaml.safe_load(text)
        except Exception:
            pass  # fall through to the built-in parser
    try:
        return _Parser(text).parse()
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError("invalid YAML: %s" % exc) from exc


class _Line:
    __slots__ = ("indent", "text")

    def __init__(self, indent: int, text: str) -> None:
        self.indent = indent
        self.text = text


def _strip_comment(s: str) -> str:
    out = []
    quote_ch = ""
    i = 0
    while i < len(s):
        ch = s[i]
        if quote_ch:
            out.append(ch)
            if ch == "\\" and quote_ch == '"' and i + 1 < len(s):
                out.append(s[i + 1])
                i += 2
                continue
            if ch == quote_ch:
                quote_ch = ""
        elif ch in "\"'":
            quote_ch = ch
            out.append(ch)
        elif ch == "#" and (not out or out[-1] in " \t"):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _balance(s: str) -> int:
    """Net bracket depth of s, ignoring quoted sections."""
    depth = 0
    quote_ch = ""
    i = 0
    while i < len(s):
        ch = s[i]
        if quote_ch:
            if ch == "\\" and quote_ch == '"':
                i += 2
                continue
            if ch == quote_ch:
                quote_ch = ""
        elif ch in "\"'":
            quote_ch = ch
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        i += 1
    return depth


class _Parser:
    """Indentation based parser for the common YAML subset."""

    def __init__(self, text: str) -> None:
        self.anchors: dict = {}
        self.lines = self._lex(text)

    def _lex(self, text: str) -> list:
        raw = []
        for ln in text.replace("\t", "    ").splitlines():
            if ln.strip() in ("---", "..."):
                continue
            body = _strip_comment(ln)
            if not body.strip():
                continue
            indent = len(body) - len(body.lstrip(" "))
            raw.append(_Line(indent, body.strip()))
        # join flow collections that span several physical lines
        merged = []
        i = 0
        while i < len(raw):
            cur = raw[i]
            depth = _balance(cur.text)
            text_acc = cur.text
            while depth > 0 and i + 1 < len(raw):
                i += 1
                text_acc += " " + raw[i].text
                depth += _balance(raw[i].text)
            merged.append(_Line(cur.indent, text_acc))
            i += 1
        return merged

    def parse(self) -> Any:
        if not self.lines:
            return None
        value, _ = self._block(0, self.lines[0].indent)
        return value

    def _sub(self, lines: list) -> Any:
        child = _Parser.__new__(_Parser)
        child.anchors = self.anchors
        child.lines = lines
        return child.parse()

    def _block(self, i: int, indent: int):
        if i >= len(self.lines):
            return None, i
        if self.lines[i].text.startswith("-"):
            return self._seq(i, indent)
        return self._map(i, indent)

    def _seq(self, i: int, indent: int):
        items = []
        while i < len(self.lines):
            ln = self.lines[i]
            if ln.indent < indent or not ln.text.startswith("-"):
                break
            if ln.indent > indent:  # stray deeper line
                i += 1
                continue
            rest = ln.text[1:].strip()
            offset = (len(ln.text) - len(ln.text[1:].lstrip())) if rest else 0
            i += 1
            if not rest:
                if i < len(self.lines) and self.lines[i].indent > indent:
                    val, i = self._block(i, self.lines[i].indent)
                else:
                    val = None
            elif rest[0] in "{[":
                val = parse_flow(rest)
            elif self._looks_like_key(rest):
                sub = [_Line(indent + offset, rest)]
                j = i
                while j < len(self.lines) and self.lines[j].indent > indent:
                    sub.append(self.lines[j])
                    j += 1
                val = self._sub(sub)
                i = j
            else:
                val = self._value(rest)
            items.append(val)
        return items, i

    def _map(self, i: int, indent: int):
        out: dict = {}
        while i < len(self.lines):
            ln = self.lines[i]
            if ln.indent < indent:
                break
            if ln.indent > indent or ln.text.startswith("-"):
                i += 1
                continue
            key, sep, rest = self._split_key(ln.text)
            if not sep:
                i += 1
                continue
            rest = rest.strip()
            i += 1
            anchor = ""
            if rest.startswith("&"):
                name, _, tail = rest.partition(" ")
                anchor = name[1:]
                rest = tail.strip()
            if not rest:
                nxt = self.lines[i] if i < len(self.lines) else None
                if nxt and nxt.indent > indent:
                    val, i = self._block(i, nxt.indent)
                elif nxt and nxt.indent == indent and nxt.text.startswith("-"):
                    # a sequence may sit at the same indent as its parent key
                    val, i = self._seq(i, indent)
                else:
                    val = None
            else:
                val = self._value(rest)
            if anchor:
                self.anchors[anchor] = val
            if key == "<<" and isinstance(val, dict):
                out.update(val)
            else:
                out[key] = val
        return out, i

    @staticmethod
    def _looks_like_key(s: str) -> bool:
        key, sep, _ = _Parser._split_key(s)
        return bool(sep) and bool(key)

    @staticmethod
    def _split_key(s: str):
        quote_ch = ""
        i = 0
        while i < len(s):
            ch = s[i]
            if quote_ch:
                if ch == "\\" and quote_ch == '"':
                    i += 2
                    continue
                if ch == quote_ch:
                    quote_ch = ""
            elif ch in "\"'":
                quote_ch = ch
            elif ch in "{[":
                return "", "", s
            elif ch == ":" and (i + 1 == len(s) or s[i + 1] in " \t"):
                return str(unquote_scalar(s[:i].strip())), ":", s[i + 1:]
            i += 1
        return "", "", s

    def _value(self, s: str) -> Any:
        if s.startswith("*"):
            return self.anchors.get(s[1:].strip())
        if s[0] in "{[":
            return parse_flow(s)
        if s[0] in "|>":
            return ""  # block scalars are not used by mihomo configs
        return unquote_scalar(s)


def unquote_scalar(s: str) -> Any:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        body = s[1:-1]
        if s[0] == '"':
            body = (
                body.replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\r", "\r")
                .replace('\\"', '"')
                .replace("\\\\", "\\")
            )
        else:
            body = body.replace("''", "'")
        return body
    low = s.lower()
    if low in ("null", "~", ""):
        return None
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if re.match(r"^[-+]?\d+$", s):
        try:
            return int(s)
        except ValueError:
            return s
    if _NUMLIKE.match(s):
        try:
            return float(s)
        except ValueError:
            return s
    return s


def parse_flow(s: str) -> Any:
    value, _ = _flow_node(s, 0)
    return value


def _flow_node(s: str, i: int):
    i = _skip_ws(s, i)
    if i >= len(s):
        return None, i
    if s[i] == "{":
        out: dict = {}
        i += 1
        while True:
            i = _skip_ws(s, i)
            if i >= len(s) or s[i] == "}":
                return out, i + 1
            key, i = _flow_token(s, i, ":,}")
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == ":":
                i += 1
                val, i = _flow_node(s, i)
            else:
                val = None
            out[str(key)] = val
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == ",":
                i += 1
    if s[i] == "[":
        arr: list = []
        i += 1
        while True:
            i = _skip_ws(s, i)
            if i >= len(s) or s[i] == "]":
                return arr, i + 1
            val, i = _flow_node(s, i)
            arr.append(val)
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == ",":
                i += 1
    return _flow_token(s, i, ",}]")


def _flow_token(s: str, i: int, stop: str):
    i = _skip_ws(s, i)
    if i < len(s) and s[i] in "\"'":
        q = s[i]
        j = i + 1
        buf = []
        while j < len(s):
            if s[j] == "\\" and q == '"' and j + 1 < len(s):
                buf.append(s[j:j + 2])
                j += 2
                continue
            if s[j] == q:
                j += 1
                break
            buf.append(s[j])
            j += 1
        return unquote_scalar(q + "".join(buf) + q), j
    j = i
    while j < len(s) and s[j] not in stop:
        j += 1
    return unquote_scalar(s[i:j]), j


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t":
        i += 1
    return i
