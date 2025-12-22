from __future__ import annotations

import base64
import fnmatch
import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

logger = logging.getLogger(__name__)


def _normalize_level(level: Any) -> str:
    value = str(level or "").strip().lower()
    return value or "unknown"


def _normalize_severity_filter(severity_filter: Optional[Sequence[str]]) -> Optional[Set[str]]:
    if not severity_filter:
        return None
    return {str(level).strip().lower() for level in severity_filter if str(level).strip()}


def _get_nested_value(data: Dict[str, Any], path: str) -> Optional[Any]:
    """
    Retrieves a value from a nested dictionary using dot notation.
    Supports composite keys containing dots by attempting to match the
    remaining path as a single key when traversal fails.
    """
    if not path:
        return None
    if path in data:
        return data.get(path)

    keys = path.split(".")
    current: Any = data
    for i, key in enumerate(keys):
        if not isinstance(current, dict):
            return None

        if i < len(keys) - 1:
            remaining = ".".join(keys[i:])
            if remaining in current:
                return current.get(remaining)

        current = current.get(key)

    return current


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _contains_ci(haystack: str, needle: str) -> bool:
    return needle.lower() in haystack.lower()


def _startswith_ci(haystack: str, prefix: str) -> bool:
    return haystack.lower().startswith(prefix.lower())


def _endswith_ci(haystack: str, suffix: str) -> bool:
    return haystack.lower().endswith(suffix.lower())


def _eq_ci(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return False

    # Try numeric comparison when appropriate.
    if isinstance(b, bool):
        if isinstance(a, bool):
            return a is b
        if isinstance(a, str):
            return a.strip().lower() in ("true", "1") if b else a.strip().lower() in ("false", "0")
        return bool(a) is b

    if isinstance(b, (int, float)) and not isinstance(b, bool):
        if isinstance(a, (int, float)) and not isinstance(a, bool):
            return a == b
        if isinstance(a, str):
            try:
                return float(a.strip()) == float(b)
            except ValueError:
                return False
        return False

    # Default: case-insensitive string equality.
    return _coerce_str(a).strip().lower() == _coerce_str(b).strip().lower()


def _windash_variants(pattern: str) -> List[str]:
    """
    Sigma `windash` modifier: treat '-' and '/' as interchangeable option prefixes.
    We generate a small set of variant patterns (max 2) for matching.
    """
    if not pattern:
        return [pattern]

    variants = {pattern}
    if "-" in pattern and "/" not in pattern:
        variants.add(pattern.replace("-", "/", 1))
    elif "/" in pattern and "-" not in pattern:
        variants.add(pattern.replace("/", "-", 1))

    return list(variants)


def _collapse_backslashes(value: str) -> str:
    if not value:
        return value
    # Collapse runs of backslashes (e.g., "\\\\foo" -> "\\foo").
    # This improves compatibility with Sigma rules that encode Windows paths using double backslashes.
    while "\\\\" in value:
        value = value.replace("\\\\", "\\")
    return value


def _backslash_variants(pattern: str) -> List[str]:
    if not pattern:
        return [pattern]
    collapsed = _collapse_backslashes(pattern)
    if collapsed == pattern:
        return [pattern]
    return [pattern, collapsed]


_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decode_base64_candidates(text: str) -> List[str]:
    """
    Sigma `base64offset` modifier: attempt to find base64-like substrings in a text
    and decode them using small offsets/padding. Returns decoded text candidates.
    """
    if not text:
        return []

    candidates: List[str] = []
    for match in _BASE64_RE.finditer(text):
        token = match.group(0)
        for offset in range(0, 4):
            chunk = token[offset:]
            if len(chunk) < 8:
                continue

            # Add padding if needed.
            pad_len = (-len(chunk)) % 4
            chunk_padded = chunk + ("=" * pad_len)

            try:
                decoded_bytes = base64.b64decode(chunk_padded, validate=False)
            except Exception:
                continue

            # Common encodings for PowerShell encoded commands are UTF-16LE and UTF-8.
            for encoding in ("utf-16le", "utf-8"):
                try:
                    decoded_text = decoded_bytes.decode(encoding, errors="ignore")
                except Exception:
                    continue
                decoded_text = decoded_text.strip("\x00").strip()
                if decoded_text:
                    candidates.append(decoded_text)

    # De-duplicate while preserving order.
    seen: Set[str] = set()
    unique: List[str] = []
    for item in candidates:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


@dataclass(frozen=True)
class _FieldMatcher:
    field: str
    modifiers: Tuple[str, ...]
    expected: Any
    compiled_regex: Optional[Tuple[re.Pattern, ...]] = None
    compiled_cidrs: Optional[Tuple[ipaddress._BaseNetwork, ...]] = None

    @property
    def operator(self) -> str:
        mods = set(self.modifiers)
        if "fieldref" in mods:
            return "fieldref"
        if "cidr" in mods:
            return "cidr"
        if "re" in mods:
            return "re"
        if "contains" in mods:
            return "contains"
        if "startswith" in mods:
            return "startswith"
        if "endswith" in mods:
            return "endswith"
        return "eq"

    def _as_values(self, value: Any) -> List[Any]:
        if isinstance(value, list):
            return value
        return [value]

    def _expected_variants(self, expected: str, windash: bool) -> List[str]:
        variants = _windash_variants(expected) if windash else [expected]
        expanded: List[str] = []
        for variant in variants:
            expanded.extend(_backslash_variants(variant))

        seen: Set[str] = set()
        unique: List[str] = []
        for item in expanded:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique

    def _match_contains(self, actual: str, expected_values: List[str], require_all: bool, windash: bool) -> bool:
        actual_variants = _backslash_variants(actual)
        if require_all:
            for exp in expected_values:
                exps = self._expected_variants(exp, windash=windash)
                if not any(_contains_ci(actual_variant, variant) for actual_variant in actual_variants for variant in exps):
                    return False
            return True

        for exp in expected_values:
            exps = self._expected_variants(exp, windash=windash)
            if any(_contains_ci(actual_variant, variant) for actual_variant in actual_variants for variant in exps):
                return True
        return False

    def _match_startswith(self, actual: str, expected_values: List[str], windash: bool) -> bool:
        actual_variants = _backslash_variants(actual)
        for exp in expected_values:
            exps = self._expected_variants(exp, windash=windash)
            if any(_startswith_ci(actual_variant, variant) for actual_variant in actual_variants for variant in exps):
                return True
        return False

    def _match_endswith(self, actual: str, expected_values: List[str], windash: bool) -> bool:
        actual_variants = _backslash_variants(actual)
        for exp in expected_values:
            exps = self._expected_variants(exp, windash=windash)
            if any(_endswith_ci(actual_variant, variant) for actual_variant in actual_variants for variant in exps):
                return True
        return False

    def _match_regex(self, actual: str) -> bool:
        if not self.compiled_regex:
            return False
        return any(p.search(actual) is not None for p in self.compiled_regex)

    def _match_cidr(self, actual: str) -> bool:
        if not self.compiled_cidrs:
            return False
        try:
            ip = ipaddress.ip_address(actual.strip())
        except ValueError:
            return False
        return any(ip in net for net in self.compiled_cidrs)

    def matches(self, event: Dict[str, Any]) -> bool:
        actual_value = _get_nested_value(event, self.field)
        if actual_value is None:
            return False

        mods = set(self.modifiers)
        require_all = "all" in mods
        windash = "windash" in mods
        base64offset = "base64offset" in mods

        operator = self.operator

        # fieldref compares two fields
        if operator == "fieldref":
            ref_field = _coerce_str(self.expected).strip()
            if not ref_field:
                return False
            ref_value = _get_nested_value(event, ref_field)
            if ref_value is None:
                return False

            actual_values = self._as_values(actual_value) if isinstance(actual_value, list) else [actual_value]
            for av in actual_values:
                if _eq_ci(av, ref_value):
                    return True
            return False

        # Normalize actual values into strings for text operators; keep original for eq.
        if isinstance(actual_value, list):
            actual_values = actual_value
        else:
            actual_values = [actual_value]

        expected_values = self._as_values(self.expected)

        # Apply base64offset transformation if requested.
        if base64offset:
            decoded_candidates: List[str] = []
            for av in actual_values:
                decoded_candidates.extend(_decode_base64_candidates(_coerce_str(av)))
            actual_values = decoded_candidates
            if not actual_values:
                return False

        if operator == "cidr":
            for av in actual_values:
                if self._match_cidr(_coerce_str(av)):
                    return True
            return False

        if operator == "re":
            for av in actual_values:
                if self._match_regex(_coerce_str(av)):
                    return True
            return False

        if operator == "contains":
            expected_strs = [_coerce_str(v) for v in expected_values if v is not None]
            for av in actual_values:
                if self._match_contains(_coerce_str(av), expected_strs, require_all=require_all, windash=windash):
                    return True
            return False

        if operator == "startswith":
            expected_strs = [_coerce_str(v) for v in expected_values if v is not None]
            for av in actual_values:
                if self._match_startswith(_coerce_str(av), expected_strs, windash=windash):
                    return True
            return False

        if operator == "endswith":
            expected_strs = [_coerce_str(v) for v in expected_values if v is not None]
            for av in actual_values:
                if self._match_endswith(_coerce_str(av), expected_strs, windash=windash):
                    return True
            return False

        # eq
        for av in actual_values:
            if require_all and isinstance(self.expected, list):
                # Rare, but treat as "equals all" (same value repeated) -> always false unless all equal.
                if all(_eq_ci(av, ev) for ev in expected_values):
                    return True
            else:
                for ev in expected_values:
                    if _eq_ci(av, ev):
                        return True
                    if isinstance(av, str) and isinstance(ev, str):
                        for av_variant in _backslash_variants(av):
                            for ev_variant in _backslash_variants(ev):
                                if _eq_ci(av_variant, ev_variant):
                                    return True
        return False


@dataclass(frozen=True)
class _CompiledClause:
    matchers: Tuple[_FieldMatcher, ...]
    keywords: Tuple[str, ...] = ()

    def matches(self, event: Dict[str, Any], event_text: str) -> bool:
        if self.keywords:
            # Keywords act as a full-text OR search.
            lowered = event_text.lower()
            return any(keyword.lower() in lowered for keyword in self.keywords if keyword)

        return all(matcher.matches(event) for matcher in self.matchers)


@dataclass(frozen=True)
class _CompiledSelection:
    """
    OR across clauses; each clause is either an AND of field matchers or a keyword OR clause.
    """
    clauses: Tuple[_CompiledClause, ...]

    def matches(self, event: Dict[str, Any], event_text: str) -> bool:
        return any(clause.matches(event, event_text) for clause in self.clauses)


class _ConditionNode:
    def evaluate(self, get_selection: "callable[[str], bool]") -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class _SelectionRef(_ConditionNode):
    name: str

    def evaluate(self, get_selection: "callable[[str], bool]") -> bool:
        return get_selection(self.name)


@dataclass(frozen=True)
class _Not(_ConditionNode):
    node: _ConditionNode

    def evaluate(self, get_selection: "callable[[str], bool]") -> bool:
        return not self.node.evaluate(get_selection)


@dataclass(frozen=True)
class _And(_ConditionNode):
    left: _ConditionNode
    right: _ConditionNode

    def evaluate(self, get_selection: "callable[[str], bool]") -> bool:
        return self.left.evaluate(get_selection) and self.right.evaluate(get_selection)


@dataclass(frozen=True)
class _Or(_ConditionNode):
    left: _ConditionNode
    right: _ConditionNode

    def evaluate(self, get_selection: "callable[[str], bool]") -> bool:
        return self.left.evaluate(get_selection) or self.right.evaluate(get_selection)


@dataclass(frozen=True)
class _NOf(_ConditionNode):
    required_count: int
    selection_names: Tuple[str, ...]

    def evaluate(self, get_selection: "callable[[str], bool]") -> bool:
        if self.required_count <= 0:
            return True
        if not self.selection_names:
            return False
        matched = 0
        for name in self.selection_names:
            if get_selection(name):
                matched += 1
                if matched >= self.required_count:
                    return True
        return False


@dataclass(frozen=True)
class _AllOf(_ConditionNode):
    selection_names: Tuple[str, ...]

    def evaluate(self, get_selection: "callable[[str], bool]") -> bool:
        # Vacuously true when the group is empty.
        return all(get_selection(name) for name in self.selection_names)


class _ConditionParser:
    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> Optional[str]:
        if self.pos >= len(self.tokens):
            return None
        return self.tokens[self.pos]

    def _consume(self) -> Optional[str]:
        tok = self._peek()
        if tok is None:
            return None
        self.pos += 1
        return tok

    def _expect(self, expected: str) -> None:
        tok = self._consume()
        if tok is None:
            raise ValueError(f"Expected {expected!r}, got end of condition")
        if expected.isalpha():
            if tok.lower() != expected.lower():
                raise ValueError(f"Expected {expected!r}, got {tok!r}")
            return
        if tok != expected:
            raise ValueError(f"Expected {expected!r}, got {tok!r}")

    def parse(self, selection_names: Sequence[str]) -> _ConditionNode:
        node = self._parse_or(selection_names)
        if self._peek() is not None:
            raise ValueError(f"Unexpected trailing tokens: {self.tokens[self.pos:]}")
        return node

    def _parse_or(self, selection_names: Sequence[str]) -> _ConditionNode:
        node = self._parse_and(selection_names)
        while True:
            tok = self._peek()
            if tok and tok.lower() == "or":
                self._consume()
                rhs = self._parse_and(selection_names)
                node = _Or(node, rhs)
                continue
            break
        return node

    def _parse_and(self, selection_names: Sequence[str]) -> _ConditionNode:
        node = self._parse_not(selection_names)
        while True:
            tok = self._peek()
            if tok and tok.lower() == "and":
                self._consume()
                rhs = self._parse_not(selection_names)
                node = _And(node, rhs)
                continue
            break
        return node

    def _parse_not(self, selection_names: Sequence[str]) -> _ConditionNode:
        tok = self._peek()
        if tok and tok.lower() == "not":
            self._consume()
            return _Not(self._parse_not(selection_names))
        return self._parse_atom(selection_names)

    def _parse_atom(self, selection_names: Sequence[str]) -> _ConditionNode:
        tok = self._peek()
        if tok is None:
            raise ValueError("Unexpected end of condition")

        if tok == "(":
            self._consume()
            node = self._parse_or(selection_names)
            self._expect(")")
            return node

        # Quantifiers: "<n> of <pattern>" or "all of <pattern>"
        lower = tok.lower()
        if lower in ("all", "any") or tok.isdigit():
            return self._parse_quantifier(selection_names)

        # Selection reference
        self._consume()
        return _SelectionRef(tok)

    def _parse_quantifier(self, selection_names: Sequence[str]) -> _ConditionNode:
        tok = self._consume()
        if tok is None:
            raise ValueError("Unexpected end of condition")

        if tok.lower() == "all":
            self._expect("of")
            pattern = self._consume()
            if not pattern:
                raise ValueError("Missing pattern after 'all of'")
            matched = tuple(name for name in selection_names if fnmatch.fnmatch(name, pattern))
            return _AllOf(matched)

        if tok.lower() == "any":
            self._expect("of")
            pattern = self._consume()
            if not pattern:
                raise ValueError("Missing pattern after 'any of'")
            matched = tuple(name for name in selection_names if fnmatch.fnmatch(name, pattern))
            return _NOf(1, matched)

        if tok.isdigit():
            count = int(tok)
            self._expect("of")
            pattern = self._consume()
            if not pattern:
                raise ValueError("Missing pattern after '<n> of'")
            matched = tuple(name for name in selection_names if fnmatch.fnmatch(name, pattern))
            return _NOf(count, matched)

        raise ValueError(f"Unsupported quantifier: {tok}")


@dataclass
class _CompiledRule:
    title: str
    rule_id: Optional[str]
    level: str
    status: str
    tags: Tuple[str, ...]
    logsource: Dict[str, Any]
    file_path: str
    selections: Dict[str, _CompiledSelection]
    condition: _ConditionNode
    referenced_fields: Set[str]

    def matches(self, event: Dict[str, Any]) -> bool:
        # Compute a reusable full-text representation (for keyword selections).
        event_text = _coerce_str(event.get("message")) or _coerce_str(event.get("Message"))
        if not event_text:
            # Fall back to a limited stringify of the event.
            # Avoid full json.dumps for performance; include only string-ish fields.
            parts: List[str] = []
            for key, value in event.items():
                if isinstance(value, str):
                    parts.append(value)
            event_text = "\n".join(parts)

        cache: Dict[str, bool] = {}

        def get_selection(name: str) -> bool:
            if name in cache:
                return cache[name]
            selection = self.selections.get(name)
            if not selection:
                cache[name] = False
                return False
            result = selection.matches(event, event_text)
            cache[name] = result
            return result

        return self.condition.evaluate(get_selection)


class SigmaEngine:
    """
    Loads Sigma YAML rules and evaluates logs in-memory.

    This is a pragmatic "runtime evaluator" (not query backend translation).
    It supports the classic Sigma rule format used in the SigmaHQ repository.
    """

    def __init__(self, config: Dict[str, Any]):
        self.rules_path = config.get("rules_path", "")
        self.rules_paths: List[str] = list(config.get("rules_paths") or [])
        if self.rules_path and self.rules_path not in self.rules_paths:
            self.rules_paths.append(self.rules_path)

        self.severity_filter = _normalize_severity_filter(config.get("severity_filter"))
        self.enabled_products = {p.strip().lower() for p in (config.get("enabled_products") or []) if str(p).strip()}
        self.enabled_categories = {c.strip().lower() for c in (config.get("enabled_categories") or []) if str(c).strip()}
        self.include_deprecated = bool(config.get("include_deprecated", False))

        self.rules: List[_CompiledRule] = []
        self.rules_by_product: Dict[str, List[_CompiledRule]] = {}
        self.rules_by_product_eventid: Dict[str, Dict[Optional[int], List[_CompiledRule]]] = {}
        self.load_errors: List[str] = []
        self.rule_files_scanned: int = 0
        self.rule_files_skipped: int = 0

        self._load_rules()

    def _should_emit(self, level: str) -> bool:
        if not self.severity_filter:
            return True
        return _normalize_level(level) in self.severity_filter

    def _iter_rule_files(self, root: str) -> Iterable[str]:
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if not filename.endswith((".yml", ".yaml")):
                    continue
                yield os.path.join(dirpath, filename)

    def _compile_matcher(self, raw_key: str, raw_value: Any, file_path: str) -> _FieldMatcher:
        parts = [p for p in raw_key.split("|") if p]
        field = parts[0].strip()
        modifiers = tuple(p.strip().lower() for p in parts[1:] if p.strip())

        compiled_regex: Optional[Tuple[re.Pattern, ...]] = None
        compiled_cidrs: Optional[Tuple[ipaddress._BaseNetwork, ...]] = None

        if "re" in modifiers:
            patterns = raw_value if isinstance(raw_value, list) else [raw_value]
            flags = re.IGNORECASE if "i" in modifiers else 0
            compiled: List[re.Pattern] = []
            for pat in patterns:
                try:
                    compiled.append(re.compile(_coerce_str(pat), flags=flags))
                except re.error as e:
                    raise ValueError(f"Invalid regex {_coerce_str(pat)!r} in {file_path}: {e}") from e
            compiled_regex = tuple(compiled)

        if "cidr" in modifiers:
            cidrs = raw_value if isinstance(raw_value, list) else [raw_value]
            networks: List[ipaddress._BaseNetwork] = []
            for cidr in cidrs:
                try:
                    networks.append(ipaddress.ip_network(_coerce_str(cidr).strip(), strict=False))
                except ValueError as e:
                    raise ValueError(f"Invalid CIDR {_coerce_str(cidr)!r} in {file_path}: {e}") from e
            compiled_cidrs = tuple(networks)

        return _FieldMatcher(
            field=field,
            modifiers=modifiers,
            expected=raw_value,
            compiled_regex=compiled_regex,
            compiled_cidrs=compiled_cidrs,
        )

    def _compile_selection(self, selection_def: Any, file_path: str, referenced_fields: Set[str]) -> _CompiledSelection:
        clauses: List[_CompiledClause] = []

        # Dict -> single AND clause
        if isinstance(selection_def, dict):
            matchers = []
            for raw_key, raw_value in selection_def.items():
                matcher = self._compile_matcher(str(raw_key), raw_value, file_path=file_path)
                referenced_fields.add(matcher.field)
                if "fieldref" in matcher.modifiers:
                    referenced_fields.add(_coerce_str(matcher.expected).strip())
                matchers.append(matcher)
            clauses.append(_CompiledClause(matchers=tuple(matchers)))
            return _CompiledSelection(clauses=tuple(clauses))

        # List -> OR across items
        if isinstance(selection_def, list):
            keywords: List[str] = []
            for item in selection_def:
                if isinstance(item, dict):
                    matchers = []
                    for raw_key, raw_value in item.items():
                        matcher = self._compile_matcher(str(raw_key), raw_value, file_path=file_path)
                        referenced_fields.add(matcher.field)
                        if "fieldref" in matcher.modifiers:
                            referenced_fields.add(_coerce_str(matcher.expected).strip())
                        matchers.append(matcher)
                    clauses.append(_CompiledClause(matchers=tuple(matchers)))
                else:
                    keywords.append(_coerce_str(item))

            if keywords:
                clauses.append(_CompiledClause(matchers=tuple(), keywords=tuple(keywords)))

            if not clauses:
                clauses.append(_CompiledClause(matchers=tuple(), keywords=tuple()))

            return _CompiledSelection(clauses=tuple(clauses))

        # Scalar -> keyword clause
        keyword = _coerce_str(selection_def)
        clauses.append(_CompiledClause(matchers=tuple(), keywords=(keyword,) if keyword else ()))
        return _CompiledSelection(clauses=tuple(clauses))

    def _compile_condition(self, condition: str, selection_names: Sequence[str], file_path: str) -> _ConditionNode:
        tokens = re.findall(r"\(|\)|\d+|[A-Za-z0-9_.*-]+", condition)
        parser = _ConditionParser(tokens)
        try:
            return parser.parse(selection_names=selection_names)
        except Exception as e:
            raise ValueError(f"Invalid condition {condition!r} in {file_path}: {e}") from e

    def _compile_rule(self, doc: Dict[str, Any], file_path: str) -> Optional[_CompiledRule]:
        if not isinstance(doc, dict):
            return None

        detection = doc.get("detection") or {}
        if not isinstance(detection, dict):
            return None

        condition_str = detection.get("condition")
        if not condition_str or not isinstance(condition_str, str):
            return None

        title = _coerce_str(doc.get("title")).strip() or os.path.basename(file_path)
        status = _normalize_level(doc.get("status"))
        if status == "deprecated" and not self.include_deprecated:
            return None

        level = _normalize_level(doc.get("level"))
        rule_id = _coerce_str(doc.get("id")).strip() or None
        tags = tuple(_coerce_str(t).strip() for t in (doc.get("tags") or []) if _coerce_str(t).strip())
        logsource = doc.get("logsource") or {}

        if not isinstance(logsource, dict):
            logsource = {}

        product = _normalize_level(logsource.get("product"))
        category = _normalize_level(logsource.get("category"))

        if self.enabled_products and product not in self.enabled_products:
            return None

        if self.enabled_categories and category not in self.enabled_categories:
            return None

        referenced_fields: Set[str] = set()
        selections: Dict[str, _CompiledSelection] = {}

        for name, selection_def in detection.items():
            if name == "condition":
                continue
            selections[name] = self._compile_selection(selection_def, file_path=file_path, referenced_fields=referenced_fields)

        selection_names = list(selections.keys())
        condition_ast = self._compile_condition(condition_str, selection_names=selection_names, file_path=file_path)

        return _CompiledRule(
            title=title,
            rule_id=rule_id,
            level=level,
            status=status,
            tags=tags,
            logsource=logsource,
            file_path=file_path,
            selections=selections,
            condition=condition_ast,
            referenced_fields=referenced_fields,
        )

    def _load_rules(self) -> None:
        rules: List[_CompiledRule] = []
        scanned = 0
        skipped = 0

        for root in self.rules_paths:
            if not root:
                continue
            if not os.path.exists(root):
                logger.warning(f"Sigma rules path does not exist: {root}")
                continue

            for file_path in self._iter_rule_files(root):
                scanned += 1
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        doc = yaml.safe_load(f)
                    compiled = self._compile_rule(doc or {}, file_path=file_path)
                    if compiled:
                        rules.append(compiled)
                    else:
                        skipped += 1
                except Exception as e:
                    self.load_errors.append(f"{file_path}: {e}")

        self.rules = rules
        self.rule_files_scanned = scanned
        self.rule_files_skipped = skipped

        grouped: Dict[str, List[_CompiledRule]] = {}
        for rule in rules:
            product = _normalize_level(rule.logsource.get("product"))
            grouped.setdefault(product, []).append(rule)

        self.rules_by_product = grouped

        self.rules_by_product_eventid = self._build_eventid_index(grouped)

        total = len(self.rules)
        errs = len(self.load_errors)
        logger.info(
            f"Sigma rules loaded: {total} (scanned: {scanned}, skipped: {skipped}, errors: {errs})"
        )
        if errs:
            logger.warning(f"Some Sigma rules failed to load (showing first 5): {self.load_errors[:5]}")

    def _selection_event_ids(self, selection: _CompiledSelection) -> Optional[Set[int]]:
        """
        Attempt to extract a safe EventID constraint for a selection.

        Returns:
          - set[int]: selection can match ONLY these EventIDs
          - None: selection can match any EventID (no safe constraint)
        """
        clause_sets: List[Set[int]] = []

        for clause in selection.clauses:
            if not clause.matchers:
                # Keyword selections don't constrain EventID safely.
                return None

            clause_ids: Optional[Set[int]] = None
            for matcher in clause.matchers:
                if matcher.field.lower() != "eventid":
                    continue
                if matcher.operator != "eq":
                    return None

                raw = matcher.expected if isinstance(matcher.expected, list) else [matcher.expected]
                ids: Set[int] = set()
                for value in raw:
                    try:
                        ids.add(int(str(value).strip()))
                    except Exception:
                        continue
                if not ids:
                    return None

                clause_ids = ids if clause_ids is None else (clause_ids & ids)

            if clause_ids is None:
                # At least one OR-clause has no EventID constraint => selection unconstrained.
                return None
            clause_sets.append(clause_ids)

        if not clause_sets:
            return None

        merged: Set[int] = set()
        for clause_ids in clause_sets:
            merged |= clause_ids
        return merged or None

    def _condition_event_ids(self, node: _ConditionNode, selection_event_ids: Dict[str, Optional[Set[int]]]) -> Optional[Set[int]]:
        if isinstance(node, _SelectionRef):
            return selection_event_ids.get(node.name)

        if isinstance(node, _Not):
            # Negation does not provide a safe constraint.
            return None

        if isinstance(node, _And):
            left = self._condition_event_ids(node.left, selection_event_ids)
            right = self._condition_event_ids(node.right, selection_event_ids)
            if left is None and right is None:
                return None
            if left is None:
                return right
            if right is None:
                return left
            return left & right

        if isinstance(node, _Or):
            left = self._condition_event_ids(node.left, selection_event_ids)
            right = self._condition_event_ids(node.right, selection_event_ids)
            if left is None or right is None:
                return None
            return left | right

        if isinstance(node, _AllOf):
            current: Optional[Set[int]] = None
            for name in node.selection_names:
                value = selection_event_ids.get(name)
                if value is None:
                    continue
                current = value if current is None else (current & value)
            return current

        if isinstance(node, _NOf):
            if node.required_count <= 0:
                return None
            if node.required_count != 1:
                # Not safe to derive constraints for N-of when N>1.
                return None

            merged: Set[int] = set()
            for name in node.selection_names:
                value = selection_event_ids.get(name)
                if value is None:
                    return None
                merged |= value
            return merged or None

        return None

    def _build_eventid_index(self, rules_by_product: Dict[str, List[_CompiledRule]]) -> Dict[str, Dict[Optional[int], List[_CompiledRule]]]:
        index: Dict[str, Dict[Optional[int], List[_CompiledRule]]] = {}

        for product, rules in rules_by_product.items():
            product_index: Dict[Optional[int], List[_CompiledRule]] = {}
            for rule in rules:
                selection_ids: Dict[str, Optional[Set[int]]] = {}
                for name, selection in rule.selections.items():
                    selection_ids[name] = self._selection_event_ids(selection)

                rule_event_ids = self._condition_event_ids(rule.condition, selection_ids)
                if rule_event_ids:
                    for event_id in rule_event_ids:
                        product_index.setdefault(event_id, []).append(rule)
                else:
                    product_index.setdefault(None, []).append(rule)

            index[product] = product_index

        return index

    def _extract_product(self, event: Dict[str, Any]) -> str:
        # Prefer explicit marker from mapper.
        source_type = _coerce_str(event.get("_source_type")).strip().lower()
        if source_type:
            return source_type
        os_type = _coerce_str(event.get("OSType") or event.get("os.type") or event.get("os_type")).strip().lower()
        return os_type or "unknown"

    def _build_alert_log_data(self, rule: _CompiledRule, event: Dict[str, Any]) -> Dict[str, Any]:
        # Include rule-referenced fields + common context fields.
        common_fields = {
            "EventID",
            "Computer",
            "hostname",
            "message",
            "source",
            "Channel",
            "IpAddress",
            "TargetUserName",
            "SubjectUserName",
            "AuthenticationPackageName",
            "_source_type",
            "_timestamp",
        }

        fields = set(rule.referenced_fields) | common_fields
        data: Dict[str, Any] = {}
        for field in fields:
            if not field:
                continue
            value = _get_nested_value(event, field)
            if value is None:
                continue
            data[field] = value
        return data

    def _alert(self, rule: _CompiledRule, event: Dict[str, Any]) -> Dict[str, Any]:
        extra = {
            "rule_id": rule.rule_id,
            "rule_status": rule.status,
            "rule_tags": list(rule.tags),
            "rule_logsource": rule.logsource,
            "rule_file": rule.file_path,
        }
        return {
            "rule_title": rule.title,
            "rule_level": rule.level,
            "log_data": self._build_alert_log_data(rule, event),
            **extra,
        }

    def evaluate(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        if not self.rules:
            return alerts

        for event in logs:
            product = self._extract_product(event)
            event_id: Optional[int] = None
            raw_event_id = event.get("EventID")
            if raw_event_id is not None:
                try:
                    event_id = int(str(raw_event_id).strip())
                except Exception:
                    event_id = None

            candidates: List[_CompiledRule] = []
            product_index = self.rules_by_product_eventid.get(product, {})
            if product_index:
                candidates.extend(product_index.get(event_id, []))
                candidates.extend(product_index.get(None, []))

            if product != "unknown":
                unknown_index = self.rules_by_product_eventid.get("unknown", {})
                candidates.extend(unknown_index.get(event_id, []))
                candidates.extend(unknown_index.get(None, []))

            if not candidates:
                continue

            for rule in candidates:
                if not self._should_emit(rule.level):
                    continue
                try:
                    if rule.matches(event):
                        alerts.append(self._alert(rule, event))
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule.title!r} ({rule.file_path}): {e}", exc_info=True)

        return alerts
