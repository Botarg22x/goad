"""Compiler and streaming evaluator for passgen patterns."""

from __future__ import annotations

from dataclasses import dataclass
import itertools
import math
from typing import Iterator, Mapping, Sequence

from .config import ConfigError, WORDLIST_NAME_RE, WordlistSpec
from .limits import MAX_CANDIDATE_LENGTH


@dataclass(frozen=True)
class LiteralToken:
    value: str


@dataclass(frozen=True)
class CharsetToken:
    name: str
    characters: str


@dataclass(frozen=True)
class WordlistToken:
    name: str


PatternToken = LiteralToken | CharsetToken | WordlistToken


@dataclass(frozen=True)
class CompiledPattern:
    source: str
    tokens: tuple[PatternToken, ...]
    wordlist_names: tuple[str, ...]
    binding_groups: tuple[tuple[str, ...], ...]
    charset_tokens: tuple[CharsetToken, ...]

    def cardinality(
        self,
        wordlist_counts: Mapping[str, int],
        paired_counts: Mapping[tuple[str, str], int] | None = None,
    ) -> int:
        source_factor = 1
        for group in self.binding_groups:
            if len(group) == 1:
                source_factor *= wordlist_counts[group[0]]
            else:
                if paired_counts is None:
                    raise ConfigError("Попарной маске нужен расчёт числа допустимых пар")
                source_factor *= paired_counts[(group[0], group[1])]
        charset_factor = math.prod(len(token.characters) for token in self.charset_tokens)
        return source_factor * charset_factor

    def maximum_candidate_length(
        self,
        wordlist_max_lengths: Mapping[str, int],
    ) -> int:
        """Return the exact maximum base-candidate length for analyzed wordlists."""

        maximum = 0
        for token in self.tokens:
            if isinstance(token, LiteralToken):
                maximum += len(token.value)
            elif isinstance(token, WordlistToken):
                maximum += wordlist_max_lengths[token.name]
            else:
                maximum += 1
        return maximum

    def generate(self, wordlists: Mapping[str, WordlistSpec]) -> Iterator[str]:
        bindings: dict[str, str] = {}
        yield from self._generate_bindings(wordlists, bindings, 0)

    def _generate_bindings(
        self,
        wordlists: Mapping[str, WordlistSpec],
        bindings: dict[str, str],
        index: int,
    ) -> Iterator[str]:
        if index >= len(self.binding_groups):
            yield from self._render_bindings(bindings)
            return
        group = self.binding_groups[index]
        if len(group) == 1:
            name = group[0]
            for value in wordlists[name].iter_words():
                bindings[name] = value
                yield from self._generate_bindings(wordlists, bindings, index + 1)
            bindings.pop(name, None)
            return
        left, right = group
        missing = object()
        pairs = itertools.zip_longest(
            wordlists[left].iter_rows(),
            wordlists[right].iter_rows(),
            fillvalue=missing,
        )
        for left_value, right_value in pairs:
            if left_value is missing or right_value is missing:
                raise ConfigError(
                    f"Число физических строк словарей {left!r} и {right!r} изменилось "
                    "после построения плана"
                )
            if left_value is None or right_value is None:
                continue
            bindings[left] = left_value
            bindings[right] = right_value
            yield from self._generate_bindings(wordlists, bindings, index + 1)
        bindings.pop(left, None)
        bindings.pop(right, None)

    def _render_bindings(self, bindings: Mapping[str, str]) -> Iterator[str]:
        projected_length = 0
        for token in self.tokens:
            if isinstance(token, LiteralToken):
                projected_length += len(token.value)
            elif isinstance(token, WordlistToken):
                projected_length += len(bindings[token.name])
            else:
                projected_length += 1
            if projected_length > MAX_CANDIDATE_LENGTH:
                raise ConfigError(
                    f"Pattern {self.source!r} would render a candidate longer than "
                    f"the hard safety limit ({MAX_CANDIDATE_LENGTH:,} characters)"
                )
        pools = [token.characters for token in self.charset_tokens]
        combinations = itertools.product(*pools) if pools else [()]
        for combination in combinations:
            charset_index = 0
            parts: list[str] = []
            for token in self.tokens:
                if isinstance(token, LiteralToken):
                    parts.append(token.value)
                elif isinstance(token, WordlistToken):
                    parts.append(bindings[token.name])
                else:
                    parts.append(combination[charset_index])
                    charset_index += 1
            yield "".join(parts)


def compile_pattern(
    value: str,
    *,
    wordlists: Mapping[str, WordlistSpec],
    charsets: Mapping[str, str],
    zip_wordlists: Sequence[tuple[str, str]] = (),
) -> CompiledPattern:
    tokens: list[PatternToken] = []
    literal: list[str] = []
    wordlist_names: list[str] = []
    charset_tokens: list[CharsetToken] = []

    def flush_literal() -> None:
        if literal:
            tokens.append(LiteralToken("".join(literal)))
            literal.clear()

    index = 0
    while index < len(value):
        char = value[index]
        if char == "?":
            if index + 1 >= len(value):
                raise ConfigError(f"Pattern ends with an incomplete charset token: {value!r}")
            next_char = value[index + 1]
            if next_char == "?":
                literal.append("?")
                index += 2
                continue
            flush_literal()
            if next_char == "{":
                end = value.find("}", index + 2)
                if end < 0:
                    raise ConfigError(f"Unclosed named charset in pattern: {value!r}")
                name = value[index + 2 : end]
                if not name:
                    raise ConfigError(f"Empty named charset in pattern: {value!r}")
                index = end + 1
            else:
                name = next_char
                index += 2
            if name not in charsets:
                raise ConfigError(f"Unknown charset ?{name} in pattern: {value!r}")
            token = CharsetToken(name=name, characters=charsets[name])
            tokens.append(token)
            charset_tokens.append(token)
            continue

        if char == "{":
            if index + 1 < len(value) and value[index + 1] == "{":
                literal.append("{")
                index += 2
                continue
            flush_literal()
            end = value.find("}", index + 1)
            if end < 0:
                raise ConfigError(f"Unclosed wordlist reference in pattern: {value!r}")
            name = value[index + 1 : end]
            if not WORDLIST_NAME_RE.fullmatch(name):
                raise ConfigError(f"Invalid wordlist reference {{{name}}} in pattern: {value!r}")
            if name not in wordlists:
                raise ConfigError(f"Unknown wordlist {{{name}}} in pattern: {value!r}")
            tokens.append(WordlistToken(name))
            if name not in wordlist_names:
                wordlist_names.append(name)
            index = end + 1
            continue

        if char == "}":
            if index + 1 < len(value) and value[index + 1] == "}":
                literal.append("}")
                index += 2
                continue
            raise ConfigError(f"Unescaped closing brace in pattern: {value!r}")

        literal.append(char)
        index += 1

    flush_literal()
    if not tokens:
        raise ConfigError("Pattern cannot be empty")
    zip_lookup = {
        name: pair
        for pair in zip_wordlists
        for name in pair
    }
    binding_groups: list[tuple[str, ...]] = []
    for name in wordlist_names:
        group = zip_lookup.get(name, (name,))
        if group in binding_groups:
            continue
        if len(group) == 2 and not all(member in wordlist_names for member in group):
            raise ConfigError(
                f"Маска {value!r} должна содержать оба попарных словаря: "
                f"{group[0]!r} и {group[1]!r}"
            )
        binding_groups.append(group)
    return CompiledPattern(
        source=value,
        tokens=tuple(tokens),
        wordlist_names=tuple(wordlist_names),
        binding_groups=tuple(binding_groups),
        charset_tokens=tuple(charset_tokens),
    )
