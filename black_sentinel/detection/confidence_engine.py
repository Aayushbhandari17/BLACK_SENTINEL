import os
import re
from typing import Iterable, Tuple


ALERT_THRESHOLD = 60

REGEX_MATCH_SCORE = 30
ENTROPY_THRESHOLD_SCORE = 25
FORMAT_VALIDATOR_SCORE = 25
CONTEXT_KEYWORD_SCORE = 20
SECRET_ASSIGNMENT_SCORE = 15

ASSIGNMENT_PATTERN = re.compile(
    r'(?i)(?:\b(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd|credential)\b|\w+)\s*[:=]\s*\S+'
)

POSITIVE_FILE_REPUTATION = (
    (re.compile(r'(^|[\\/])\.aws[\\/]credentials$', re.IGNORECASE), 40),
    (re.compile(r'(^|[\\/])\.kube[\\/]config$', re.IGNORECASE), 40),
    (re.compile(r'(^|[\\/])credentials(?:\.[^\\/]*)?$', re.IGNORECASE), 30),
    (re.compile(r'(^|[\\/])secrets\.ya?ml$', re.IGNORECASE), 30),
    (re.compile(r'(^|[\\/])\.env(?:\.[^\\/]*)?$', re.IGNORECASE), 25),
    (re.compile(r'(^|[\\/])(?:config|.*\.config|.*config\.(?:json|ya?ml|txt))$', re.IGNORECASE), 20),
)

NEGATIVE_FILE_REPUTATION = (
    (re.compile(r'(^|[\\/])node_modules([\\/]|$)', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/])(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/])(?:\.next|dist|build|out|coverage|\.cache|vendor)([\\/]|$)', re.IGNORECASE), -50),
)

NEGATIVE_APPLICATION_DATA = (
    (re.compile(r'(^|[\\/])(?:google[\\/]chrome|chrome|chromium)([\\/]|$)', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/])(?:microsoft[\\/]edge|edge)([\\/]|$)', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/])firefox([\\/]|$)', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/])leveldb([\\/]|$)', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/])extension storage([\\/]|$)', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/]).*telemetry.*$', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/])library[\\/]application support([\\/]|$)', re.IGNORECASE), -60),
    (re.compile(r'(^|[\\/])appdata[\\/](?:local|roaming)[\\/](?:google|microsoft|code)([\\/]|$)', re.IGNORECASE), -60),
)


def normalize_path(path: str) -> str:
    return os.path.normcase(path or "").replace("\\", "/")


def has_assignment_pattern(context: str) -> bool:
    return bool(ASSIGNMENT_PATTERN.search(context or ""))


def _score_first_match(path: str, rules: Iterable[Tuple[re.Pattern, int]]) -> int:
    for pattern, score in rules:
        if pattern.search(path):
            return score
    return 0


def file_reputation_score(file_path: str) -> int:
    path = normalize_path(file_path)
    score = _score_first_match(path, POSITIVE_FILE_REPUTATION)
    score += _score_first_match(path, NEGATIVE_FILE_REPUTATION)
    score += _score_first_match(path, NEGATIVE_APPLICATION_DATA)
    return score


def score(
    *,
    file_path: str = "",
    regex_match: bool = False,
    entropy_threshold_exceeded: bool = False,
    format_validator_passed: bool = False,
    context_keyword_match: bool = False,
    assignment_pattern_match: bool = False,
    strong_validator_passed: bool = False,
) -> int:
    final_score = file_reputation_score(file_path)

    if regex_match:
        final_score += REGEX_MATCH_SCORE
    if entropy_threshold_exceeded:
        final_score += ENTROPY_THRESHOLD_SCORE
    if format_validator_passed:
        final_score += FORMAT_VALIDATOR_SCORE
    if context_keyword_match:
        final_score += CONTEXT_KEYWORD_SCORE
    if assignment_pattern_match:
        final_score += SECRET_ASSIGNMENT_SCORE

    if strong_validator_passed:
        final_score = max(final_score, 90)

    return final_score


def should_publish(final_score: int) -> bool:
    return final_score >= ALERT_THRESHOLD


def confidence_from_score(final_score: int) -> float:
    return min(1.0, max(0.0, final_score / 100.0))
