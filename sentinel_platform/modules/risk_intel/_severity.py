"""Deterministic severity recovery; missing evidence is never an information rating."""
from __future__ import annotations
import math
from . import _cvss

ALIASES = {key: value for value, keys in {
    'critical': ('critical', '严重', '超危', '严重风险', '危急'),
    'high': ('high', '高危', '高', '高风险'),
    'medium': ('medium', 'moderate', '中危', '中', '中风险'),
    'low': ('low', '低危', '低', '低风险'),
    'info': ('info', 'informational', 'information', '信息', '信息级', '提示', 'none'),
}.items() for key in keys}


def normalize(value):
    return ALIASES.get(str(value or '').strip().lower(), 'unknown')


def score_rating(value):
    if isinstance(value, bool) or value is None or value == '':
        return 'unknown'
    try:
        score = float(value)
    except (ValueError, TypeError, OverflowError):
        return 'unknown'
    if not math.isfinite(score) or not 0 <= score <= 10:
        return 'unknown'
    return normalize(_cvss.severity_of(score))


def resolve(doc, fields=('manual_severity', 'severity', 'vuln_severity')):
    for field in fields:
        rating = normalize(doc.get(field))
        if rating != 'unknown':
            return rating
    vector = doc.get('cvss_vector') or doc.get('vector')
    score, rating = _cvss.score_from_vector(vector)
    if score is not None:
        return normalize(rating)
    for field in ('cvss_score', 'cvss', 'baseScore'):
        rating = score_rating(doc.get(field))
        if rating != 'unknown':
            return rating
    return 'unknown'


def grade_input(doc):
    vector = doc.get('cvss_vector')
    if _cvss.is_valid_vector(vector):
        return vector
    return resolve(doc)
