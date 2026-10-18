"""Model loading and prediction boundary for the Flask app."""

from __future__ import annotations

import math
import ipaddress
import re
import threading
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin


_URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
_URGENCY_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"\burgent(?:ly)?\b",
    r"\bimmediately\b",
    r"\baction\s+required\b",
    r"\bfinal\s+(?:notice|attempt|warning|reminder)\b",
    r"\bwithin\s+\d+\s+(?:minutes?|hours?|days?)\b",
    r"\b(?:today|tonight|right now|expires?|expired|deadline)\b",
    r"\b(?:suspend|suspended|lock|locked|deactivat\w+)\b",
    r"\bavoid\s+(?:losing|suspension|disruption)\b",
    r"\blast\s+chance\b",
))
_CREDENTIAL_TERMS = re.compile(
    r"\b(?:passwords?|passcodes?|credentials?|one[- ]time codes?|verification codes?|"
    r"security codes?|otps?|pins?|recovery phrases?|authenticator codes?)\b",
    re.IGNORECASE,
)
_REQUEST_VERBS = r"(?:enter|provide|submit|send|reply with|share|confirm|verify|type|update|return|text|requests?|asks?\s+for)"
_REQUEST_NEGATION = re.compile(
    r"\b(?:never|not|don't|do not|doesn't|does not|didn't|did not|won't|will not|"
    r"wouldn't|would not|cannot|can't|no one|nobody)\b(?:[\W_]+\w+){0,4}[\W_]*$",
    re.IGNORECASE,
)
_SECRET_REQUEST_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    rf"\b{_REQUEST_VERBS}\b[^.!?\n]{{0,70}}\b(?:passwords?|passcodes?|credentials?|one[- ]time codes?|verification codes?|security codes?|otps?|pins?|recovery phrases?|authenticator codes?)\b",
    rf"\b(?:passwords?|passcodes?|credentials?|one[- ]time codes?|verification codes?|security codes?|otps?|pins?|recovery phrases?|authenticator codes?)\b[^.!?\n]{{0,70}}\b{_REQUEST_VERBS}\b",
))
_FINANCIAL_TERMS = re.compile(
    r"\b(?:bank details?|bank accounts?|routing numbers?|card numbers?|payment details?|"
    r"financial information|card security codes?)\b",
    re.IGNORECASE,
)
_FINANCIAL_REQUEST_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    rf"\b{_REQUEST_VERBS}\b[^.!?\n]{{0,70}}\b(?:bank details?|bank accounts?|routing numbers?|card numbers?|payment details?|financial information|card security codes?)\b",
    rf"\b(?:bank details?|bank accounts?|routing numbers?|card numbers?|payment details?|financial information|card security codes?)\b[^.!?\n]{{0,70}}\b{_REQUEST_VERBS}\b",
))
_URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "cutt.ly", "buff.ly",
    "rebrand.ly", "shorturl.at", "rb.gy", "lnkd.in",
})


class EmailSecurityFeatures(BaseEstimator, TransformerMixin):
    """Extract small, explainable email and URL signals from raw email text."""

    feature_names = (
        "url_count",
        "unique_url_domains",
        "shortener_url_count",
        "ip_address_url_count",
        "punycode_url_count",
        "userinfo_url_count",
        "deep_subdomain_url_count",
        "long_domain_url_count",
        "suspicious_domain_pattern_count",
        "urgency_phrase_count",
        "credential_term_count",
        "password_or_code_request",
        "financial_detail_request",
    )

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = [self._features(str(text)) for text in X]
        return csr_matrix(np.asarray(rows, dtype=np.float64))

    def get_feature_names_out(self, input_features=None):
        return np.asarray(self.feature_names, dtype=object)

    @staticmethod
    def _has_non_negated_request(text: str, patterns: tuple[re.Pattern, ...]) -> bool:
        for pattern in patterns:
            for match in pattern.finditer(text):
                request_verb = re.search(rf"\b{_REQUEST_VERBS}\b", match.group(0), re.IGNORECASE)
                if request_verb is None:
                    continue
                verb_start = match.start() + request_verb.start()
                prefix = text[max(0, verb_start - 100):verb_start]
                request_clause = re.split(r"[.!?;\n]", prefix)[-1]
                if not _REQUEST_NEGATION.search(request_clause):
                    return True
        return False

    @staticmethod
    def _features(text: str) -> list[float]:
        urls = [match.group(0).rstrip(".,;:!?)]}") for match in _URL_PATTERN.finditer(text)]
        domains = set()
        shorteners = ip_urls = punycode = userinfo = deep_subdomains = long_domains = 0

        for raw_url in urls:
            candidate = raw_url if "://" in raw_url else f"http://{raw_url}"
            try:
                parsed = urlsplit(candidate)
                host = (parsed.hostname or "").lower().rstrip(".")
                if not host:
                    continue
                domains.add(host)
                if "@" in parsed.netloc:
                    userinfo += 1
                is_ip_address = False
                try:
                    ipaddress.ip_address(host.strip("[]"))
                    ip_urls += 1
                    is_ip_address = True
                except ValueError:
                    pass
                if any(label.startswith("xn--") for label in host.split(".")):
                    punycode += 1
                if not is_ip_address and host.count(".") >= 3:
                    deep_subdomains += 1
                if len(host) > 45:
                    long_domains += 1
                if any(host == shortener or host.endswith(f".{shortener}") for shortener in _URL_SHORTENERS):
                    shorteners += 1
            except ValueError:
                continue

        suspicious_domains = sum((
            shorteners,
            ip_urls,
            punycode,
            userinfo,
            deep_subdomains,
            long_domains,
        ))
        urgency_count = sum(len(pattern.findall(text)) for pattern in _URGENCY_PATTERNS)
        credential_terms = len(_CREDENTIAL_TERMS.findall(text))
        password_or_code_request = int(
            EmailSecurityFeatures._has_non_negated_request(text, _SECRET_REQUEST_PATTERNS)
        )
        financial_detail_request = int(
            EmailSecurityFeatures._has_non_negated_request(text, _FINANCIAL_REQUEST_PATTERNS)
        )

        return [
            min(len(urls), 10),
            min(len(domains), 10),
            min(shorteners, 5),
            min(ip_urls, 5),
            min(punycode, 5),
            min(userinfo, 5),
            min(deep_subdomains, 5),
            min(long_domains, 5),
            min(suspicious_domains, 10),
            min(urgency_count, 10),
            min(credential_terms, 10),
            password_or_code_request,
            financial_detail_request,
        ]


class ModelNotAvailable(Exception):
    """Raised when the configured model artifact is not present."""


class ModelLoadError(Exception):
    """Raised when an artifact cannot be loaded or is not a supported pipeline."""


class PredictionError(Exception):
    """Raised when a loaded pipeline cannot return a valid binary prediction."""


def _load_joblib(path: Path):
    try:
        import joblib
    except ImportError as exc:
        raise ModelLoadError("Install the requirements before loading a model") from exc
    return joblib.load(path)


class PhishingModel:
    """Lazily load a raw-text scikit-learn pipeline and classify email content."""

    def __init__(self, model_path: str | Path, loader: Callable | None = None):
        self.model_path = Path(model_path)
        self.loader = loader or _load_joblib
        self._pipeline = None
        self._signature = None
        self._load_error_signature = None
        self._lock = threading.Lock()

    def _get_pipeline(self):
        try:
            stat = self.model_path.stat()
        except FileNotFoundError as exc:
            raise ModelNotAvailable from exc
        signature = (stat.st_mtime_ns, stat.st_size)

        with self._lock:
            if self._signature == signature and self._pipeline is not None:
                return self._pipeline
            if self._load_error_signature == signature:
                raise ModelLoadError("The model artifact is not a supported pipeline")

            try:
                pipeline = self.loader(self.model_path)
                if not callable(getattr(pipeline, "predict", None)):
                    raise TypeError("Pipeline has no predict method")
                if not callable(getattr(pipeline, "predict_proba", None)):
                    raise TypeError("Pipeline has no predict_proba method")
                self._pipeline = pipeline
                self._signature = signature
                self._load_error_signature = None
                return pipeline
            except Exception as exc:
                self._pipeline = None
                self._signature = None
                self._load_error_signature = signature
                raise ModelLoadError("The model artifact could not be loaded") from exc

    @staticmethod
    def _binary_label(value):
        if isinstance(value, bool):
            raise ValueError("Boolean labels are not supported")
        try:
            label = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("Expected binary labels 0 and 1") from exc
        if label not in (0, 1) or value != label:
            raise ValueError("Expected binary labels 0 and 1")
        return label

    @staticmethod
    def _top_contributing_terms(pipeline, email_text: str, predicted: int, limit: int = 3) -> list[str]:
        """Return active word n-grams that support the predicted class."""
        try:
            steps = pipeline.named_steps
            word_vectorizer = dict(steps["features"].transformer_list).get("word_tfidf")
            classifier = steps["classifier"]
            if word_vectorizer is None or not hasattr(classifier, "coef_"):
                return []

            classes = [PhishingModel._binary_label(value) for value in classifier.classes_]
            if len(classes) != 2 or classes.count(1) != 1 or classifier.coef_.shape[0] != 1:
                return []

            # Binary LogisticRegression coefficients point toward classes_[1].
            phishing_direction = 1 if classes[1] == 1 else -1
            direction = phishing_direction if predicted == 1 else -phishing_direction
            row = word_vectorizer.transform([email_text]).tocsr()
            coefficients = classifier.coef_[0]
            terms = word_vectorizer.get_feature_names_out()
            ignored_terms = {"from", "subject", "text", "title", "com", "org", "net", "www", "http", "https"}
            contributions = {}

            for index, tfidf_value in zip(row.indices, row.data):
                term = str(terms[index]).strip()
                if " " in term or term in ignored_terms or not any(character.isalpha() for character in term):
                    continue
                contribution = float(tfidf_value * coefficients[index] * direction)
                if math.isfinite(contribution) and contribution > 0:
                    contributions[term] = max(contributions.get(term, 0.0), contribution)

            return [term for term, _score in sorted(
                contributions.items(), key=lambda item: (-item[1], item[0])
            )[:limit]]
        except (AttributeError, KeyError, TypeError, ValueError, IndexError):
            # Verdicts still work for compatible pipelines without this structure.
            return []

    def analyze(self, email_text: str) -> dict:
        try:
            pipeline = self._get_pipeline()
            classes = list(pipeline.classes_)
            normalized_classes = [self._binary_label(value) for value in classes]
            if sorted(normalized_classes) != [0, 1]:
                raise ValueError("Pipeline classes must be 0 and 1")

            predicted = self._binary_label(pipeline.predict([email_text])[0])
            rows = pipeline.predict_proba([email_text])
            if len(rows) != 1 or len(rows[0]) != len(classes):
                raise ValueError("Probability output does not match model classes")

            probability_by_label = {}
            for label, raw_probability in zip(normalized_classes, rows[0]):
                probability = float(raw_probability)
                if not math.isfinite(probability) or not 0 <= probability <= 1:
                    raise ValueError("Model returned an invalid probability")
                probability_by_label[label] = probability

            if abs(sum(probability_by_label.values()) - 1.0) > 1e-3:
                raise ValueError("Model probabilities must sum to one")

            confidence = probability_by_label[predicted]
            verdict = "phishing" if predicted == 1 else "legitimate"
            return {
                "label": predicted,
                "verdict": verdict,
                "confidence": confidence,
                "confidence_percent": round(confidence * 100, 1),
                "top_terms": self._top_contributing_terms(pipeline, email_text, predicted),
            }
        except (ModelNotAvailable, ModelLoadError):
            raise
        except Exception as exc:
            raise PredictionError("The model could not produce a valid result") from exc
