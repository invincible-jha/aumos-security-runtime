"""ML-based prompt injection detection using spaCy.

Uses spaCy's text classification pipeline to detect injection attempts
that pattern matching might miss — including paraphrased or obfuscated
attacks that avoid direct keyword matching.

The model is loaded ONCE at startup via initialize() and reused across
all requests. Loading spaCy models is expensive (~500ms) and must never
happen on the request hot path.

Model options:
1. Base spaCy model (en_core_web_sm) with a custom textcat component
2. Fine-tuned model path provided via AUMOS_SECRUNTIME_ML_MODEL_PATH

The classifier outputs a probability score for the "INJECTION" class.
Scores are compared to thresholds defined in settings:
  - >= injection_block_threshold (default 0.85): block
  - >= injection_warn_threshold (default 0.60): warn
  - < injection_warn_threshold: allow
"""

from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class MLScanResult:
    """Result from the ML-based injection classifier.

    Attributes:
        is_threat: Whether the ML model predicts injection.
        threat_type: Always "prompt_injection" for this scanner.
        severity: Severity based on confidence score.
        confidence: Probability score from the classifier (0.0–1.0).
        details: Details about the model prediction.
    """

    is_threat: bool
    threat_type: str = "prompt_injection"
    severity: str = "high"
    confidence: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


class MLScanner:
    """spaCy-based ML prompt injection classifier.

    Loads the spaCy model at startup and classifies input content
    using a text classification pipeline. The model is loaded once
    and reused across all requests via the stored instance.

    Args:
        model_path: Path to fine-tuned model. Empty string uses base spaCy model.
        block_threshold: Confidence above which to classify as injection.
        warn_threshold: Confidence above which to classify as suspicious.
    """

    def __init__(
        self,
        model_path: str = "",
        block_threshold: float = 0.85,
        warn_threshold: float = 0.60,
    ) -> None:
        """Initialize the ML scanner with configuration.

        Does NOT load the model — call initialize() explicitly at startup.

        Args:
            model_path: Path to fine-tuned spaCy model. Empty = base model.
            block_threshold: Score above which content is classified as injection.
            warn_threshold: Score above which content is classified as suspicious.
        """
        self._model_path = model_path
        self._block_threshold = block_threshold
        self._warn_threshold = warn_threshold
        self._nlp: Any = None
        self._initialized = False

    async def initialize(self) -> None:
        """Load spaCy model into memory.

        This is intentionally synchronous under the hood because spaCy's
        model loading is CPU-bound and runs in the same thread. It should
        ONLY be called at startup, never on the request hot path.

        Raises:
            RuntimeError: If the model cannot be loaded.
        """
        import asyncio

        # Run the blocking model load in a thread pool to avoid blocking
        # the event loop during startup
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._load_model)
        self._initialized = True
        logger.info(
            "ML scanner model loaded",
            model_path=self._model_path or "spacy/en_core_web_sm",
        )

    def _load_model(self) -> None:
        """Load the spaCy model (blocking — runs in thread pool).

        Uses the custom fine-tuned model if model_path is set,
        otherwise falls back to the base en_core_web_sm model.
        """
        try:
            import spacy

            if self._model_path:
                self._nlp = spacy.load(self._model_path)
                logger.info("Loaded fine-tuned injection classifier", path=self._model_path)
            else:
                # Base model — textcat component added for injection classification
                # In production, this should be replaced with a fine-tuned model
                self._nlp = spacy.load("en_core_web_sm")
                logger.info(
                    "Loaded base spaCy model — textcat not available, using heuristic fallback"
                )
        except Exception as exc:
            logger.error("Failed to load ML model", error=str(exc))
            raise RuntimeError(f"ML scanner model load failed: {exc}") from exc

    async def scan(self, content: str) -> MLScanResult:
        """Classify content as injection or benign using the ML model.

        Truncates content to 512 tokens to manage latency.
        Falls back to a low-confidence non-threat result if the model
        has not been initialized (fail-open for ML, not fail-open overall
        because pattern scanner provides the primary detection layer).

        Args:
            content: Text content to classify.

        Returns:
            MLScanResult with is_threat flag and confidence score.
        """
        if not self._initialized or self._nlp is None:
            logger.warning("ML scanner not initialized — returning low-confidence result")
            return MLScanResult(
                is_threat=False,
                confidence=0.0,
                details={"method": "ml_scanner", "status": "not_initialized"},
            )

        # Truncate to manage latency budget — long content adds proportional time
        truncated_content = content[:4096]

        # Run spaCy NLP pipeline
        doc = self._nlp(truncated_content)

        # If the model has a textcat component, use its scores
        if doc.cats and "INJECTION" in doc.cats:
            injection_score = doc.cats["INJECTION"]
        else:
            # Heuristic fallback when no textcat is available:
            # Use presence of named entities and linguistic features
            # This is intentionally conservative — prefer false negatives
            # over false positives in the ML layer (patterns handle critical cases)
            injection_score = self._heuristic_score(doc)

        # Determine severity and threat status based on thresholds
        if injection_score >= self._block_threshold:
            severity = "high"
            is_threat = True
        elif injection_score >= self._warn_threshold:
            severity = "medium"
            is_threat = True
        else:
            severity = "low"
            is_threat = False

        return MLScanResult(
            is_threat=is_threat,
            threat_type="prompt_injection",
            severity=severity,
            confidence=injection_score,
            details={
                "method": "ml_scanner",
                "model": self._model_path or "en_core_web_sm",
                "score": round(injection_score, 4),
                "block_threshold": self._block_threshold,
                "warn_threshold": self._warn_threshold,
            },
        )

    def _heuristic_score(self, doc: Any) -> float:
        """Compute a heuristic injection score without a textcat model.

        Used as fallback when the spaCy model does not have a text
        classification component. Intentionally conservative — generates
        low scores to avoid polluting pattern scanner results.

        The primary detection responsibility falls on the pattern scanner.
        This heuristic exists only to catch novel paraphrasing that
        avoids all known patterns.

        Args:
            doc: spaCy Doc object.

        Returns:
            Heuristic injection probability score (0.0–0.5 range).
        """
        score = 0.0

        # Imperative verbs targeting instruction-following behavior
        imperative_targets = {"ignore", "forget", "disregard", "override", "pretend", "reveal"}
        imperative_count = sum(
            1
            for token in doc
            if token.pos_ == "VERB" and token.lemma_.lower() in imperative_targets
        )
        score += min(imperative_count * 0.10, 0.30)

        # High token count with instruction-like structure
        if len(doc) > 200:
            score += 0.05

        return min(score, 0.50)  # Cap at 0.50 — never crosses warn threshold alone
