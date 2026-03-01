"""Jailbreak pattern database for the AumOS Security Runtime.

Provides a curated, versioned database of known jailbreak techniques with
regex pattern matching and semantic similarity matching for variants.
Loaded at startup into memory and refreshed periodically.
"""

import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import numpy as np
from aumos_common.observability import get_logger

if TYPE_CHECKING:
    from aumos_security_runtime.core.interfaces import IJailbreakPatternRepository

logger = get_logger(__name__)


@dataclass
class CompiledPattern:
    """A compiled jailbreak pattern ready for matching.

    Attributes:
        pattern_id: UUID of the pattern record.
        name: Human-readable pattern name.
        technique_family: Attack family (DAN, roleplay, token_smuggling, etc.).
        regex: Compiled regex object for fast matching.
        severity: Severity level (critical, high, medium, low).
    """

    pattern_id: uuid.UUID
    name: str
    technique_family: str
    regex: re.Pattern  # type: ignore[type-arg]
    severity: str


@dataclass
class JailbreakMatchResult:
    """Result of a jailbreak pattern match.

    Attributes:
        matched: Whether any pattern matched.
        pattern_id: UUID of the matched pattern (None if no match).
        technique_family: Attack family of the matched pattern.
        confidence: Match confidence (1.0 for regex, cosine sim for semantic).
        match_method: 'regex', 'semantic', or 'none'.
        severity: Severity level of the matched pattern.
    """

    matched: bool
    confidence: float
    match_method: str
    pattern_id: uuid.UUID | None = None
    technique_family: str | None = None
    severity: str | None = None


class JailbreakPatternDatabase:
    """In-memory jailbreak pattern database with regex and semantic matching.

    Loads patterns from the repository at startup and refreshes periodically.
    Uses a two-stage matching approach:
    1. Regex matching (fast, O(n) patterns)
    2. Semantic similarity matching (slower, for novel variants)

    Args:
        repo: Repository for jailbreak pattern persistence.
        refresh_interval_seconds: How often to reload from DB (default: 3600).
        semantic_threshold: Cosine similarity threshold for semantic match (default: 0.85).
    """

    def __init__(
        self,
        repo: "IJailbreakPatternRepository",
        refresh_interval_seconds: int = 3600,
        semantic_threshold: float = 0.85,
    ) -> None:
        self._repo = repo
        self._refresh_interval = refresh_interval_seconds
        self._semantic_threshold = semantic_threshold
        self._compiled_patterns: list[CompiledPattern] = []
        self._embeddings: np.ndarray | None = None
        self._embedding_model: object | None = None
        self._last_refresh: float | None = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Load patterns from DB and initialize embedding model at startup."""
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import]
            self._embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        except ImportError:
            logger.warning("sentence_transformers not installed; semantic matching disabled")
            self._embedding_model = None

        await self._refresh()
        logger.info(
            "jailbreak_pattern_database_initialized",
            pattern_count=len(self._compiled_patterns),
            semantic_enabled=self._embedding_model is not None,
        )

    async def match(self, content: str) -> JailbreakMatchResult:
        """Match content against the jailbreak pattern database.

        Runs regex matching first, then semantic similarity if no regex match.

        Args:
            content: Text to check against known jailbreak patterns.

        Returns:
            JailbreakMatchResult with match details.
        """
        await self._refresh_if_stale()

        # Stage 1: Regex pattern matching (fast)
        for pattern in self._compiled_patterns:
            try:
                if pattern.regex.search(content):
                    return JailbreakMatchResult(
                        matched=True,
                        pattern_id=pattern.pattern_id,
                        technique_family=pattern.technique_family,
                        confidence=1.0,
                        match_method="regex",
                        severity=pattern.severity,
                    )
            except re.error:
                continue

        # Stage 2: Semantic similarity (only if embedding model is available)
        if self._embedding_model is not None and self._embeddings is not None and len(self._compiled_patterns) > 0:
            try:
                content_embedding = await asyncio.to_thread(
                    self._encode_text, content
                )
                similarities = self._cosine_similarity(content_embedding, self._embeddings)
                max_idx = int(np.argmax(similarities))

                if similarities[max_idx] >= self._semantic_threshold:
                    pattern = self._compiled_patterns[max_idx]
                    return JailbreakMatchResult(
                        matched=True,
                        pattern_id=pattern.pattern_id,
                        technique_family=pattern.technique_family,
                        confidence=float(similarities[max_idx]),
                        match_method="semantic",
                        severity=pattern.severity,
                    )
            except Exception as exc:
                logger.warning("semantic_matching_failed", error=str(exc))

        return JailbreakMatchResult(matched=False, confidence=0.0, match_method="none")

    def _encode_text(self, text: str) -> np.ndarray:
        """Encode text to embedding vector (runs in thread pool)."""
        model = self._embedding_model
        if model is None:
            return np.array([])
        encoded = model.encode([text])  # type: ignore[union-attr]
        return np.array(encoded)

    def _cosine_similarity(self, query: np.ndarray, corpus: np.ndarray) -> np.ndarray:
        """Compute cosine similarity between query and corpus embeddings."""
        if query.ndim == 1:
            query = query.reshape(1, -1)
        query_norm = np.linalg.norm(query, axis=1, keepdims=True)
        corpus_norm = np.linalg.norm(corpus, axis=1, keepdims=True)
        query_normalized = query / (query_norm + 1e-8)
        corpus_normalized = corpus / (corpus_norm + 1e-8)
        return (query_normalized @ corpus_normalized.T).flatten()

    async def _refresh_if_stale(self) -> None:
        """Refresh patterns from DB if the refresh interval has elapsed."""
        now = time.monotonic()
        if self._last_refresh is None or (now - self._last_refresh) >= self._refresh_interval:
            async with self._lock:
                # Double-check after acquiring lock
                if self._last_refresh is None or (now - self._last_refresh) >= self._refresh_interval:
                    await self._refresh()

    async def _refresh(self) -> None:
        """Load patterns from repository and recompile."""
        try:
            patterns = await self._repo.list_all_active()
            compiled: list[CompiledPattern] = []

            for p in patterns:
                try:
                    regex = re.compile(p.pattern_regex, re.IGNORECASE | re.DOTALL)
                    compiled.append(
                        CompiledPattern(
                            pattern_id=p.id,
                            name=p.name,
                            technique_family=p.technique_family,
                            regex=regex,
                            severity=p.severity,
                        )
                    )
                except re.error as exc:
                    logger.warning("invalid_jailbreak_regex", pattern_name=p.name, error=str(exc))

            self._compiled_patterns = compiled

            # Rebuild semantic embeddings
            if self._embedding_model is not None and compiled:
                pattern_texts = [f"{p.name} {p.technique_family}" for p in compiled]
                self._embeddings = await asyncio.to_thread(
                    self._embedding_model.encode,  # type: ignore[union-attr]
                    pattern_texts,
                )
            else:
                self._embeddings = None

            self._last_refresh = time.monotonic()
            logger.info(
                "jailbreak_patterns_refreshed",
                count=len(compiled),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as exc:
            logger.error("jailbreak_pattern_refresh_failed", error=str(exc))
