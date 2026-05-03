"""Semantic similarity scoring via sentence embeddings (**orisim**)."""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from oritypo_solver.services.settings import env_bool

logger = logging.getLogger(__name__)

_model_lock = threading.Lock()
_model_instance: Any = None


def similarity_enabled() -> bool:
    return env_bool("ORI_ENABLE_SIMILARITY", default=True)


def _model_name() -> str:
    return os.environ.get("ORI_SIMILARITY_MODEL", "").strip() or "all-MiniLM-L6-v2"


def _get_model() -> Any:
    global _model_instance
    if _model_instance is not None:
        return _model_instance
    with _model_lock:
        if _model_instance is not None:
            return _model_instance
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            logger.warning("sentence-transformers not installed; similarity disabled")
            return None
        name = _model_name()
        logger.info("Loading similarity model %s …", name)
        _model_instance = SentenceTransformer(name)
        logger.info("Similarity model loaded.")
        return _model_instance


def build_reference_text(crawl_data: dict) -> str:
    """Assemble a representative text from crawl data for embedding."""
    parts: list[str] = []
    for title in (crawl_data.get("titles") or [])[:3]:
        parts.append(title)
    for desc in (crawl_data.get("meta_descriptions") or [])[:2]:
        parts.append(desc)
    for og in (crawl_data.get("og_titles") or [])[:2]:
        parts.append(og)
    for heading in (crawl_data.get("heading_samples") or [])[:6]:
        parts.append(heading)
    snippet = crawl_data.get("content_snippet") or ""
    if snippet:
        parts.append(snippet[:800])
    return " ".join(parts).strip()


def encode_text(text: str) -> list[float] | None:
    """Encode text into an embedding vector. Returns None if unavailable."""
    if not text.strip():
        return None
    model = _get_model()
    if model is None:
        return None
    try:
        vec = model.encode(text, normalize_embeddings=True)
        return vec.tolist()
    except Exception:
        logger.exception("Failed to encode text")
        return None


def cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Compute cosine similarity between two normalized vectors."""
    if len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    return max(0.0, min(1.0, dot))


def compute_similarity(
    reference_embedding: list[float],
    finding_crawl: dict,
) -> float | None:
    """Compute similarity between reference and a finding's crawl data."""
    text = build_reference_text(finding_crawl)
    if not text.strip():
        return None
    finding_embedding = encode_text(text)
    if finding_embedding is None:
        return None
    return round(cosine_similarity(reference_embedding, finding_embedding), 4)
