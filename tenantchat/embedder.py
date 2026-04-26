"""Local embeddings via sentence-transformers — runs on CPU, no GPU needed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
from rich.console import Console

console = Console()

MODEL_NAME  = "all-MiniLM-L6-v2"
CACHE_PATH  = Path.home() / ".tenantchat" / "embeddings_cache.json"


class Embedder:
    """
    Local semantic embeddings using sentence-transformers.

    Used for:
      1. CA policy matrix intent coverage scoring
      2. Cross-framework finding deduplication
      3. Community knowledge semantic matching
    """

    def __init__(self) -> None:
        self._model = None
        self._cache: dict[str, list[float]] = self._load_cache()

    def load(self) -> None:
        """Lazy-load the model on first use."""
        if self._model is not None:
            return
        console.print(
            f"[dim]Loading embedding model {MODEL_NAME}...[/dim]"
        )
        from sentence_transformers import SentenceTransformer
        self._model = SentenceTransformer(MODEL_NAME)
        console.print("[dim]Embedding model ready.[/dim]")

    def embed(self, text: str) -> list[float]:
        """Embed a single text string. Cached."""
        if text in self._cache:
            return self._cache[text]
        self.load()
        vector = self._model.encode(text, normalize_embeddings=True)
        result = vector.tolist()
        self._cache[text] = result
        self._save_cache()
        return result

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of texts efficiently."""
        self.load()
        missing = [t for t in texts if t not in self._cache]
        if missing:
            vectors = self._model.encode(
                missing, normalize_embeddings=True, show_progress_bar=False
            )
            for text, vector in zip(missing, vectors):
                self._cache[text] = vector.tolist()
            self._save_cache()
        return [self._cache[t] for t in texts]

    def similarity(
        self,
        vec_a: list[float],
        vec_b: list[float],
    ) -> float:
        """Cosine similarity between two embedding vectors."""
        a = np.array(vec_a)
        b = np.array(vec_b)
        denom = np.linalg.norm(a) * np.linalg.norm(b)
        if denom == 0:
            return 0.0
        return float(np.dot(a, b) / denom)

    def similarity_text(self, text_a: str, text_b: str) -> float:
        """Cosine similarity between two text strings."""
        return self.similarity(self.embed(text_a), self.embed(text_b))

    def most_similar(
        self,
        query: str,
        candidates: list[str],
        top_k: int = 3,
    ) -> list[tuple[str, float]]:
        """
        Find the most semantically similar candidates to a query.
        Returns list of (text, score) tuples sorted by score descending.
        """
        if not candidates:
            return []
        query_vec   = self.embed(query)
        cand_vecs   = self.embed_batch(candidates)
        scored = [
            (text, self.similarity(query_vec, vec))
            for text, vec in zip(candidates, cand_vecs)
        ]
        return sorted(scored, key=lambda x: x[1], reverse=True)[:top_k]

    def policy_coverage_score(
        self,
        baseline_requirement: str,
        policies: list[dict],
    ) -> tuple[float, list[dict]]:
        """
        Score how well a set of CA policies covers a baseline requirement.

        Returns:
            coverage_score: 0.0 to 1.0
            gap_policies: policies with low individual coverage
        """
        if not policies:
            return 0.0, []

        req_vec = self.embed(baseline_requirement)

        scored_policies = []
        for policy in policies:
            policy_text = self._policy_to_text(policy)
            policy_vec  = self.embed(policy_text)
            score       = self.similarity(req_vec, policy_vec)
            scored_policies.append((policy, score))

        max_score = max(s for _, s in scored_policies)
        gap_policies = [
            p for p, s in scored_policies
            if s < 0.4
        ]

        return max_score, gap_policies

    def _policy_to_text(self, policy: dict) -> str:
        """Convert a CA policy object to searchable text."""
        parts = [
            policy.get("displayName", ""),
            f"state: {policy.get('state', '')}",
        ]
        conditions = policy.get("conditions", {})
        if conditions.get("clientAppTypes"):
            parts.append(
                f"clientAppTypes: {conditions['clientAppTypes']}"
            )
        if conditions.get("users"):
            users = conditions["users"]
            parts.append(
                f"includeUsers: {users.get('includeUsers', [])}"
            )
            parts.append(
                f"excludeGroups: {users.get('excludeGroups', [])}"
            )
        grant = policy.get("grantControls") or {}
        if grant.get("builtInControls"):
            parts.append(
                f"grantControls: {grant['builtInControls']}"
            )
        return " | ".join(parts)

    def _load_cache(self) -> dict[str, list[float]]:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        if CACHE_PATH.exists():
            try:
                return json.loads(CACHE_PATH.read_text())
            except Exception:
                return {}
        return {}

    def _save_cache(self) -> None:
        try:
            CACHE_PATH.write_text(json.dumps(self._cache))
        except Exception:
            pass
