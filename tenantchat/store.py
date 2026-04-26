"""ChromaDB local vector store — persists embeddings between sessions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings
from rich.console import Console

from tenantchat.embedder import Embedder

console  = Console()
DB_PATH  = Path.home() / ".tenantchat" / "vectorstore"


class Store:
    """
    Local ChromaDB vector store.

    Collections:
      tenant_state   — embedded tenant configuration snapshots
      baselines      — embedded baseline control definitions
      community_kb   — embedded community knowledge articles
      findings       — embedded assessment findings
    """

    def __init__(self) -> None:
        DB_PATH.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(
            path=str(DB_PATH),
            settings=Settings(anonymized_telemetry=False),
        )
        self._embedder = Embedder()
        self._collections: dict[str, Any] = {}

    def _collection(self, name: str) -> Any:
        if name not in self._collections:
            self._collections[name] = (
                self._client.get_or_create_collection(name)
            )
        return self._collections[name]

    # ── Tenant state ─────────────────────────────────────────────────────

    def upsert_tenant_state(
        self,
        tenant_id: str,
        domain:    str,
        state_chunks: list[dict],
    ) -> None:
        """
        Embed and store tenant configuration chunks.
        Each chunk is a dict with 'text' and 'metadata'.
        """
        col = self._collection("tenant_state")
        for i, chunk in enumerate(state_chunks):
            text     = chunk["text"]
            metadata = chunk.get("metadata", {})
            metadata["tenant_id"] = tenant_id
            metadata["domain"]    = domain
            col.upsert(
                ids=[f"{tenant_id}_{i}"],
                embeddings=[self._embedder.embed(text)],
                documents=[text],
                metadatas=[metadata],
            )
        console.print(
            f"[dim]Stored {len(state_chunks)} tenant state chunks.[/dim]"
        )

    def search_tenant_state(
        self,
        query:     str,
        tenant_id: str,
        top_k:     int = 5,
    ) -> list[dict]:
        """Semantic search over tenant state for a given tenant."""
        col = self._collection("tenant_state")
        try:
            results = col.query(
                query_embeddings=[self._embedder.embed(query)],
                n_results=top_k,
                where={"tenant_id": tenant_id},
            )
            return self._format_results(results)
        except Exception:
            return []

    # ── Baselines ────────────────────────────────────────────────────────

    def upsert_baseline(
        self,
        control_id:  str,
        framework:   str,
        title:       str,
        description: str,
        metadata:    dict | None = None,
    ) -> None:
        """Embed and store a baseline control definition."""
        col  = self._collection("baselines")
        text = f"{framework} {control_id}: {title}. {description}"
        meta = metadata or {}
        meta.update({
            "control_id": control_id,
            "framework":  framework,
            "title":      title,
        })
        col.upsert(
            ids=[f"{framework}_{control_id}"],
            embeddings=[self._embedder.embed(text)],
            documents=[text],
            metadatas=[meta],
        )

    def search_baselines(
        self,
        query: str,
        top_k: int = 5,
        framework: str | None = None,
    ) -> list[dict]:
        """Semantic search over baseline controls."""
        col = self._collection("baselines")
        try:
            where = {"framework": framework} if framework else None
            results = col.query(
                query_embeddings=[self._embedder.embed(query)],
                n_results=top_k,
                where=where,
            )
            return self._format_results(results)
        except Exception:
            return []

    # ── Community KB ─────────────────────────────────────────────────────

    def upsert_kb_article(
        self,
        article_id: str,
        title:      str,
        content:    str,
        author:     str,
        url:        str,
        domain:     str,
    ) -> None:
        """Embed and store a community knowledge article."""
        col  = self._collection("community_kb")
        text = f"{title} by {author}: {content[:500]}"
        col.upsert(
            ids=[article_id],
            embeddings=[self._embedder.embed(text)],
            documents=[text],
            metadatas=[{
                "title":  title,
                "author": author,
                "url":    url,
                "domain": domain,
            }],
        )

    def search_kb(
        self,
        query: str,
        top_k: int = 3,
        domain: str | None = None,
    ) -> list[dict]:
        """Semantic search over community knowledge base."""
        col = self._collection("community_kb")
        try:
            where   = {"domain": domain} if domain else None
            results = col.query(
                query_embeddings=[self._embedder.embed(query)],
                n_results=top_k,
                where=where,
            )
            return self._format_results(results)
        except Exception:
            return []

    # ── Findings ─────────────────────────────────────────────────────────

    def upsert_finding(
        self,
        finding_id: str,
        tenant_id:  str,
        title:      str,
        delta:      str,
        severity:   str,
        framework:  str,
    ) -> None:
        """Embed and store an assessment finding."""
        col  = self._collection("findings")
        text = f"{severity} {title}: {delta}"
        col.upsert(
            ids=[finding_id],
            embeddings=[self._embedder.embed(text)],
            documents=[text],
            metadatas=[{
                "tenant_id": tenant_id,
                "title":     title,
                "severity":  severity,
                "framework": framework,
            }],
        )

    def search_findings(
        self,
        query:     str,
        tenant_id: str,
        top_k:     int = 5,
    ) -> list[dict]:
        """Semantic search over findings for a tenant."""
        col = self._collection("findings")
        try:
            results = col.query(
                query_embeddings=[self._embedder.embed(query)],
                n_results=top_k,
                where={"tenant_id": tenant_id},
            )
            return self._format_results(results)
        except Exception:
            return []

    # ── Helpers ──────────────────────────────────────────────────────────

    def _format_results(self, results: dict) -> list[dict]:
        """Format ChromaDB query results into clean dicts."""
        output = []
        docs      = results.get("documents", [[]])[0]
        metas     = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]
        for doc, meta, dist in zip(docs, metas, distances):
            output.append({
                "text":       doc,
                "metadata":   meta,
                "similarity": round(1 - dist, 4),
            })
        return output

    def clear_tenant(self, tenant_id: str) -> None:
        """Remove all stored data for a specific tenant."""
        for name in ("tenant_state", "findings"):
            col = self._collection(name)
            try:
                col.delete(where={"tenant_id": tenant_id})
            except Exception:
                pass
