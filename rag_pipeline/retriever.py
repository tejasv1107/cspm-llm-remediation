"""Retrieve the top-3 Terraform modules for a finding: resource type + semantic similarity."""

from __future__ import annotations

from dataclasses import dataclass, field

from ingestion.schema import FindingRecord
from rag_pipeline.module_indexer import (
    COLLECTION_NAME,
    DEFAULT_CHROMA_PATH,
    Embedder,
    get_collection,
    get_embedder,
)

RESOURCE_TYPE_BONUS = 0.5   # module declares this finding's resource type
CONTROL_BONUS = 0.5         # module lists this finding's Security Hub control


@dataclass
class RetrievedModule:
    """One retrieval hit."""

    name: str
    score: float                 # ranking score = similarity + bonuses
    similarity: float            # cosine similarity in [-1, 1]
    resource_type_match: bool
    control_match: bool
    description: str
    hcl: str = field(repr=False)


class ModuleRetriever:
    """Query the ChromaDB module collection.

    A candidate is kept only if it matches on resource type, matches on control, or is
    semantically close (``similarity >= min_similarity``). Otherwise the retriever returns
    nothing, which lets the pipeline degrade gracefully instead of forcing a bad module.
    """

    def __init__(
        self,
        chroma_path: str = DEFAULT_CHROMA_PATH,
        embedder: Embedder | None = None,
        collection_name: str = COLLECTION_NAME,
        min_similarity: float | None = None,
        candidate_pool: int = 10,
    ) -> None:
        """``min_similarity`` defaults to the embedder's own calibrated threshold."""
        self.embedder = embedder or get_embedder()
        self.collection = get_collection(chroma_path, collection_name)
        self.min_similarity = (
            min_similarity if min_similarity is not None else self.embedder.default_min_similarity
        )
        self.candidate_pool = candidate_pool

    @staticmethod
    def build_query(finding: FindingRecord) -> str:
        """Text describing the finding, in the same vocabulary as the module embeddings."""
        return " ".join(
            part for part in (finding.title, finding.control_id, finding.resource_type,
                              finding.recommendation_text) if part
        )

    def retrieve(self, finding: FindingRecord, k: int = 3) -> list[RetrievedModule]:
        """Top-``k`` modules for ``finding`` (possibly fewer, possibly none)."""
        count = self.collection.count()
        if count == 0:
            return []
        result = self.collection.query(
            query_embeddings=self.embedder.embed([self.build_query(finding)]),
            n_results=min(self.candidate_pool, count),
            include=["documents", "metadatas", "distances"],
        )
        hits: list[RetrievedModule] = []
        for doc, meta, distance in zip(result["documents"][0], result["metadatas"][0], result["distances"][0]):
            similarity = 1.0 - float(distance)
            type_match = f"|{finding.resource_type}|" in meta["resource_types"]
            control_match = bool(finding.control_id) and f"|{finding.control_id}|" in meta["controls"]
            if not (type_match or control_match or similarity >= self.min_similarity):
                continue
            score = similarity + (RESOURCE_TYPE_BONUS if type_match else 0) + (CONTROL_BONUS if control_match else 0)
            hits.append(
                RetrievedModule(
                    name=meta["module_name"],
                    score=score,
                    similarity=similarity,
                    resource_type_match=type_match,
                    control_match=control_match,
                    description=meta["description"],
                    hcl=doc,
                )
            )
        return sorted(hits, key=lambda h: h.score, reverse=True)[:k]
