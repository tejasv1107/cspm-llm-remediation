"""Mean Reciprocal Rank of RAG retrieval against a hand-labelled ground-truth set."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from ingestion.schema import FindingRecord, Severity
from rag_pipeline.retriever import RetrievedModule

DEFAULT_GROUND_TRUTH = Path("data/ground_truth/ground_truth.json")
_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


class SupportsRetrieve(Protocol):
    def retrieve(self, finding: FindingRecord, k: int = 3) -> list[RetrievedModule]: ...


def reciprocal_rank(ranked: list[str], relevant: set[str]) -> float:
    """1 / rank of the first relevant item (1-indexed); 0.0 if none is retrieved."""
    for position, name in enumerate(ranked, start=1):
        if name in relevant:
            return 1.0 / position
    return 0.0


def load_ground_truth(path: str | Path = DEFAULT_GROUND_TRUTH) -> list[dict[str, Any]]:
    """Load the ground-truth JSON: a list of finding descriptors with ``relevant_modules``."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["findings"]


def entry_to_finding(entry: dict[str, Any]) -> FindingRecord:
    """Build a FindingRecord from a ground-truth entry (only retrieval-relevant fields matter)."""
    return FindingRecord(
        finding_id=entry["id"],
        account_id="000000000000",
        severity=Severity(entry.get("severity", "HIGH")),
        title=entry["title"],
        resource_type=entry["resource_type"],
        resource_arn=entry.get("resource_arn", "arn:aws:s3:::example"),
        region="ap-south-1",
        created_at=_EPOCH,
        updated_at=_EPOCH,
        recommendation_text=entry.get("recommendation_text", ""),
        control_id=entry.get("control_id", ""),
    )


def evaluate_mrr(retriever: SupportsRetrieve, entries: list[dict[str, Any]], k: int = 3) -> dict[str, Any]:
    """Compute MRR@k, Hit@1 and Hit@k over entries that have at least one relevant module.

    Entries with an empty ``relevant_modules`` list are *negative* cases (no module should
    match); they are excluded from MRR and reported as ``no_module_accuracy``.
    """
    positives, negatives = [], []
    per_item = []
    for entry in entries:
        ranked = [m.name for m in retriever.retrieve(entry_to_finding(entry), k=k)]
        relevant = set(entry.get("relevant_modules", []))
        if relevant:
            rr = reciprocal_rank(ranked, relevant)
            positives.append(rr)
            per_item.append({"id": entry["id"], "ranked": ranked, "relevant": sorted(relevant), "rr": rr})
        else:
            negatives.append(not ranked)
            per_item.append({"id": entry["id"], "ranked": ranked, "relevant": [], "rr": None})

    n = len(positives)
    return {
        "k": k,
        "n_positive": n,
        "n_negative": len(negatives),
        "mrr": sum(positives) / n if n else 0.0,
        "hit_at_1": sum(1 for r in positives if r == 1.0) / n if n else 0.0,
        "hit_at_k": sum(1 for r in positives if r > 0) / n if n else 0.0,
        "no_module_accuracy": sum(negatives) / len(negatives) if negatives else None,
        "per_item": per_item,
    }


def main() -> None:  # pragma: no cover - thin CLI
    from rag_pipeline.module_indexer import get_embedder
    from rag_pipeline.retriever import ModuleRetriever

    parser = argparse.ArgumentParser(description="Evaluate retrieval MRR")
    parser.add_argument("--ground-truth", default=str(DEFAULT_GROUND_TRUTH))
    parser.add_argument("--chroma-path", default="./chroma_db")
    parser.add_argument("--embedder", default=None)
    parser.add_argument("-k", type=int, default=3)
    args = parser.parse_args()

    retriever = ModuleRetriever(chroma_path=args.chroma_path, embedder=get_embedder(args.embedder))
    result = evaluate_mrr(retriever, load_ground_truth(args.ground_truth), k=args.k)
    print(json.dumps({k: v for k, v in result.items() if k != "per_item"}, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
