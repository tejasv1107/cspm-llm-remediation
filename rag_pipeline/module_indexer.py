"""Embed the Terraform modules into ChromaDB with searchable metadata tags.

Each module's ``main.tf`` starts with a comment header that this indexer parses::

    # Module: s3_public_access_block
    # Description: ...
    # Controls: CIS 2.1.1; Security Hub S3.1, S3.2
    # Resource-Types: AwsS3Bucket, AwsS3AccountPublicAccessBlock
    # Keywords: ...

Embeddings are computed here (not by Chroma) so the embedder is swappable: an offline
hashing embedder for tests, Chroma's MiniLM default, or Amazon Titan via Bedrock.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import boto3
import chromadb

COLLECTION_NAME = "terraform_modules"
DEFAULT_MODULES_DIR = Path(os.getenv("TERRAFORM_MODULES_DIR", "terraform_modules"))
DEFAULT_CHROMA_PATH = os.getenv("CHROMADB_PATH", "./chroma_db")

_HEADER = re.compile(r"^#\s*(Module|Description|Controls|Resource-Types|Keywords):\s*(.+)$", re.MULTILINE)
_VARIABLE = re.compile(r'^variable\s+"([^"]+)"', re.MULTILINE)


# ----------------------------------------------------------------------- embedders
class Embedder(Protocol):
    """Anything that turns texts into fixed-size vectors.

    ``default_min_similarity`` is the cosine similarity below which the retriever treats a
    module as unrelated when it matches on neither resource type nor control. Similarity
    scales differ per model, so the threshold belongs to the embedder.
    """

    name: str
    default_min_similarity: float

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def tokenize(text: str) -> list[str]:
    """Lower-case word tokens; splits CamelCase so ``AwsS3Bucket`` -> aws, s3, bucket."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return re.findall(r"[a-z0-9]+", spaced.lower())


class HashingEmbedder:
    """Deterministic, offline bag-of-words embedder (signed feature hashing, L2-normalised).

    Not semantic, but stable and dependency-free: ideal for unit tests and CI.
    """

    name = "hash"
    default_min_similarity = 0.3  # calibrated on the seed ground-truth set

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            vec = [0.0] * self.dim
            for token in tokenize(text):
                digest = hashlib.md5(token.encode("utf-8")).digest()
                index = int.from_bytes(digest[:4], "big") % self.dim
                vec[index] += 1.0 if digest[4] % 2 == 0 else -1.0
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            vectors.append([v / norm for v in vec])
        return vectors


class ChromaDefaultEmbedder:
    """Chroma's bundled MiniLM (ONNX) model. Downloads ~80 MB on first use."""

    name = "default"
    # On the seed set, correct modules scored >= 0.51 and unrelated findings <= 0.49. That
    # margin is thin and comes from only 5 negatives: re-calibrate on real ground truth.
    default_min_similarity = 0.5

    def __init__(self) -> None:
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

        self._fn = DefaultEmbeddingFunction()

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [list(map(float, v)) for v in self._fn(texts)]


class BedrockTitanEmbedder:
    """Amazon Titan Text Embeddings v2 through Bedrock."""

    name = "bedrock"
    default_min_similarity = 0.5  # NOT calibrated (no Bedrock access when written): measure before trusting

    def __init__(self, model_id: str = "amazon.titan-embed-text-v2:0", client=None) -> None:
        self.model_id = model_id
        self._client = client or boto3.client("bedrock-runtime", region_name=os.getenv("AWS_REGION", "ap-south-1"))

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for text in texts:
            response = self._client.invoke_model(
                modelId=self.model_id,
                body=json.dumps({"inputText": text, "normalize": True}),
                contentType="application/json",
                accept="application/json",
            )
            out.append(json.loads(response["body"].read())["embedding"])
        return out


def get_embedder(kind: str | None = None) -> Embedder:
    """Pick an embedder by name (``hash`` | ``default`` | ``bedrock``); env ``EMBEDDER`` if None."""
    kind = (kind or os.getenv("EMBEDDER", "default")).lower()
    if kind == "hash":
        return HashingEmbedder()
    if kind == "bedrock":
        return BedrockTitanEmbedder()
    if kind == "default":
        return ChromaDefaultEmbedder()
    raise ValueError(f"Unknown embedder {kind!r}; expected hash, default or bedrock")


# ----------------------------------------------------------------------- modules
@dataclass
class ModuleDoc:
    """A parsed Terraform module ready to be indexed."""

    name: str
    description: str
    controls: list[str]
    resource_types: list[str]
    keywords: str
    variables: list[str]
    hcl: str = field(repr=False)

    def embedding_text(self) -> str:
        """The natural-language text that represents this module in vector space."""
        return (
            f"{self.name.replace('_', ' ')}. {self.description} "
            f"Controls: {' '.join(self.controls)}. Resource types: {' '.join(self.resource_types)}. "
            f"Keywords: {self.keywords}. Inputs: {' '.join(self.variables)}."
        )

    def metadata(self) -> dict[str, str]:
        """Chroma metadata (scalars only). Lists are stored pipe-delimited: ``|A|B|``."""
        return {
            "module_name": self.name,
            "description": self.description,
            "controls": "|" + "|".join(self.controls) + "|",
            "resource_types": "|" + "|".join(self.resource_types) + "|",
        }


def parse_controls(raw: str) -> list[str]:
    """``"CIS 2.1.1; Security Hub S3.1, S3.2"`` -> ``["CIS 2.1.1", "S3.1", "S3.2"]``."""
    controls: list[str] = []
    for part in raw.split(";"):
        part = part.strip()
        is_cis = part.upper().startswith("CIS")
        part = re.sub(r"^(CIS|Security Hub)\s*", "", part, flags=re.IGNORECASE)
        for item in filter(None, (p.strip() for p in part.split(","))):
            controls.append(f"CIS {item}" if is_cis else item)
    return controls


def parse_module(module_dir: Path) -> ModuleDoc:
    """Parse ``module_dir/main.tf`` (header comments + variable names)."""
    hcl = (module_dir / "main.tf").read_text(encoding="utf-8")
    header = dict(_HEADER.findall(hcl))
    return ModuleDoc(
        name=header.get("Module", module_dir.name).strip(),
        description=header.get("Description", "").strip(),
        controls=parse_controls(header.get("Controls", "")),
        resource_types=[t.strip() for t in header.get("Resource-Types", "").split(",") if t.strip()],
        keywords=header.get("Keywords", "").strip(),
        variables=_VARIABLE.findall(hcl),
        hcl=hcl,
    )


def discover_modules(modules_dir: Path | str = DEFAULT_MODULES_DIR) -> list[ModuleDoc]:
    """Parse every sub-directory of ``modules_dir`` that contains a ``main.tf``."""
    root = Path(modules_dir)
    return [parse_module(d) for d in sorted(root.iterdir()) if (d / "main.tf").is_file()]


def get_collection(chroma_path: str | Path = DEFAULT_CHROMA_PATH, collection_name: str = COLLECTION_NAME):
    """Open (or create) the persistent cosine-distance collection."""
    client = chromadb.PersistentClient(path=str(chroma_path))
    return client.get_or_create_collection(
        name=collection_name, embedding_function=None, metadata={"hnsw:space": "cosine"}
    )


def index_modules(
    modules_dir: Path | str = DEFAULT_MODULES_DIR,
    chroma_path: str | Path = DEFAULT_CHROMA_PATH,
    embedder: Embedder | None = None,
    collection_name: str = COLLECTION_NAME,
) -> int:
    """Embed and upsert all modules. Returns the number indexed. Idempotent (upsert by name)."""
    embedder = embedder or get_embedder()
    modules = discover_modules(modules_dir)
    if not modules:
        return 0
    collection = get_collection(chroma_path, collection_name)
    collection.upsert(
        ids=[m.name for m in modules],
        embeddings=embedder.embed([m.embedding_text() for m in modules]),
        documents=[m.hcl for m in modules],  # the document IS the HCL handed to the LLM
        metadatas=[m.metadata() for m in modules],
    )
    return len(modules)


def main() -> None:  # pragma: no cover - thin CLI
    parser = argparse.ArgumentParser(description="Index Terraform modules into ChromaDB")
    parser.add_argument("--modules-dir", default=str(DEFAULT_MODULES_DIR))
    parser.add_argument("--chroma-path", default=DEFAULT_CHROMA_PATH)
    parser.add_argument("--embedder", default=None, help="hash | default | bedrock")
    args = parser.parse_args()
    count = index_modules(args.modules_dir, args.chroma_path, get_embedder(args.embedder))
    print(f"Indexed {count} modules into {args.chroma_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
