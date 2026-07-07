"""
stores/faiss_store.py
FAISS Store — DS4: Vector Memory for HCI-OS Behavior Embeddings

Provides sub-millisecond approximate nearest neighbor (ANN) search
over 256-dim behavior embeddings using FAISS IndexFlatIP (inner product).

Architecture:
    - Vectors are L2-normalized before insertion so that inner product
      equals cosine similarity.
    - Supports save/load from disk for persistence across restarts.
    - Each embedding is associated with metadata (evidence_id, fingerprint, etc.)
      stored in a parallel list.

Pipeline position: Used by A3 (Path 2 fuzzy match)
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("FAISSStore")

# ─── Configuration ───────────────────────────────────────────────────────────
DEFAULT_DIMENSION: int = 256
DEFAULT_SIMILARITY_THRESHOLD: float = 0.85
DEFAULT_INDEX_PATH: str = str(
    Path(__file__).parent.parent / "data" / "faiss_behavior.index"
)
DEFAULT_META_PATH: str = str(
    Path(__file__).parent.parent / "data" / "faiss_metadata.json"
)


class FAISSStore:
    """
    FAISS-backed vector index for behavior embedding similarity search.

    Uses IndexFlatIP (inner product) with L2-normalized vectors,
    which is mathematically equivalent to cosine similarity search.
    """

    def __init__(
        self,
        dimension: int = DEFAULT_DIMENSION,
        similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        index_path: Optional[str] = None,
        meta_path: Optional[str] = None,
        auto_load: bool = True,
    ):
        """
        Initialize the FAISS store.

        Args:
            dimension: Embedding dimensionality (256 for HCI-OS).
            similarity_threshold: Cosine similarity threshold for fuzzy match.
            index_path: Path to save/load the FAISS index file.
            meta_path: Path to save/load the metadata JSON file.
            auto_load: If True, auto-load existing index from disk on init.
        """
        self.dimension = dimension
        self.similarity_threshold = similarity_threshold
        self.index_path = index_path or DEFAULT_INDEX_PATH
        self.meta_path = meta_path or DEFAULT_META_PATH

        # Metadata parallel to the FAISS index — stores evidence_id, fingerprint, etc.
        self._metadata: List[Dict[str, Any]] = []

        try:
            import faiss
            self._faiss = faiss
            self._index = faiss.IndexFlatIP(dimension)
            logger.info(
                "FAISSStore: Initialized IndexFlatIP (dim=%d, threshold=%.2f)",
                dimension,
                similarity_threshold,
            )
        except ImportError:
            logger.warning(
                "FAISSStore: faiss-cpu not installed — using NumPy fallback. "
                "Install with: pip install faiss-cpu"
            )
            self._faiss = None
            self._index = None
            self._np_vectors: List[np.ndarray] = []

        # Auto-load from disk if index file exists
        if auto_load:
            self.load()

    @property
    def size(self) -> int:
        """Number of vectors currently in the index."""
        if self._faiss is not None and self._index is not None:
            return self._index.ntotal
        return len(self._np_vectors) if hasattr(self, "_np_vectors") else 0

    # ─── Normalization ────────────────────────────────────────────────────────

    @staticmethod
    def _normalize(vectors: np.ndarray) -> np.ndarray:
        """
        L2-normalize vectors so that inner product = cosine similarity.
        Handles zero vectors gracefully.
        """
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        # Avoid division by zero
        norms = np.where(norms == 0, 1.0, norms)
        return vectors / norms

    # ─── Add ──────────────────────────────────────────────────────────────────

    def add(
        self,
        embeddings: List[List[float]],
        metadata: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        """
        Add embeddings to the index.

        Args:
            embeddings: List of 256-dim float vectors.
            metadata: Optional parallel list of metadata dicts
                      (e.g., {"evidence_id": "...", "fingerprint": "..."}).

        Returns:
            Number of vectors added.
        """
        if not embeddings:
            return 0

        vectors = np.array(embeddings, dtype=np.float32)
        if vectors.ndim == 1:
            vectors = vectors.reshape(1, -1)

        if vectors.shape[1] != self.dimension:
            raise ValueError(
                f"Expected {self.dimension}-dim vectors, got {vectors.shape[1]}-dim"
            )

        # L2-normalize for cosine similarity via inner product
        vectors = self._normalize(vectors)

        if self._faiss is not None and self._index is not None:
            self._index.add(vectors)
        else:
            for v in vectors:
                self._np_vectors.append(v.copy())

        # Store metadata
        if metadata:
            self._metadata.extend(metadata[:len(vectors)])
        else:
            self._metadata.extend([{}] * len(vectors))

        logger.debug("FAISSStore: Added %d vectors (total: %d)", len(vectors), self.size)
        return len(vectors)

    # ─── Search ───────────────────────────────────────────────────────────────

    def search(
        self,
        query_embedding: List[float],
        k: int = 1,
        threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search for the top-k nearest neighbors by cosine similarity.

        Args:
            query_embedding: 256-dim query vector.
            k: Number of nearest neighbors to return.
            threshold: Optional override for similarity threshold.

        Returns:
            List of dicts, each with:
              - "index": int position in the index
              - "similarity": float cosine similarity score
              - "metadata": dict of associated metadata
              - "above_threshold": bool if similarity >= threshold
        """
        if self.size == 0:
            return []

        thresh = threshold if threshold is not None else self.similarity_threshold

        query = np.array([query_embedding], dtype=np.float32)
        if query.shape[1] != self.dimension:
            raise ValueError(
                f"Query must be {self.dimension}-dim, got {query.shape[1]}-dim"
            )

        # Normalize query
        query = self._normalize(query)

        if self._faiss is not None and self._index is not None:
            # FAISS search — returns (distances, indices) arrays
            actual_k = min(k, self.size)
            distances, indices = self._index.search(query, actual_k)
            results = []
            for i in range(actual_k):
                idx = int(indices[0][i])
                sim = float(distances[0][i])
                if idx < 0:
                    continue
                meta = self._metadata[idx] if idx < len(self._metadata) else {}
                results.append({
                    "index": idx,
                    "similarity": sim,
                    "metadata": meta,
                    "above_threshold": sim >= thresh,
                })
            return results
        else:
            # NumPy fallback
            if not self._np_vectors:
                return []
            matrix = np.stack(self._np_vectors)
            matrix = self._normalize(matrix)
            similarities = (matrix @ query.T).flatten()
            top_k_indices = np.argsort(-similarities)[:k]
            results = []
            for idx in top_k_indices:
                sim = float(similarities[idx])
                meta = self._metadata[idx] if idx < len(self._metadata) else {}
                results.append({
                    "index": int(idx),
                    "similarity": sim,
                    "metadata": meta,
                    "above_threshold": sim >= thresh,
                })
            return results

    # ─── Persistence ──────────────────────────────────────────────────────────

    def save(self) -> bool:
        """
        Save the FAISS index and metadata to disk.
        Returns True on success.
        """
        import json

        try:
            os.makedirs(os.path.dirname(self.index_path), exist_ok=True)

            if self._faiss is not None and self._index is not None:
                self._faiss.write_index(self._index, self.index_path)
            else:
                # NumPy fallback: save as .npy
                if self._np_vectors:
                    np.save(self.index_path + ".npy", np.stack(self._np_vectors))

            # Save metadata
            with open(self.meta_path, "w", encoding="utf-8") as fh:
                json.dump(self._metadata, fh, default=str)

            logger.info(
                "FAISSStore: Saved index (%d vectors) to %s",
                self.size,
                self.index_path,
            )
            return True
        except Exception as exc:
            logger.error("FAISSStore: Save failed: %s", exc)
            return False

    def load(self) -> bool:
        """
        Load the FAISS index and metadata from disk.
        Returns True if loaded, False if files not found.
        """
        import json

        try:
            if self._faiss is not None:
                if os.path.exists(self.index_path):
                    self._index = self._faiss.read_index(self.index_path)
                    logger.info(
                        "FAISSStore: Loaded index (%d vectors) from %s",
                        self._index.ntotal,
                        self.index_path,
                    )
                else:
                    return False
            else:
                npy_path = self.index_path + ".npy"
                if os.path.exists(npy_path):
                    matrix = np.load(npy_path)
                    self._np_vectors = [matrix[i] for i in range(len(matrix))]
                else:
                    return False

            # Load metadata
            if os.path.exists(self.meta_path):
                with open(self.meta_path, "r", encoding="utf-8") as fh:
                    self._metadata = json.load(fh)

            return True
        except Exception as exc:
            logger.error("FAISSStore: Load failed: %s", exc)
            return False

    def reset(self) -> None:
        """Clear the index and metadata (in-memory only; does not delete files)."""
        if self._faiss is not None:
            self._index = self._faiss.IndexFlatIP(self.dimension)
        else:
            self._np_vectors = []
        self._metadata = []
        logger.info("FAISSStore: Index reset (0 vectors)")
