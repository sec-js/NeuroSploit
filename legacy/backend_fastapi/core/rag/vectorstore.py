"""
Multi-backend vector store for RAG knowledge retrieval.

Backends (in priority order):
1. ChromaDB + sentence-transformers (semantic embeddings, persistent)
2. TF-IDF via scikit-learn (statistical similarity)
3. BM25 (zero dependencies, keyword-based ranking)

All backends provide the same interface: add(), query(), delete_collection().
"""

import json
import math
import hashlib
import logging
import time
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple

logger = logging.getLogger(__name__)

# Optional dependencies
try:
    import chromadb
    from chromadb.config import Settings as ChromaSettings
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


@dataclass
class RetrievedChunk:
    """A retrieved knowledge chunk with relevance score."""
    text: str
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    chunk_id: str = ""
    source: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Document:
    """A document to be indexed in the vector store."""
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    doc_id: str = ""

    def __post_init__(self):
        if not self.doc_id:
            self.doc_id = hashlib.md5(self.text[:500].encode()).hexdigest()[:12]


class BaseVectorStore(ABC):
    """Abstract vector store interface."""

    @abstractmethod
    def add(self, collection: str, documents: List[Document]) -> int:
        """Add documents to a collection. Returns count added."""
        pass

    @abstractmethod
    def query(self, collection: str, query_text: str, top_k: int = 5,
              metadata_filter: Optional[Dict] = None) -> List[RetrievedChunk]:
        """Query a collection for relevant documents."""
        pass

    @abstractmethod
    def collection_exists(self, collection: str) -> bool:
        """Check if a collection has been indexed."""
        pass

    @abstractmethod
    def delete_collection(self, collection: str) -> None:
        """Delete a collection and all its documents."""
        pass

    @abstractmethod
    def collection_count(self, collection: str) -> int:
        """Return number of documents in a collection."""
        pass

    @property
    @abstractmethod
    def backend_name(self) -> str:
        pass


class BM25VectorStore(BaseVectorStore):
    """
    BM25 (Best Matching 25) keyword-based ranking.
    Zero external dependencies - works with pure Python.
    Good for exact keyword matching and term-frequency scoring.
    """

    def __init__(self, persist_dir: str, k1: float = 1.5, b: float = 0.75):
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.k1 = k1
        self.b = b
        self._collections: Dict[str, Dict] = {}
        self._load_persisted()

    @property
    def backend_name(self) -> str:
        return "bm25"

    def _tokenize(self, text: str) -> List[str]:
        """Simple whitespace + punctuation tokenizer."""
        import re
        text = text.lower()
        tokens = re.findall(r'\b[a-z0-9_]{2,}\b', text)
        return tokens

    def _load_persisted(self):
        """Load persisted collections from disk."""
        index_file = self.persist_dir / "bm25_index.json"
        if index_file.exists():
            try:
                with open(index_file, 'r') as f:
                    data = json.load(f)
                self._collections = data.get("collections", {})
                logger.info(f"BM25: Loaded {len(self._collections)} collections from disk")
            except Exception as e:
                logger.warning(f"BM25: Failed to load index: {e}")
                self._collections = {}

    def _persist(self):
        """Persist collections to disk."""
        index_file = self.persist_dir / "bm25_index.json"
        try:
            with open(index_file, 'w') as f:
                json.dump({"collections": self._collections, "timestamp": time.time()}, f)
        except Exception as e:
            logger.warning(f"BM25: Failed to persist index: {e}")

    def add(self, collection: str, documents: List[Document]) -> int:
        if not documents:
            return 0

        if collection not in self._collections:
            self._collections[collection] = {
                "documents": [],
                "doc_freqs": [],
                "df": {},
                "doc_lengths": [],
                "avgdl": 0,
                "N": 0
            }

        col = self._collections[collection]

        added = 0
        existing_ids = {d.get("doc_id", "") for d in col["documents"]}

        for doc in documents:
            if doc.doc_id in existing_ids:
                continue

            tokens = self._tokenize(doc.text)
            token_freq = dict(Counter(tokens))
            unique_tokens = set(tokens)

            col["documents"].append({
                "doc_id": doc.doc_id,
                "text": doc.text[:5000],  # Cap storage
                "metadata": doc.metadata
            })
            col["doc_freqs"].append(token_freq)
            col["doc_lengths"].append(len(tokens))

            for token in unique_tokens:
                col["df"][token] = col["df"].get(token, 0) + 1

            added += 1

        col["N"] = len(col["documents"])
        col["avgdl"] = sum(col["doc_lengths"]) / max(col["N"], 1)

        if added > 0:
            self._persist()

        return added

    def query(self, collection: str, query_text: str, top_k: int = 5,
              metadata_filter: Optional[Dict] = None) -> List[RetrievedChunk]:
        if collection not in self._collections:
            return []

        col = self._collections[collection]
        if col["N"] == 0:
            return []

        query_tokens = self._tokenize(query_text)
        if not query_tokens:
            return []

        scores = []
        N = col["N"]
        avgdl = col["avgdl"]

        for i in range(N):
            # Metadata filter
            if metadata_filter:
                doc_meta = col["documents"][i].get("metadata", {})
                skip = False
                for key, val in metadata_filter.items():
                    if isinstance(val, list):
                        if doc_meta.get(key) not in val:
                            skip = True
                            break
                    elif doc_meta.get(key) != val:
                        skip = True
                        break
                if skip:
                    scores.append(0.0)
                    continue

            doc_freq = col["doc_freqs"][i]
            doc_len = col["doc_lengths"][i]
            score = 0.0

            for token in query_tokens:
                if token not in doc_freq:
                    continue

                tf = doc_freq[token]
                df = col["df"].get(token, 0)

                # BM25 IDF
                idf = math.log((N - df + 0.5) / (df + 0.5) + 1.0)

                # BM25 TF normalization
                tf_norm = (tf * (self.k1 + 1)) / (
                    tf + self.k1 * (1.0 - self.b + self.b * doc_len / avgdl)
                )

                score += idf * tf_norm

            scores.append(score)

        # Get top-k
        indexed_scores = [(i, s) for i, s in enumerate(scores) if s > 0]
        indexed_scores.sort(key=lambda x: x[1], reverse=True)

        results = []
        for i, score in indexed_scores[:top_k]:
            doc = col["documents"][i]
            results.append(RetrievedChunk(
                text=doc["text"],
                score=score,
                metadata=doc.get("metadata", {}),
                chunk_id=doc.get("doc_id", f"doc_{i}"),
                source=collection
            ))

        return results

    def collection_exists(self, collection: str) -> bool:
        return collection in self._collections and self._collections[collection]["N"] > 0

    def delete_collection(self, collection: str) -> None:
        if collection in self._collections:
            del self._collections[collection]
            self._persist()

    def collection_count(self, collection: str) -> int:
        if collection not in self._collections:
            return 0
        return self._collections[collection]["N"]


class TFIDFVectorStore(BaseVectorStore):
    """
    TF-IDF based vector store using scikit-learn.
    Better than BM25 for capturing document-level similarity.
    Requires: scikit-learn, numpy
    """

    def __init__(self, persist_dir: str):
        if not HAS_SKLEARN or not HAS_NUMPY:
            raise ImportError("TF-IDF backend requires scikit-learn and numpy")

        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self._collections: Dict[str, Dict] = {}

    @property
    def backend_name(self) -> str:
        return "tfidf"

    def add(self, collection: str, documents: List[Document]) -> int:
        if not documents:
            return 0

        if collection not in self._collections:
            self._collections[collection] = {
                "documents": [],
                "texts": [],
                "vectorizer": None,
                "matrix": None
            }

        col = self._collections[collection]
        existing_ids = {d.get("doc_id", "") for d in col["documents"]}

        added = 0
        for doc in documents:
            if doc.doc_id in existing_ids:
                continue
            col["documents"].append({
                "doc_id": doc.doc_id,
                "text": doc.text[:5000],
                "metadata": doc.metadata
            })
            col["texts"].append(doc.text[:5000])
            added += 1

        if added > 0:
            # Rebuild TF-IDF matrix
            vectorizer = TfidfVectorizer(
                max_features=10000,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=1,
                max_df=0.95
            )
            col["matrix"] = vectorizer.fit_transform(col["texts"])
            col["vectorizer"] = vectorizer

        return added

    def query(self, collection: str, query_text: str, top_k: int = 5,
              metadata_filter: Optional[Dict] = None) -> List[RetrievedChunk]:
        if collection not in self._collections:
            return []

        col = self._collections[collection]
        if col["vectorizer"] is None or col["matrix"] is None:
            return []

        query_vec = col["vectorizer"].transform([query_text])
        similarities = cosine_similarity(query_vec, col["matrix"]).flatten()

        # Apply metadata filter
        if metadata_filter:
            for i, doc in enumerate(col["documents"]):
                meta = doc.get("metadata", {})
                for key, val in metadata_filter.items():
                    if isinstance(val, list):
                        if meta.get(key) not in val:
                            similarities[i] = 0.0
                    elif meta.get(key) != val:
                        similarities[i] = 0.0

        top_indices = np.argsort(similarities)[::-1][:top_k]

        results = []
        for i in top_indices:
            if similarities[i] <= 0:
                continue
            doc = col["documents"][i]
            results.append(RetrievedChunk(
                text=doc["text"],
                score=float(similarities[i]),
                metadata=doc.get("metadata", {}),
                chunk_id=doc.get("doc_id", f"doc_{i}"),
                source=collection
            ))

        return results

    def collection_exists(self, collection: str) -> bool:
        return (collection in self._collections and
                len(self._collections[collection]["documents"]) > 0)

    def delete_collection(self, collection: str) -> None:
        if collection in self._collections:
            del self._collections[collection]

    def collection_count(self, collection: str) -> int:
        if collection not in self._collections:
            return 0
        return len(self._collections[collection]["documents"])


class ChromaVectorStore(BaseVectorStore):
    """
    ChromaDB + sentence-transformers for true semantic embeddings.
    Best quality: understands meaning, not just keywords.
    Requires: chromadb, sentence-transformers
    """

    DEFAULT_MODEL = "all-MiniLM-L6-v2"  # Fast, 384-dim, good quality

    def __init__(self, persist_dir: str, model_name: str = None):
        if not HAS_CHROMADB:
            raise ImportError("ChromaDB backend requires: pip install chromadb")

        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self.client = chromadb.PersistentClient(
            path=str(self.persist_dir / "chromadb")
        )

        # Embedding model
        self._embed_model = None
        self._model_name = model_name or self.DEFAULT_MODEL
        if HAS_SENTENCE_TRANSFORMERS:
            try:
                self._embed_model = SentenceTransformer(self._model_name)
                logger.info(f"ChromaDB: Loaded embedding model '{self._model_name}'")
            except Exception as e:
                logger.warning(f"ChromaDB: Failed to load model: {e}")

    @property
    def backend_name(self) -> str:
        return "chromadb"

    def _get_collection(self, name: str):
        """Get or create a ChromaDB collection."""
        if self._embed_model:
            return self.client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"}
            )
        else:
            return self.client.get_or_create_collection(name=name)

    def _embed(self, texts: List[str]) -> Optional[List[List[float]]]:
        """Generate embeddings using sentence-transformers."""
        if not self._embed_model:
            return None
        try:
            embeddings = self._embed_model.encode(texts, show_progress_bar=False)
            return embeddings.tolist()
        except Exception as e:
            logger.warning(f"ChromaDB: Embedding failed: {e}")
            return None

    def add(self, collection: str, documents: List[Document]) -> int:
        if not documents:
            return 0

        col = self._get_collection(collection)

        # Filter already-indexed docs
        existing = set()
        try:
            result = col.get()
            if result and result.get("ids"):
                existing = set(result["ids"])
        except Exception:
            pass

        new_docs = [d for d in documents if d.doc_id not in existing]
        if not new_docs:
            return 0

        # Batch add (ChromaDB limit: 41666 per batch)
        batch_size = 500
        added = 0

        for start in range(0, len(new_docs), batch_size):
            batch = new_docs[start:start + batch_size]

            ids = [d.doc_id for d in batch]
            texts = [d.text[:5000] for d in batch]
            metadatas = []
            for d in batch:
                # ChromaDB metadata must be str/int/float/bool
                meta = {}
                for k, v in d.metadata.items():
                    if isinstance(v, (str, int, float, bool)):
                        meta[k] = v
                    elif isinstance(v, list):
                        meta[k] = ",".join(str(x) for x in v)
                    else:
                        meta[k] = str(v)
                metadatas.append(meta)

            embeddings = self._embed(texts)

            try:
                if embeddings:
                    col.add(
                        ids=ids,
                        documents=texts,
                        metadatas=metadatas,
                        embeddings=embeddings
                    )
                else:
                    col.add(
                        ids=ids,
                        documents=texts,
                        metadatas=metadatas
                    )
                added += len(batch)
            except Exception as e:
                logger.warning(f"ChromaDB: Failed to add batch: {e}")

        return added

    def query(self, collection: str, query_text: str, top_k: int = 5,
              metadata_filter: Optional[Dict] = None) -> List[RetrievedChunk]:
        try:
            col = self._get_collection(collection)
        except Exception:
            return []

        if col.count() == 0:
            return []

        # Build ChromaDB where clause
        where = None
        if metadata_filter:
            conditions = []
            for key, val in metadata_filter.items():
                if isinstance(val, list):
                    conditions.append({key: {"$in": val}})
                else:
                    conditions.append({key: {"$eq": val}})
            if len(conditions) == 1:
                where = conditions[0]
            elif len(conditions) > 1:
                where = {"$and": conditions}

        # Query with embeddings if available
        query_embedding = self._embed([query_text])

        try:
            if query_embedding:
                results = col.query(
                    query_embeddings=query_embedding,
                    n_results=min(top_k, col.count()),
                    where=where
                )
            else:
                results = col.query(
                    query_texts=[query_text],
                    n_results=min(top_k, col.count()),
                    where=where
                )
        except Exception as e:
            logger.warning(f"ChromaDB query failed: {e}")
            return []

        chunks = []
        if results and results.get("documents"):
            docs = results["documents"][0]
            ids = results["ids"][0] if results.get("ids") else [""] * len(docs)
            distances = results["distances"][0] if results.get("distances") else [0.0] * len(docs)
            metadatas = results["metadatas"][0] if results.get("metadatas") else [{}] * len(docs)

            for text, doc_id, distance, meta in zip(docs, ids, distances, metadatas):
                # ChromaDB returns distance (lower = better), convert to similarity score
                score = max(0.0, 1.0 - distance)
                chunks.append(RetrievedChunk(
                    text=text,
                    score=score,
                    metadata=meta or {},
                    chunk_id=doc_id,
                    source=collection
                ))

        return chunks

    def collection_exists(self, collection: str) -> bool:
        try:
            col = self.client.get_collection(collection)
            return col.count() > 0
        except Exception:
            return False

    def delete_collection(self, collection: str) -> None:
        try:
            self.client.delete_collection(collection)
        except Exception:
            pass

    def collection_count(self, collection: str) -> int:
        try:
            col = self.client.get_collection(collection)
            return col.count()
        except Exception:
            return 0


def create_vectorstore(persist_dir: str, backend: str = "auto") -> BaseVectorStore:
    """
    Factory function to create the best available vector store.

    Args:
        persist_dir: Directory for persistent storage
        backend: "auto" (best available), "chromadb", "tfidf", or "bm25"

    Returns:
        Configured vector store instance
    """
    if backend == "chromadb" or (backend == "auto" and HAS_CHROMADB):
        try:
            store = ChromaVectorStore(persist_dir)
            logger.info(f"RAG: Using ChromaDB backend (semantic embeddings)")
            return store
        except Exception as e:
            logger.warning(f"RAG: ChromaDB init failed: {e}, falling back")

    if backend == "tfidf" or (backend == "auto" and HAS_SKLEARN):
        try:
            store = TFIDFVectorStore(persist_dir)
            logger.info(f"RAG: Using TF-IDF backend (statistical similarity)")
            return store
        except Exception as e:
            logger.warning(f"RAG: TF-IDF init failed: {e}, falling back")

    store = BM25VectorStore(persist_dir)
    logger.info(f"RAG: Using BM25 backend (keyword ranking)")
    return store
