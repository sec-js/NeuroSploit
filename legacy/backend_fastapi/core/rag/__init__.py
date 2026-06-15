"""
RAG (Retrieval-Augmented Generation) system for NeuroSploitv2.

Enhances AI reasoning by providing relevant context from multiple knowledge
sources without modifying the underlying model. This is a "reasoning amplifier"
that teaches the AI HOW to think about vulnerabilities through:

1. Semantic retrieval from 9000+ bug bounty reports
2. Few-shot examples showing successful exploitation reasoning
3. Chain-of-Thought reasoning templates per vulnerability type
4. Cross-scan reasoning memory (learning from past successes/failures)

Usage:
    from backend.core.rag import RAGEngine, FewShotSelector, ReasoningMemory
    from backend.core.rag.reasoning_templates import format_reasoning_prompt

    # Initialize
    rag = RAGEngine(data_dir="data")
    rag.index_all()  # One-time indexing

    # Get testing context
    context = rag.get_testing_context("xss", technology="PHP")

    # Get few-shot examples
    few_shot = FewShotSelector(rag_engine=rag)
    examples = few_shot.get_testing_examples("sqli", technology="MySQL")

    # Get reasoning framework
    reasoning = format_reasoning_prompt("ssrf")

    # Record success for future learning
    memory = ReasoningMemory()
    memory.record_success(trace)

Backends (auto-selected, best available):
    - ChromaDB + sentence-transformers: Semantic embeddings (best quality)
    - TF-IDF (scikit-learn): Statistical similarity (good quality)
    - BM25 (zero deps): Keyword ranking (works out of box)
"""

from .engine import RAGEngine, RAGContext
from .few_shot import FewShotSelector, FewShotExample
from .reasoning_memory import ReasoningMemory, ReasoningTrace, FailureRecord
from .reasoning_templates import (
    get_reasoning_template,
    format_reasoning_prompt,
    get_available_types,
    REASONING_TEMPLATES
)
from .vectorstore import (
    BaseVectorStore,
    BM25VectorStore,
    RetrievedChunk,
    Document,
    create_vectorstore
)

__all__ = [
    # Core engine
    "RAGEngine",
    "RAGContext",

    # Few-shot selection
    "FewShotSelector",
    "FewShotExample",

    # Reasoning memory
    "ReasoningMemory",
    "ReasoningTrace",
    "FailureRecord",

    # Reasoning templates
    "get_reasoning_template",
    "format_reasoning_prompt",
    "get_available_types",
    "REASONING_TEMPLATES",

    # Vector store
    "BaseVectorStore",
    "BM25VectorStore",
    "RetrievedChunk",
    "Document",
    "create_vectorstore",
]
