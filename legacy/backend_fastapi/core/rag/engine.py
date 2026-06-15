"""
RAG Engine - Retrieval-Augmented Generation for enhanced AI reasoning.

Indexes all knowledge sources (bug bounty reports, vuln KB, custom docs,
reasoning traces) and provides semantic retrieval for context-enriched
LLM prompts. Does NOT modify the model - only augments input context.

Collections:
- bug_bounty_patterns: 9131 real-world vulnerability reports
- vuln_methodologies: 100 vulnerability type methodologies
- custom_knowledge: User-uploaded research documents
- reasoning_traces: Successful reasoning chains from past scans
- attack_patterns: Extracted attack patterns and techniques
"""

import json
import logging
import re
import time
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field

from .vectorstore import (
    BaseVectorStore, Document, RetrievedChunk,
    create_vectorstore
)

logger = logging.getLogger(__name__)

# Collection names
COL_BUG_BOUNTY = "bug_bounty_patterns"
COL_VULN_METHODS = "vuln_methodologies"
COL_CUSTOM = "custom_knowledge"
COL_REASONING = "reasoning_traces"
COL_ATTACK = "attack_patterns"

# Defaults
DEFAULT_TOP_K = 5
MAX_CONTEXT_CHARS = 4000
INDEX_BATCH_SIZE = 200


@dataclass
class RAGContext:
    """Assembled RAG context for a specific query."""
    query: str
    chunks: List[RetrievedChunk] = field(default_factory=list)
    total_score: float = 0.0
    sources_used: List[str] = field(default_factory=list)
    token_estimate: int = 0

    def to_prompt_text(self, max_chars: int = MAX_CONTEXT_CHARS) -> str:
        """Format retrieved context for injection into LLM prompt."""
        if not self.chunks:
            return ""

        sections = []
        current_len = 0

        for chunk in self.chunks:
            source_label = chunk.metadata.get("source_type", chunk.source)
            vuln_type = chunk.metadata.get("vuln_type", "")
            score_pct = int(chunk.score * 100) if chunk.score <= 1.0 else int(chunk.score)

            header = f"[{source_label}]"
            if vuln_type:
                header += f" ({vuln_type})"
            header += f" [relevance: {score_pct}%]"

            text = chunk.text.strip()
            section = f"{header}\n{text}\n"

            if current_len + len(section) > max_chars:
                remaining = max_chars - current_len - len(header) - 20
                if remaining > 100:
                    section = f"{header}\n{text[:remaining]}...\n"
                else:
                    break

            sections.append(section)
            current_len += len(section)

        if not sections:
            return ""

        result = "=== RETRIEVED KNOWLEDGE (RAG) ===\n"
        result += "Use this knowledge to inform your analysis. Adapt techniques to the target.\n\n"
        result += "\n---\n".join(sections)
        result += "\n=== END RETRIEVED KNOWLEDGE ===\n"

        self.token_estimate = len(result) // 4  # rough token estimate
        return result


class RAGEngine:
    """
    Main RAG orchestrator. Indexes knowledge sources and provides
    semantic retrieval for context-enriched AI reasoning.
    """

    def __init__(self, data_dir: str = "data", backend: str = "auto",
                 persist_dir: str = None):
        self.data_dir = Path(data_dir)
        self.persist_dir = persist_dir or str(self.data_dir / "vectorstore")

        self.store: BaseVectorStore = create_vectorstore(
            self.persist_dir, backend=backend
        )

        self._indexed = False
        self._index_stats: Dict[str, int] = {}

        logger.info(f"RAG Engine initialized with '{self.store.backend_name}' backend")

    @property
    def backend_name(self) -> str:
        return self.store.backend_name

    @property
    def is_indexed(self) -> bool:
        return self._indexed

    def get_stats(self) -> Dict:
        """Return indexing statistics."""
        stats = {
            "backend": self.store.backend_name,
            "indexed": self._indexed,
            "collections": {}
        }
        for col_name in [COL_BUG_BOUNTY, COL_VULN_METHODS, COL_CUSTOM,
                         COL_REASONING, COL_ATTACK]:
            count = self.store.collection_count(col_name)
            if count > 0:
                stats["collections"][col_name] = count
        return stats

    # ── Indexing ────────────────────────────────────────────────

    def index_all(self, force: bool = False) -> Dict[str, int]:
        """
        Index all available knowledge sources.
        Returns dict of collection_name -> documents_indexed.
        """
        stats = {}

        # Only re-index if forced or collections are empty
        if not force and self._all_collections_populated():
            logger.info("RAG: All collections already populated, skipping index")
            self._indexed = True
            return stats

        start = time.time()

        stats[COL_BUG_BOUNTY] = self._index_bug_bounty()
        stats[COL_VULN_METHODS] = self._index_vuln_knowledge_base()
        stats[COL_CUSTOM] = self._index_custom_knowledge()
        stats[COL_ATTACK] = self._index_attack_patterns()

        elapsed = time.time() - start
        total = sum(stats.values())
        self._indexed = True
        self._index_stats = stats

        logger.info(f"RAG: Indexed {total} documents across {len(stats)} collections in {elapsed:.1f}s")
        return stats

    def _all_collections_populated(self) -> bool:
        """Check if main collections already have data."""
        return (self.store.collection_exists(COL_BUG_BOUNTY) and
                self.store.collection_exists(COL_VULN_METHODS))

    def _index_bug_bounty(self) -> int:
        """Index the bug bounty finetuning dataset."""
        dataset_path = Path("models/bug-bounty/bugbounty_finetuning_dataset.json")
        if not dataset_path.exists():
            logger.warning(f"RAG: Bug bounty dataset not found at {dataset_path}")
            return 0

        if self.store.collection_exists(COL_BUG_BOUNTY):
            existing = self.store.collection_count(COL_BUG_BOUNTY)
            if existing > 1000:
                logger.info(f"RAG: Bug bounty already indexed ({existing} docs)")
                return 0

        try:
            with open(dataset_path, 'r', encoding='utf-8') as f:
                entries = json.load(f)
        except Exception as e:
            logger.error(f"RAG: Failed to load bug bounty dataset: {e}")
            return 0

        if not isinstance(entries, list):
            return 0

        documents = []
        for i, entry in enumerate(entries):
            instruction = entry.get("instruction", "")
            output = entry.get("output", "")

            if not output or len(output) < 50:
                continue

            # Extract vulnerability types from content
            vuln_types = self._detect_vuln_types(instruction + " " + output)

            # Extract technologies
            technologies = self._detect_technologies(output)

            # Chunk 1: Full methodology (primary chunk)
            methodology = self._extract_section(output, [
                "passos para reproduzir", "steps to reproduce",
                "methodology", "exploitation", "proof of concept",
                "como reproduzir", "reprodução"
            ])

            if methodology and len(methodology) > 100:
                documents.append(Document(
                    text=methodology[:4000],
                    metadata={
                        "source_type": "bug_bounty",
                        "vuln_type": vuln_types[0] if vuln_types else "unknown",
                        "vuln_types": ",".join(vuln_types[:5]),
                        "technologies": ",".join(technologies[:5]),
                        "chunk_type": "methodology",
                        "entry_index": i
                    },
                    doc_id=f"bb_method_{i}"
                ))

            # Chunk 2: Summary + Impact (secondary chunk)
            summary = self._extract_section(output, [
                "resumo", "summary", "descrição", "description",
                "overview"
            ])
            impact = self._extract_section(output, [
                "impacto", "impact", "severity", "risco"
            ])

            summary_text = f"{instruction}\n\n{summary or output[:500]}"
            if impact:
                summary_text += f"\n\nImpact: {impact}"

            documents.append(Document(
                text=summary_text[:3000],
                metadata={
                    "source_type": "bug_bounty",
                    "vuln_type": vuln_types[0] if vuln_types else "unknown",
                    "vuln_types": ",".join(vuln_types[:5]),
                    "technologies": ",".join(technologies[:5]),
                    "chunk_type": "summary",
                    "entry_index": i
                },
                doc_id=f"bb_summary_{i}"
            ))

            # Chunk 3: Payloads & PoC code (if present)
            payloads = self._extract_code_blocks(output)
            if payloads:
                payload_text = f"Vulnerability: {vuln_types[0] if vuln_types else 'unknown'}\n"
                payload_text += f"Technologies: {', '.join(technologies[:3])}\n\n"
                payload_text += "Payloads/PoC:\n" + "\n\n".join(payloads[:10])

                documents.append(Document(
                    text=payload_text[:3000],
                    metadata={
                        "source_type": "bug_bounty",
                        "vuln_type": vuln_types[0] if vuln_types else "unknown",
                        "vuln_types": ",".join(vuln_types[:5]),
                        "technologies": ",".join(technologies[:5]),
                        "chunk_type": "payload",
                        "entry_index": i
                    },
                    doc_id=f"bb_payload_{i}"
                ))

        # Index in batches
        total_added = 0
        for start in range(0, len(documents), INDEX_BATCH_SIZE):
            batch = documents[start:start + INDEX_BATCH_SIZE]
            added = self.store.add(COL_BUG_BOUNTY, batch)
            total_added += added

        logger.info(f"RAG: Indexed {total_added} bug bounty chunks from {len(entries)} entries")
        return total_added

    def _index_vuln_knowledge_base(self) -> int:
        """Index the 100-type vulnerability knowledge base."""
        kb_path = self.data_dir / "vuln_knowledge_base.json"
        if not kb_path.exists():
            return 0

        if self.store.collection_exists(COL_VULN_METHODS):
            existing = self.store.collection_count(COL_VULN_METHODS)
            if existing >= 90:
                return 0

        try:
            with open(kb_path, 'r', encoding='utf-8') as f:
                kb = json.load(f)
        except Exception as e:
            logger.error(f"RAG: Failed to load vuln KB: {e}")
            return 0

        vuln_types = kb.get("vulnerability_types", {})
        if not vuln_types:
            return 0

        documents = []
        for vuln_type, info in vuln_types.items():
            text = f"Vulnerability: {info.get('title', vuln_type)}\n"
            text += f"Type: {vuln_type}\n"
            text += f"CWE: {info.get('cwe_id', 'N/A')}\n"
            text += f"Severity: {info.get('severity', 'N/A')}\n\n"
            text += f"Description: {info.get('description', '')}\n\n"
            text += f"Impact: {info.get('impact', '')}\n\n"
            text += f"Remediation: {info.get('remediation', '')}\n"

            fp_markers = info.get("false_positive_markers", [])
            if fp_markers:
                text += f"\nFalse Positive Indicators: {', '.join(fp_markers)}\n"

            documents.append(Document(
                text=text,
                metadata={
                    "source_type": "vuln_kb",
                    "vuln_type": vuln_type,
                    "severity": info.get("severity", "medium"),
                    "cwe_id": info.get("cwe_id", ""),
                    "chunk_type": "methodology"
                },
                doc_id=f"vkb_{vuln_type}"
            ))

        # Index XBOW insights if available
        xbow = kb.get("xbow_insights", {})
        if xbow:
            for category, insights in xbow.items():
                if isinstance(insights, str):
                    text = f"XBOW Benchmark Insight - {category}:\n{insights}"
                elif isinstance(insights, dict):
                    text = f"XBOW Benchmark Insight - {category}:\n{json.dumps(insights, indent=2)}"
                elif isinstance(insights, list):
                    text = f"XBOW Benchmark Insight - {category}:\n" + "\n".join(str(i) for i in insights)
                else:
                    continue

                documents.append(Document(
                    text=text[:3000],
                    metadata={
                        "source_type": "vuln_kb",
                        "vuln_type": category,
                        "chunk_type": "insight"
                    },
                    doc_id=f"xbow_{category}"
                ))

        added = self.store.add(COL_VULN_METHODS, documents)
        logger.info(f"RAG: Indexed {added} vuln KB entries")
        return added

    def _index_custom_knowledge(self) -> int:
        """Index user-uploaded custom knowledge documents."""
        index_path = self.data_dir / "custom-knowledge" / "index.json"
        if not index_path.exists():
            return 0

        try:
            with open(index_path, 'r', encoding='utf-8') as f:
                index = json.load(f)
        except Exception:
            return 0

        documents = []
        for doc_entry in index.get("documents", []):
            for entry in doc_entry.get("knowledge_entries", []):
                vuln_type = entry.get("vuln_type", "unknown")
                text = f"Custom Knowledge - {vuln_type}\n"
                text += f"Source: {doc_entry.get('filename', 'unknown')}\n\n"

                if entry.get("methodology"):
                    text += f"Methodology: {entry['methodology']}\n\n"
                if entry.get("key_insights"):
                    if isinstance(entry["key_insights"], list):
                        text += "Key Insights:\n" + "\n".join(f"- {i}" for i in entry["key_insights"]) + "\n\n"
                    else:
                        text += f"Key Insights: {entry['key_insights']}\n\n"
                if entry.get("payloads"):
                    payloads = entry["payloads"][:10]
                    text += "Payloads:\n" + "\n".join(f"  {p}" for p in payloads) + "\n\n"
                if entry.get("bypass_techniques"):
                    techniques = entry["bypass_techniques"][:10]
                    text += "Bypass Techniques:\n" + "\n".join(f"- {t}" for t in techniques) + "\n"

                documents.append(Document(
                    text=text[:4000],
                    metadata={
                        "source_type": "custom",
                        "vuln_type": vuln_type,
                        "filename": doc_entry.get("filename", ""),
                        "chunk_type": "methodology"
                    },
                    doc_id=f"custom_{doc_entry.get('id', '')}_{vuln_type}"
                ))

        if not documents:
            return 0

        added = self.store.add(COL_CUSTOM, documents)
        logger.info(f"RAG: Indexed {added} custom knowledge entries")
        return added

    def _index_attack_patterns(self) -> int:
        """Index extracted attack patterns from execution history."""
        hist_path = self.data_dir / "execution_history.json"
        if not hist_path.exists():
            return 0

        try:
            with open(hist_path, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except Exception:
            return 0

        attacks = history.get("attacks", [])
        if not attacks:
            return 0

        # Group successful attacks by vuln_type + tech
        successes: Dict[str, List[Dict]] = {}
        for attack in attacks:
            if not attack.get("success"):
                continue
            key = f"{attack.get('vuln_type', '')}_{attack.get('tech', '')}"
            if key not in successes:
                successes[key] = []
            successes[key].append(attack)

        documents = []
        for key, attack_list in successes.items():
            vuln_type = attack_list[0].get("vuln_type", "unknown")
            tech = attack_list[0].get("tech", "unknown")

            text = f"Successful Attack Pattern: {vuln_type} on {tech}\n"
            text += f"Success count: {len(attack_list)}\n\n"

            for atk in attack_list[:5]:
                evidence = atk.get("evidence_preview", "")
                domain = atk.get("target_domain", "")
                text += f"- Target: {domain}, Evidence: {evidence}\n"

            documents.append(Document(
                text=text[:2000],
                metadata={
                    "source_type": "attack_pattern",
                    "vuln_type": vuln_type,
                    "technology": tech,
                    "success_count": len(attack_list),
                    "chunk_type": "pattern"
                },
                doc_id=f"atk_{key}"
            ))

        if not documents:
            return 0

        added = self.store.add(COL_ATTACK, documents)
        logger.info(f"RAG: Indexed {added} attack patterns")
        return added

    def index_reasoning_trace(self, trace: Dict) -> bool:
        """
        Index a successful reasoning trace for future retrieval.
        Called when a finding is confirmed.

        trace = {
            "vuln_type": str,
            "technology": str,
            "endpoint": str,
            "reasoning_chain": List[str],
            "payload_used": str,
            "evidence": str,
            "confidence": float,
            "timestamp": float
        }
        """
        vuln_type = trace.get("vuln_type", "unknown")
        tech = trace.get("technology", "unknown")

        text = f"Confirmed Reasoning Trace - {vuln_type}\n"
        text += f"Technology: {tech}\n"
        text += f"Endpoint: {trace.get('endpoint', '')}\n"
        text += f"Confidence: {trace.get('confidence', 0):.0%}\n\n"

        chain = trace.get("reasoning_chain", [])
        if chain:
            text += "Reasoning Chain:\n"
            for i, step in enumerate(chain, 1):
                text += f"  {i}. {step}\n"
            text += "\n"

        if trace.get("payload_used"):
            text += f"Payload Used: {trace['payload_used']}\n"
        if trace.get("evidence"):
            text += f"Evidence: {trace['evidence'][:500]}\n"

        doc = Document(
            text=text[:3000],
            metadata={
                "source_type": "reasoning_trace",
                "vuln_type": vuln_type,
                "technology": tech,
                "confidence": trace.get("confidence", 0),
                "chunk_type": "reasoning",
                "timestamp": trace.get("timestamp", time.time())
            },
            doc_id=f"trace_{vuln_type}_{int(time.time())}"
        )

        try:
            self.store.add(COL_REASONING, [doc])
            return True
        except Exception as e:
            logger.warning(f"RAG: Failed to index reasoning trace: {e}")
            return False

    # ── Querying ────────────────────────────────────────────────

    def query(self, query_text: str, collections: List[str] = None,
              top_k: int = DEFAULT_TOP_K,
              vuln_type: str = None,
              technology: str = None,
              chunk_type: str = None) -> RAGContext:
        """
        Query across collections for relevant knowledge.

        Args:
            query_text: The search query
            collections: Which collections to search (default: all)
            top_k: Number of results per collection
            vuln_type: Filter by vulnerability type
            technology: Filter by technology
            chunk_type: Filter by chunk type (methodology, payload, summary, etc.)

        Returns:
            RAGContext with ranked, deduplicated results
        """
        if not collections:
            collections = [COL_BUG_BOUNTY, COL_VULN_METHODS, COL_CUSTOM,
                          COL_REASONING, COL_ATTACK]

        # Build metadata filter
        meta_filter = {}
        if vuln_type:
            meta_filter["vuln_type"] = vuln_type
        if chunk_type:
            meta_filter["chunk_type"] = chunk_type

        all_chunks: List[RetrievedChunk] = []
        sources_used = []

        for col_name in collections:
            if not self.store.collection_exists(col_name):
                continue

            chunks = self.store.query(
                collection=col_name,
                query_text=query_text,
                top_k=top_k,
                metadata_filter=meta_filter if meta_filter else None
            )

            if chunks:
                all_chunks.extend(chunks)
                sources_used.append(col_name)

        # Also search with technology-enhanced query if provided
        if technology and technology not in query_text.lower():
            enhanced_query = f"{query_text} {technology}"
            for col_name in collections:
                if not self.store.collection_exists(col_name):
                    continue
                chunks = self.store.query(
                    collection=col_name,
                    query_text=enhanced_query,
                    top_k=max(2, top_k // 2),
                    metadata_filter=meta_filter if meta_filter else None
                )
                if chunks:
                    all_chunks.extend(chunks)

        # Deduplicate by chunk_id
        seen = set()
        unique_chunks = []
        for chunk in all_chunks:
            if chunk.chunk_id not in seen:
                seen.add(chunk.chunk_id)
                unique_chunks.append(chunk)

        # Sort by relevance score
        unique_chunks.sort(key=lambda c: c.score, reverse=True)

        # Limit total results
        max_results = top_k * 2
        unique_chunks = unique_chunks[:max_results]

        total_score = sum(c.score for c in unique_chunks)

        return RAGContext(
            query=query_text,
            chunks=unique_chunks,
            total_score=total_score,
            sources_used=sources_used
        )

    def get_testing_context(self, vuln_type: str, target_url: str = "",
                            technology: str = "", endpoint: str = "",
                            parameter: str = "",
                            max_chars: int = MAX_CONTEXT_CHARS) -> str:
        """
        Get optimized RAG context for vulnerability testing.
        Combines methodology, real examples, and attack patterns.
        """
        # Build a rich query
        query_parts = [vuln_type.replace("_", " ")]
        if technology:
            query_parts.append(technology)
        if endpoint:
            query_parts.append(f"endpoint {endpoint}")
        if parameter:
            query_parts.append(f"parameter {parameter}")

        query = " ".join(query_parts)

        # Query with vuln_type preference
        context = self.query(
            query_text=query,
            vuln_type=vuln_type,
            technology=technology,
            top_k=5
        )

        # Also get broader results without vuln_type filter
        broad_context = self.query(
            query_text=query,
            technology=technology,
            top_k=3
        )

        # Merge, preferring vuln-specific results
        seen = {c.chunk_id for c in context.chunks}
        for chunk in broad_context.chunks:
            if chunk.chunk_id not in seen:
                context.chunks.append(chunk)
                seen.add(chunk.chunk_id)

        # Re-sort and limit
        context.chunks.sort(key=lambda c: c.score, reverse=True)
        context.chunks = context.chunks[:8]

        return context.to_prompt_text(max_chars=max_chars)

    def get_verification_context(self, vuln_type: str, evidence: str,
                                  technology: str = "",
                                  max_chars: int = 2000) -> str:
        """
        Get RAG context for finding verification/judgment.
        Focuses on confirmed examples and false positive patterns.
        """
        query = f"{vuln_type.replace('_', ' ')} verification proof confirmed {evidence[:200]}"
        if technology:
            query += f" {technology}"

        # Get confirmed reasoning traces
        trace_ctx = self.query(
            query_text=query,
            collections=[COL_REASONING],
            vuln_type=vuln_type,
            top_k=3
        )

        # Get methodology for verification criteria
        method_ctx = self.query(
            query_text=f"{vuln_type} false positive verification criteria proof",
            collections=[COL_VULN_METHODS, COL_BUG_BOUNTY],
            vuln_type=vuln_type,
            chunk_type="methodology",
            top_k=3
        )

        # Combine
        all_chunks = trace_ctx.chunks + method_ctx.chunks
        all_chunks.sort(key=lambda c: c.score, reverse=True)

        combined = RAGContext(
            query=query,
            chunks=all_chunks[:6],
            total_score=sum(c.score for c in all_chunks[:6]),
            sources_used=list(set(trace_ctx.sources_used + method_ctx.sources_used))
        )

        return combined.to_prompt_text(max_chars=max_chars)

    def get_strategy_context(self, technologies: List[str],
                              endpoints: List[str] = None,
                              max_chars: int = 3000) -> str:
        """
        Get RAG context for attack strategy planning.
        Focuses on tech-specific patterns and successful attack history.
        """
        query_parts = ["penetration testing attack strategy"]
        query_parts.extend(technologies[:3])
        if endpoints:
            query_parts.extend(endpoints[:3])

        query = " ".join(query_parts)

        # Get attack patterns
        attack_ctx = self.query(
            query_text=query,
            collections=[COL_ATTACK, COL_BUG_BOUNTY],
            top_k=5
        )

        # Get methodology per technology
        for tech in technologies[:2]:
            tech_ctx = self.query(
                query_text=f"{tech} common vulnerabilities exploitation",
                collections=[COL_BUG_BOUNTY, COL_VULN_METHODS],
                technology=tech,
                top_k=3
            )
            attack_ctx.chunks.extend(tech_ctx.chunks)

        # Deduplicate and sort
        seen = set()
        unique = []
        for c in attack_ctx.chunks:
            if c.chunk_id not in seen:
                seen.add(c.chunk_id)
                unique.append(c)
        unique.sort(key=lambda c: c.score, reverse=True)

        combined = RAGContext(
            query=query,
            chunks=unique[:10],
            total_score=sum(c.score for c in unique[:10]),
            sources_used=attack_ctx.sources_used
        )

        return combined.to_prompt_text(max_chars=max_chars)

    # ── Helpers ─────────────────────────────────────────────────

    def _detect_vuln_types(self, text: str) -> List[str]:
        """Detect vulnerability types mentioned in text."""
        text_lower = text.lower()
        VULN_KEYWORDS = {
            "xss": ["xss", "cross-site scripting", "cross site scripting", "script injection", "reflected xss", "stored xss"],
            "sqli": ["sql injection", "sqli", "sql injeção", "union select", "sqlmap"],
            "ssrf": ["ssrf", "server-side request forgery", "server side request"],
            "idor": ["idor", "insecure direct object", "referência direta"],
            "rce": ["rce", "remote code execution", "command injection", "execução remota", "os command"],
            "lfi": ["lfi", "local file inclusion", "path traversal", "directory traversal", "inclusão de arquivo"],
            "ssti": ["ssti", "server-side template injection", "template injection", "jinja", "twig"],
            "xxe": ["xxe", "xml external entity", "xml injection"],
            "csrf": ["csrf", "cross-site request forgery", "request forgery"],
            "open_redirect": ["open redirect", "redirecionamento aberto", "redirect"],
            "auth_bypass": ["authentication bypass", "auth bypass", "bypass autenticação"],
            "race_condition": ["race condition", "condição de corrida", "toctou"],
            "deserialization": ["deserialization", "deserialização", "unserialize", "pickle"],
            "upload": ["file upload", "upload", "unrestricted upload"],
            "cors": ["cors", "cross-origin"],
            "prototype_pollution": ["prototype pollution", "poluição de protótipo"],
            "request_smuggling": ["request smuggling", "http smuggling", "cl.te", "te.cl"],
            "graphql": ["graphql", "introspection"],
            "jwt": ["jwt", "json web token"],
            "nosql": ["nosql injection", "mongodb injection", "nosql"],
            "crlf": ["crlf injection", "header injection", "injeção de cabeçalho"],
            "subdomain_takeover": ["subdomain takeover", "tomada de subdomínio"],
            "information_disclosure": ["information disclosure", "divulgação de informação", "sensitive data"],
            "bola": ["bola", "broken object level"],
            "bfla": ["bfla", "broken function level"],
            "privilege_escalation": ["privilege escalation", "escalação de privilégio"],
        }

        detected = []
        for vuln_type, keywords in VULN_KEYWORDS.items():
            for kw in keywords:
                if kw in text_lower:
                    detected.append(vuln_type)
                    break

        return detected if detected else ["unknown"]

    def _detect_technologies(self, text: str) -> List[str]:
        """Detect technologies mentioned in text."""
        text_lower = text.lower()
        TECH_KEYWORDS = {
            "php": ["php", "laravel", "wordpress", "drupal", "symfony", "codeigniter"],
            "python": ["python", "django", "flask", "fastapi", "tornado"],
            "java": ["java", "spring", "struts", "tomcat", "jboss", "wildfly"],
            "node": ["node.js", "nodejs", "express", "next.js", "nuxt"],
            "ruby": ["ruby", "rails", "sinatra"],
            "dotnet": [".net", "asp.net", "c#", "iis"],
            "go": ["golang", " go ", "gin", "echo"],
            "nginx": ["nginx"],
            "apache": ["apache", "httpd"],
            "react": ["react", "reactjs"],
            "angular": ["angular"],
            "vue": ["vue.js", "vuejs"],
            "graphql": ["graphql"],
            "docker": ["docker", "kubernetes", "k8s"],
            "aws": ["aws", "amazon", "s3", "lambda", "ec2"],
            "azure": ["azure", "microsoft cloud"],
            "mysql": ["mysql", "mariadb"],
            "postgres": ["postgresql", "postgres"],
            "mongodb": ["mongodb", "mongo"],
            "redis": ["redis"],
        }

        detected = []
        for tech, keywords in TECH_KEYWORDS.items():
            for kw in keywords:
                if kw in text_lower:
                    detected.append(tech)
                    break

        return detected

    def _extract_section(self, text: str, markers: List[str],
                          max_chars: int = 2000) -> Optional[str]:
        """Extract a section from text based on header markers."""
        text_lower = text.lower()

        for marker in markers:
            idx = text_lower.find(marker)
            if idx != -1:
                # Find section start (after the marker line)
                newline_after = text.find("\n", idx)
                if newline_after == -1:
                    continue
                section_start = newline_after + 1

                # Find section end (next ## header or end)
                next_header = re.search(r'\n#{1,3}\s', text[section_start:])
                if next_header:
                    section_end = section_start + next_header.start()
                else:
                    section_end = min(section_start + max_chars, len(text))

                section = text[section_start:section_end].strip()
                if len(section) > 50:
                    return section[:max_chars]

        return None

    def _extract_code_blocks(self, text: str) -> List[str]:
        """Extract code blocks and payloads from text."""
        blocks = []

        # Fenced code blocks
        for match in re.finditer(r'```[\w]*\n(.*?)```', text, re.DOTALL):
            code = match.group(1).strip()
            if len(code) > 20:
                blocks.append(code[:500])

        # Inline code with attack indicators
        for match in re.finditer(r'`([^`]{10,500})`', text):
            code = match.group(1)
            attack_indicators = ['<script', 'alert(', 'SELECT', 'UNION',
                                '../', 'curl ', 'wget ', '{{', '${',
                                'eval(', 'exec(', 'system(']
            if any(ind in code for ind in attack_indicators):
                blocks.append(code)

        return blocks[:20]
