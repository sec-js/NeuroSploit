"""
NeuroSploit v3 - Knowledge Management API

Upload, manage, and query custom security knowledge documents.
"""
import os
from typing import Optional, List
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from pydantic import BaseModel

router = APIRouter()

# Lazy-loaded processor instance
_processor = None


def _get_processor():
    global _processor
    if _processor is None:
        from backend.core.knowledge_processor import KnowledgeProcessor
        # Try to get LLM client for AI analysis
        llm = None
        try:
            from backend.core.autonomous_agent import LLMClient
            client = LLMClient()
            if client.is_available():
                llm = client
        except Exception:
            pass
        _processor = KnowledgeProcessor(llm_client=llm)
    return _processor


# --- Schemas ---

class KnowledgeDocumentResponse(BaseModel):
    id: str
    filename: str
    title: str
    source_type: str
    uploaded_at: str
    processed: bool
    file_size_bytes: int
    summary: str
    vuln_types: List[str]
    entries_count: int


class KnowledgeEntryResponse(BaseModel):
    vuln_type: str
    methodology: str = ""
    payloads: List[str] = []
    key_insights: str = ""
    bypass_techniques: List[str] = []
    source_document: str = ""


class KnowledgeStatsResponse(BaseModel):
    total_documents: int
    total_entries: int
    vuln_types_covered: List[str]
    storage_bytes: int


# --- Endpoints ---

@router.post("/upload", response_model=KnowledgeDocumentResponse)
async def upload_knowledge(file: UploadFile = File(...)):
    """Upload a security document for knowledge extraction.
    
    Supported formats: PDF, Markdown (.md), Text (.txt), HTML
    The document will be analyzed and indexed by vulnerability type.
    """
    if not file.filename:
        raise HTTPException(400, "Filename is required")

    # Read file content
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(413, "File too large (max 50MB)")
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    processor = _get_processor()

    try:
        doc = await processor.process_upload(content, file.filename)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Processing failed: {str(e)}")

    return KnowledgeDocumentResponse(
        id=doc["id"],
        filename=doc["filename"],
        title=doc["title"],
        source_type=doc["source_type"],
        uploaded_at=doc["uploaded_at"],
        processed=doc["processed"],
        file_size_bytes=doc["file_size_bytes"],
        summary=doc["summary"],
        vuln_types=doc["vuln_types"],
        entries_count=len(doc.get("knowledge_entries", [])),
    )


@router.get("/documents", response_model=List[KnowledgeDocumentResponse])
async def list_documents():
    """List all indexed knowledge documents."""
    processor = _get_processor()
    docs = processor.get_documents()
    return [
        KnowledgeDocumentResponse(
            id=d["id"],
            filename=d["filename"],
            title=d["title"],
            source_type=d["source_type"],
            uploaded_at=d["uploaded_at"],
            processed=d["processed"],
            file_size_bytes=d["file_size_bytes"],
            summary=d["summary"],
            vuln_types=d["vuln_types"],
            entries_count=d["entries_count"],
        )
        for d in docs
    ]


@router.get("/documents/{doc_id}")
async def get_document(doc_id: str):
    """Get a specific document with its full knowledge entries."""
    processor = _get_processor()
    doc = processor.get_document(doc_id)
    if not doc:
        raise HTTPException(404, f"Document '{doc_id}' not found")
    return doc


@router.delete("/documents/{doc_id}")
async def delete_document(doc_id: str):
    """Delete a knowledge document and its index entries."""
    processor = _get_processor()
    deleted = processor.delete_document(doc_id)
    if not deleted:
        raise HTTPException(404, f"Document '{doc_id}' not found")
    return {"message": f"Document '{doc_id}' deleted", "id": doc_id}


@router.get("/search", response_model=List[KnowledgeEntryResponse])
async def search_knowledge(vuln_type: str = Query(..., description="Vulnerability type to search")):
    """Search knowledge entries by vulnerability type."""
    processor = _get_processor()
    entries = processor.search_by_vuln_type(vuln_type)
    return [
        KnowledgeEntryResponse(
            vuln_type=e.get("vuln_type", ""),
            methodology=e.get("methodology", ""),
            payloads=e.get("payloads", []),
            key_insights=e.get("key_insights", ""),
            bypass_techniques=e.get("bypass_techniques", []),
            source_document=e.get("source_document", ""),
        )
        for e in entries
    ]


@router.get("/stats", response_model=KnowledgeStatsResponse)
async def get_stats():
    """Get knowledge base statistics."""
    processor = _get_processor()
    stats = processor.get_stats()
    return KnowledgeStatsResponse(**stats)
