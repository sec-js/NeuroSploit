import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { Upload, FileText, Brain, Search, Trash2, ChevronDown, ChevronUp, BookOpen, RefreshCw, AlertTriangle, CheckCircle2, X, Database } from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'

/* ---------- inline keyframes ---------- */
const styleTag = `
@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(-8px); }
  to   { opacity: 1; transform: translateY(0); }
}
@keyframes refreshSpin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}
`

const API_BASE = '/api/v1/knowledge'
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB
const SUPPORTED_EXTENSIONS = ['.pdf', '.md', '.txt', '.html']
const SUPPORTED_MIME_TYPES = [
  'application/pdf',
  'text/markdown',
  'text/plain',
  'text/html',
]

interface KnowledgeDocument {
  id: string
  filename: string
  title: string
  source_type: string
  uploaded_at: string
  summary: string
  vuln_types: string[]
  entry_count: number
  file_size_bytes: number
}

interface KnowledgeEntry {
  id: string
  vuln_type: string
  category: string
  content: string
  source: string
}

interface KnowledgeDocumentDetail extends KnowledgeDocument {
  knowledge_entries: KnowledgeEntry[]
}

interface KnowledgeStats {
  total_documents: number
  total_entries: number
  vuln_types_covered: string[]
  vuln_type_count: number
}

/* ---------- Toast notification system ---------- */
interface Toast {
  id: number
  message: string
  severity: 'info' | 'success' | 'warning' | 'error'
}

let _toastId = 0

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null
  const border: Record<string, string> = {
    info: 'border-blue-500',
    success: 'border-green-500',
    warning: 'border-yellow-500',
    error: 'border-red-500',
  }
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`bg-dark-800 border-l-4 ${border[t.severity]} rounded-lg px-4 py-3 shadow-xl flex items-start gap-3`}
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <span className="text-sm text-dark-200 flex-1">{t.message}</span>
          <button onClick={() => onDismiss(t.id)} className="text-dark-500 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
    </div>
  )
}

// Assign a consistent color to a vuln type based on its name
const VULN_TYPE_COLORS = [
  { bg: 'bg-purple-500/20', text: 'text-purple-400' },
  { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  { bg: 'bg-green-500/20', text: 'text-green-400' },
  { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  { bg: 'bg-red-500/20', text: 'text-red-400' },
  { bg: 'bg-pink-500/20', text: 'text-pink-400' },
  { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  { bg: 'bg-indigo-500/20', text: 'text-indigo-400' },
  { bg: 'bg-teal-500/20', text: 'text-teal-400' },
  { bg: 'bg-emerald-500/20', text: 'text-emerald-400' },
  { bg: 'bg-violet-500/20', text: 'text-violet-400' },
]

function getVulnTypeColor(vulnType: string) {
  let hash = 0
  for (let i = 0; i < vulnType.length; i++) {
    hash = vulnType.charCodeAt(i) + ((hash << 5) - hash)
  }
  const index = Math.abs(hash) % VULN_TYPE_COLORS.length
  return VULN_TYPE_COLORS[index]
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

const SOURCE_TYPE_STYLES: Record<string, { bg: string; text: string }> = {
  pdf: { bg: 'bg-red-500/15', text: 'text-red-400' },
  markdown: { bg: 'bg-blue-500/15', text: 'text-blue-400' },
  text: { bg: 'bg-green-500/15', text: 'text-green-400' },
  html: { bg: 'bg-orange-500/15', text: 'text-orange-400' },
}

function getSourceTypeBadge(sourceType: string) {
  const style = SOURCE_TYPE_STYLES[sourceType] || { bg: 'bg-dark-600', text: 'text-dark-300' }
  return style
}

const ENTRY_CATEGORY_ICONS: Record<string, string> = {
  methodology: 'Strategy & approach',
  payloads: 'Attack payloads',
  insights: 'Key observations',
  bypass: 'WAF/filter bypass techniques',
  detection: 'Detection patterns',
  remediation: 'Fix guidance',
  reference: 'Reference material',
}

export default function KnowledgePage() {
  const [stats, setStats] = useState<KnowledgeStats | null>(null)
  const [documents, setDocuments] = useState<KnowledgeDocument[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [filterVulnType, setFilterVulnType] = useState<string>('')
  const [expandedDocId, setExpandedDocId] = useState<string | null>(null)
  const [expandedDocDetail, setExpandedDocDetail] = useState<KnowledgeDocumentDetail | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [isDragOver, setIsDragOver] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [toasts, setToasts] = useState<Toast[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)

  /* ---------- Toast helpers ---------- */
  const addToast = useCallback((message: string, severity: Toast['severity']) => {
    const id = ++_toastId
    setToasts(prev => [...prev, { id, message, severity }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  /* ---------- Derived data ---------- */
  const uniqueCategories = useMemo(() => {
    const cats = new Set<string>()
    documents.forEach(doc => {
      doc.vuln_types.forEach(vt => cats.add(vt))
    })
    return cats.size
  }, [documents])

  const totalEntries = useMemo(() => {
    return documents.reduce((sum, doc) => sum + doc.entry_count, 0)
  }, [documents])

  /* ---------- Data fetching ---------- */
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/stats`)
      if (res.ok) {
        const data = await res.json()
        setStats(data)
      }
    } catch (err) {
      console.error('Failed to fetch knowledge stats:', err)
    }
  }, [])

  const fetchDocuments = useCallback(async (vulnType?: string) => {
    setLoading(true)
    try {
      const url = vulnType
        ? `${API_BASE}/search?vuln_type=${encodeURIComponent(vulnType)}`
        : `${API_BASE}/documents`
      const res = await fetch(url)
      if (res.ok) {
        const data = await res.json()
        // search endpoint returns { results, count }, documents returns array
        setDocuments(vulnType ? data.results : data)
      }
    } catch (err) {
      console.error('Failed to fetch knowledge documents:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchAll = useCallback(() => {
    fetchStats()
    fetchDocuments(filterVulnType || undefined)
  }, [fetchStats, fetchDocuments, filterVulnType])

  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    await Promise.all([fetchStats(), fetchDocuments(filterVulnType || undefined)])
    setRefreshing(false)
  }, [fetchStats, fetchDocuments, filterVulnType])

  useEffect(() => {
    fetchStats()
    fetchDocuments()
  }, [fetchStats, fetchDocuments])

  // Auto-dismiss messages after 5 seconds
  useEffect(() => {
    if (message) {
      const timer = setTimeout(() => setMessage(null), 5000)
      return () => clearTimeout(timer)
    }
  }, [message])

  const handleFilterChange = useCallback((vulnType: string) => {
    setFilterVulnType(vulnType)
    setExpandedDocId(null)
    setExpandedDocDetail(null)
    fetchDocuments(vulnType || undefined)
  }, [fetchDocuments])

  const validateFile = useCallback((file: File): string | null => {
    if (file.size > MAX_FILE_SIZE) {
      return `File "${file.name}" exceeds 10MB limit (${formatFileSize(file.size)})`
    }
    const ext = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!SUPPORTED_EXTENSIONS.includes(ext) && !SUPPORTED_MIME_TYPES.includes(file.type)) {
      return `Unsupported file type "${ext}". Supported: PDF, MD, TXT, HTML`
    }
    return null
  }, [])

  const uploadFile = useCallback(async (file: File) => {
    const validationError = validateFile(file)
    if (validationError) {
      setMessage({ type: 'error', text: validationError })
      addToast(validationError, 'error')
      return
    }

    setUploading(true)
    setMessage(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      const res = await fetch(`${API_BASE}/upload`, {
        method: 'POST',
        body: formData,
      })

      if (res.ok) {
        const data = await res.json()
        const successMsg = data.message || `"${file.name}" uploaded and processed successfully`
        setMessage({ type: 'success', text: successMsg })
        addToast(successMsg, 'success')
        fetchAll()
      } else {
        const errData = await res.json().catch(() => null)
        const errMsg = errData?.detail || `Failed to upload "${file.name}"`
        setMessage({ type: 'error', text: errMsg })
        addToast(errMsg, 'error')
      }
    } catch (err) {
      const errMsg = `Upload failed: ${err instanceof Error ? err.message : 'Network error'}`
      setMessage({ type: 'error', text: errMsg })
      addToast(errMsg, 'error')
    } finally {
      setUploading(false)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
    }
  }, [validateFile, addToast, fetchAll])

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) uploadFile(file)
  }, [uploadFile])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragOver(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) uploadFile(file)
  }, [uploadFile])

  const handleDelete = useCallback(async (docId: string) => {
    try {
      const res = await fetch(`${API_BASE}/documents/${docId}`, { method: 'DELETE' })
      if (res.ok) {
        setMessage({ type: 'success', text: 'Document deleted successfully' })
        addToast('Document deleted successfully', 'success')
        setDeleteConfirm(null)
        if (expandedDocId === docId) {
          setExpandedDocId(null)
          setExpandedDocDetail(null)
        }
        fetchAll()
      } else {
        setMessage({ type: 'error', text: 'Failed to delete document' })
        addToast('Failed to delete document', 'error')
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to delete document' })
      addToast('Failed to delete document', 'error')
    }
  }, [expandedDocId, addToast, fetchAll])

  const toggleExpand = useCallback(async (docId: string) => {
    if (expandedDocId === docId) {
      setExpandedDocId(null)
      setExpandedDocDetail(null)
      return
    }

    setExpandedDocId(docId)
    setExpandedDocDetail(null)
    setLoadingDetail(true)

    try {
      const res = await fetch(`${API_BASE}/documents/${docId}`)
      if (res.ok) {
        const data = await res.json()
        setExpandedDocDetail(data)
      }
    } catch (err) {
      console.error('Failed to fetch document detail:', err)
    } finally {
      setLoadingDetail(false)
    }
  }, [expandedDocId])

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Inline keyframes */}
      <style>{styleTag}</style>

      {/* Toast notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <Brain className="w-6 h-6 text-purple-400" />
            </div>
            Knowledge Base
          </h2>
          <p className="text-dark-400 mt-1 ml-14">
            Upload and manage vulnerability research, methodologies, and attack knowledge
          </p>
        </div>
        <Button variant="secondary" onClick={handleRefresh} disabled={refreshing}>
          <RefreshCw
            className="w-4 h-4 mr-2"
            style={refreshing ? { animation: 'refreshSpin 0.8s linear infinite' } : undefined}
          />
          Refresh
        </Button>
      </div>

      {/* Stats Row */}
      <div
        className="grid grid-cols-1 sm:grid-cols-3 gap-4"
        style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
      >
        <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/15 rounded-lg">
              <FileText className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Documents</p>
              <p className="text-2xl font-bold text-white">{stats?.total_documents ?? documents.length}</p>
            </div>
          </div>
        </div>
        <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/15 rounded-lg">
              <Database className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Knowledge Entries</p>
              <p className="text-2xl font-bold text-white">{stats?.total_entries ?? totalEntries}</p>
            </div>
          </div>
        </div>
        <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/15 rounded-lg">
              <BookOpen className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Categories</p>
              <p className="text-2xl font-bold text-white">{stats?.vuln_type_count ?? uniqueCategories}</p>
            </div>
          </div>
          {stats && stats.vuln_types_covered.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-3">
              {stats.vuln_types_covered.slice(0, 8).map(vt => {
                const color = getVulnTypeColor(vt)
                return (
                  <span
                    key={vt}
                    className={`px-2 py-0.5 text-xs rounded-full ${color.bg} ${color.text}`}
                  >
                    {vt}
                  </span>
                )
              })}
              {stats.vuln_types_covered.length > 8 && (
                <span className="px-2 py-0.5 text-xs rounded-full bg-dark-600 text-dark-300">
                  +{stats.vuln_types_covered.length - 8} more
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Status Message */}
      {message && (
        <div
          className={`flex items-center justify-between gap-3 p-4 rounded-lg border transition-all ${
            message.type === 'success'
              ? 'bg-green-500/10 border-green-500/30 text-green-400'
              : 'bg-red-500/10 border-red-500/30 text-red-400'
          }`}
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <div className="flex items-center gap-3">
            {message.type === 'success'
              ? <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
              : <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            }
            <span>{message.text}</span>
          </div>
          <button onClick={() => setMessage(null)} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Upload Area */}
      <div style={{ animation: 'fadeSlideIn 0.4s ease-out' }}>
        <Card title="Upload Knowledge" subtitle="Add vulnerability research documents to the knowledge base">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => !uploading && fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer ${
              isDragOver
                ? 'border-primary-500 bg-primary-500/5'
                : 'border-dark-600 hover:border-primary-500'
            } ${uploading ? 'opacity-60 cursor-wait' : ''}`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf,.md,.txt,.html"
              onChange={handleFileSelect}
              className="hidden"
              disabled={uploading}
            />

            {uploading ? (
              <div className="flex flex-col items-center gap-3">
                <div className="w-12 h-12 rounded-full border-2 border-primary-500 border-t-transparent animate-spin" />
                <p className="text-white font-medium">Processing document...</p>
                <p className="text-dark-400 text-sm">Extracting knowledge entries and indexing vulnerability types</p>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-3">
                <div className="w-14 h-14 bg-dark-700/50 rounded-full flex items-center justify-center">
                  <Upload className="w-7 h-7 text-dark-400" />
                </div>
                <div>
                  <p className="text-white font-medium">
                    {isDragOver ? 'Drop file here' : 'Drag and drop a file here, or click to browse'}
                  </p>
                  <p className="text-dark-400 text-sm mt-1">
                    Supported: PDF, Markdown, TXT, HTML -- Max 10MB
                  </p>
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Filter / Search */}
      <div
        className="flex flex-col sm:flex-row items-start sm:items-center gap-4"
        style={{ animation: 'fadeSlideIn 0.5s ease-out' }}
      >
        <div className="flex items-center gap-2 text-dark-400">
          <Search className="w-4 h-4" />
          <span className="text-sm font-medium">Filter by vulnerability type</span>
        </div>
        <div className="relative flex-1 max-w-xs w-full">
          <select
            value={filterVulnType}
            onChange={(e) => handleFilterChange(e.target.value)}
            className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-2 text-white text-sm appearance-none focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors"
          >
            <option value="">All vulnerability types</option>
            {(stats?.vuln_types_covered || []).map(vt => (
              <option key={vt} value={vt}>{vt}</option>
            ))}
          </select>
          <ChevronDown className="w-4 h-4 text-dark-400 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
        </div>
        {filterVulnType && (
          <button
            onClick={() => handleFilterChange('')}
            className="text-sm text-primary-400 hover:text-primary-300 transition-colors"
          >
            Clear filter
          </button>
        )}
      </div>

      {/* Document List */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">
            Documents
            <span className="text-dark-500 text-sm font-normal ml-2">
              {documents.length} document{documents.length !== 1 ? 's' : ''}
              {filterVulnType && ` matching "${filterVulnType}"`}
            </span>
          </h3>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <RefreshCw className="w-6 h-6 text-dark-400 animate-spin" />
          </div>
        ) : documents.length === 0 ? (
          <Card>
            <div className="text-center py-16" style={{ animation: 'fadeSlideIn 0.4s ease-out' }}>
              <div className="w-20 h-20 bg-dark-700/30 rounded-full flex items-center justify-center mx-auto mb-5">
                <BookOpen className="w-10 h-10 text-dark-500" />
              </div>
              <p className="text-dark-300 font-semibold text-lg">
                {filterVulnType ? 'No documents match this filter' : 'No knowledge documents yet'}
              </p>
              <p className="text-dark-500 text-sm mt-2 max-w-md mx-auto">
                {filterVulnType
                  ? 'Try a different vulnerability type or clear the filter'
                  : 'Upload research papers, writeups, or methodology docs to build your knowledge base'
                }
              </p>
              {!filterVulnType && (
                <Button
                  variant="primary"
                  className="mt-6"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Upload className="w-4 h-4 mr-2" />
                  Upload your first document
                </Button>
              )}
            </div>
          </Card>
        ) : (
          <div className="space-y-3">
            {documents.map((doc, idx) => (
              <div
                key={doc.id}
                className="bg-dark-800 border border-dark-700/50 rounded-xl overflow-hidden hover:border-dark-600 transition-colors"
                style={{ animation: `fadeSlideIn ${0.2 + idx * 0.06}s ease-out` }}
              >
                {/* Document Header */}
                <div className="p-4 sm:p-5">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 sm:gap-4 flex-1 min-w-0">
                      <div className="p-2.5 bg-dark-700/50 rounded-lg flex-shrink-0">
                        <FileText className="w-5 h-5 text-dark-300" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 flex-wrap">
                          <h4 className="font-semibold text-white text-base sm:text-lg truncate">
                            {doc.title || doc.filename}
                          </h4>
                          {(() => {
                            const badge = getSourceTypeBadge(doc.source_type)
                            return (
                              <span className={`px-2.5 py-0.5 text-xs rounded-full font-medium ${badge.bg} ${badge.text} border border-current/20`}>
                                {doc.source_type.toUpperCase()}
                              </span>
                            )
                          })()}
                        </div>

                        {doc.title && doc.title !== doc.filename && (
                          <p className="text-dark-500 text-sm mt-0.5 truncate">{doc.filename}</p>
                        )}

                        {/* Metadata row */}
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-sm text-dark-400">
                          <span>{formatDate(doc.uploaded_at)}</span>
                          <span>{formatFileSize(doc.file_size_bytes)}</span>
                          <span>{doc.entry_count} {doc.entry_count === 1 ? 'entry' : 'entries'}</span>
                        </div>

                        {/* Summary preview */}
                        {doc.summary && (
                          <p className="text-dark-300 text-sm mt-2 line-clamp-2">{doc.summary}</p>
                        )}

                        {/* Vuln type badges */}
                        {doc.vuln_types.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 mt-3">
                            {doc.vuln_types.map(vt => {
                              const color = getVulnTypeColor(vt)
                              return (
                                <span
                                  key={vt}
                                  className={`px-2 py-0.5 text-xs rounded-full ${color.bg} ${color.text}`}
                                >
                                  {vt}
                                </span>
                              )
                            })}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1 flex-shrink-0 ml-4">
                      <button
                        onClick={() => toggleExpand(doc.id)}
                        className="p-2 rounded-lg text-dark-400 hover:text-white hover:bg-dark-700/50 transition-colors"
                        title={expandedDocId === doc.id ? 'Collapse' : 'Expand details'}
                      >
                        {expandedDocId === doc.id
                          ? <ChevronUp className="w-5 h-5" />
                          : <ChevronDown className="w-5 h-5" />
                        }
                      </button>

                      {deleteConfirm === doc.id ? (
                        <div className="flex items-center gap-1">
                          <Button variant="danger" size="sm" onClick={() => handleDelete(doc.id)}>
                            Confirm
                          </Button>
                          <Button variant="ghost" size="sm" onClick={() => setDeleteConfirm(null)}>
                            <span className="text-dark-400 text-xs">Cancel</span>
                          </Button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setDeleteConfirm(doc.id)}
                          className="p-2 rounded-lg text-dark-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                          title="Delete document"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* Expanded Detail */}
                {expandedDocId === doc.id && (
                  <div
                    className="border-t border-dark-700/50 bg-dark-900/50"
                    style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
                  >
                    {loadingDetail ? (
                      <div className="flex items-center justify-center py-12">
                        <RefreshCw className="w-5 h-5 text-dark-400 animate-spin" />
                        <span className="text-dark-400 text-sm ml-3">Loading knowledge entries...</span>
                      </div>
                    ) : expandedDocDetail && expandedDocDetail.knowledge_entries.length > 0 ? (
                      <div className="p-5 space-y-3">
                        <div className="flex items-center gap-2 mb-4">
                          <BookOpen className="w-4 h-4 text-purple-400" />
                          <span className="text-sm font-medium text-white">
                            {expandedDocDetail.knowledge_entries.length} Knowledge {expandedDocDetail.knowledge_entries.length === 1 ? 'Entry' : 'Entries'}
                          </span>
                        </div>

                        {expandedDocDetail.knowledge_entries.map((entry, idx) => {
                          const vulnColor = getVulnTypeColor(entry.vuln_type)
                          const categoryLabel = ENTRY_CATEGORY_ICONS[entry.category] || entry.category

                          return (
                            <div
                              key={entry.id || idx}
                              className="bg-dark-800 border border-dark-700/50 rounded-lg p-4"
                              style={{ animation: `fadeSlideIn ${0.15 + idx * 0.05}s ease-out` }}
                            >
                              <div className="flex items-center gap-2 mb-2 flex-wrap">
                                <span className={`px-2 py-0.5 text-xs rounded-full ${vulnColor.bg} ${vulnColor.text}`}>
                                  {entry.vuln_type}
                                </span>
                                <span className="px-2 py-0.5 text-xs rounded-full bg-dark-600 text-dark-300">
                                  {entry.category}
                                </span>
                                {categoryLabel !== entry.category && (
                                  <span className="text-xs text-dark-500">{categoryLabel}</span>
                                )}
                              </div>
                              <pre className="text-sm text-dark-200 whitespace-pre-wrap font-mono leading-relaxed bg-dark-900/50 rounded-lg p-3 max-h-64 overflow-y-auto">
                                {entry.content}
                              </pre>
                              {entry.source && (
                                <p className="text-xs text-dark-500 mt-2">
                                  Source: {entry.source}
                                </p>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    ) : (
                      <div className="text-center py-12">
                        <p className="text-dark-400 text-sm">No knowledge entries found in this document</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
