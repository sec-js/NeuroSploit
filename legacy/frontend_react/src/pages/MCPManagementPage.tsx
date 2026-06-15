import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Plus, Trash2, RefreshCw, Server, Wifi, Terminal, Pencil,
  ChevronDown, ChevronRight, CheckCircle2, AlertTriangle, X,
  Wrench, Plug, Loader2
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'

/* ------------------------------------------------------------------ */
/*  Inline keyframes                                                   */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface MCPServer {
  name: string
  transport: 'stdio' | 'sse'
  command?: string
  args?: string[]
  url?: string
  env?: Record<string, string>
  description?: string
  enabled: boolean
  is_builtin: boolean
  tool_count: number
}

interface MCPTool {
  name: string
  description: string
  input_schema: Record<string, unknown>
}

interface TestResult {
  success: boolean
  message: string
}

/* ------------------------------------------------------------------ */
/*  Toast notification system                                          */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Delete Confirmation Modal                                          */
/* ------------------------------------------------------------------ */

function DeleteModal({ name, onConfirm, onCancel }: {
  name: string
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={onCancel}>
      <div
        className="bg-dark-800 rounded-xl border border-dark-700 p-6 max-w-sm w-full"
        onClick={e => e.stopPropagation()}
        style={{ animation: 'fadeSlideIn 0.2s ease-out' }}
      >
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 rounded-lg bg-red-500/10">
            <Trash2 className="w-5 h-5 text-red-400" />
          </div>
          <h3 className="text-lg font-semibold text-white">Delete Server</h3>
        </div>
        <p className="text-sm text-dark-300 mb-6">
          Are you sure you want to delete <span className="text-white font-medium">&quot;{name}&quot;</span>?
          This cannot be undone.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onCancel}>Cancel</Button>
          <Button variant="danger" onClick={onConfirm}>
            <Trash2 className="w-4 h-4 mr-2" />
            Delete
          </Button>
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Sub-components                                                     */
/* ------------------------------------------------------------------ */

function ToggleSwitch({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={onToggle}
      className={`w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-primary-500' : 'bg-dark-700'}`}
    >
      <div className={`w-5 h-5 bg-white rounded-full shadow-md transform transition-transform ${enabled ? 'translate-x-6' : 'translate-x-0.5'}`} />
    </button>
  )
}

function TransportBadge({ transport }: { transport: 'stdio' | 'sse' }) {
  return (
    <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${
      transport === 'stdio'
        ? 'bg-blue-500/20 text-blue-400'
        : 'bg-purple-500/20 text-purple-400'
    }`}>
      {transport === 'stdio' ? (
        <span className="inline-flex items-center gap-1"><Terminal className="w-3 h-3" />stdio</span>
      ) : (
        <span className="inline-flex items-center gap-1"><Wifi className="w-3 h-3" />sse</span>
      )}
    </span>
  )
}

/* ------------------------------------------------------------------ */
/*  Tool param extractor                                               */
/* ------------------------------------------------------------------ */

function getToolParams(schema: Record<string, unknown>): string[] {
  if (!schema || typeof schema !== 'object') return []
  const props = schema.properties
  if (!props || typeof props !== 'object') return []
  return Object.keys(props as Record<string, unknown>)
}

/* ------------------------------------------------------------------ */
/*  Main Component                                                     */
/* ------------------------------------------------------------------ */

export default function MCPManagementPage() {
  // Server list
  const [servers, setServers] = useState<MCPServer[]>([])
  const [loading, setLoading] = useState(true)

  // Modal
  const [showModal, setShowModal] = useState(false)
  const [editingServer, setEditingServer] = useState<MCPServer | null>(null)

  // Form state
  const [formName, setFormName] = useState('')
  const [formTransport, setFormTransport] = useState<'stdio' | 'sse'>('stdio')
  const [formCommand, setFormCommand] = useState('')
  const [formArgs, setFormArgs] = useState('')
  const [formUrl, setFormUrl] = useState('')
  const [formEnv, setFormEnv] = useState('')
  const [formDescription, setFormDescription] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Test results  { serverName: TestResult }
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({})
  const [testingServer, setTestingServer] = useState<string | null>(null)

  // Expanded tool browser
  const [expandedServer, setExpandedServer] = useState<string | null>(null)
  const [serverTools, setServerTools] = useState<Record<string, MCPTool[]>>({})
  const [loadingTools, setLoadingTools] = useState<string | null>(null)

  // Toast system
  const [toasts, setToasts] = useState<Toast[]>([])

  // Delete confirmation
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  // Refresh animation
  const [refreshing, setRefreshing] = useState(false)

  /* ---------------------------------------------------------------- */
  /*  Toast helpers                                                    */
  /* ---------------------------------------------------------------- */

  const addToast = useCallback((message: string, severity: Toast['severity']) => {
    const id = ++_toastId
    setToasts(prev => [...prev, { id, message, severity }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  /* ---------------------------------------------------------------- */
  /*  Derived data                                                     */
  /* ---------------------------------------------------------------- */

  const enabledCount = useMemo(() => servers.filter(s => s.enabled).length, [servers])
  const totalTools = useMemo(() => servers.reduce((sum, s) => sum + s.tool_count, 0), [servers])

  /* ---------------------------------------------------------------- */
  /*  Data fetching                                                    */
  /* ---------------------------------------------------------------- */

  const fetchServers = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/v1/mcp/servers')
      if (res.ok) {
        const data = await res.json()
        setServers(data.servers ?? [])
      }
    } catch (err) {
      console.error('Failed to fetch MCP servers:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    try {
      const res = await fetch('/api/v1/mcp/servers')
      if (res.ok) {
        const data = await res.json()
        setServers(data.servers ?? [])
      }
    } catch (err) {
      console.error('Failed to fetch MCP servers:', err)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchServers()
  }, [fetchServers])

  /* ---------------------------------------------------------------- */
  /*  CRUD handlers                                                    */
  /* ---------------------------------------------------------------- */

  const parseEnvVars = useCallback((raw: string): Record<string, string> | undefined => {
    const lines = raw.split('\n').map(l => l.trim()).filter(Boolean)
    if (lines.length === 0) return undefined
    const env: Record<string, string> = {}
    for (const line of lines) {
      const idx = line.indexOf('=')
      if (idx > 0) {
        env[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
      }
    }
    return Object.keys(env).length > 0 ? env : undefined
  }, [])

  const handleSave = useCallback(async () => {
    if (!formName.trim()) {
      addToast('Server name is required', 'error')
      return
    }
    if (formTransport === 'stdio' && !formCommand.trim()) {
      addToast('Command is required for stdio transport', 'error')
      return
    }
    if (formTransport === 'sse' && !formUrl.trim()) {
      addToast('URL is required for SSE transport', 'error')
      return
    }

    setIsSaving(true)

    const body: Record<string, unknown> = {
      name: formName.trim(),
      transport: formTransport,
      description: formDescription.trim() || undefined,
      env: parseEnvVars(formEnv),
    }
    if (formTransport === 'stdio') {
      body.command = formCommand.trim()
      body.args = formArgs.trim() ? formArgs.trim().split(/\s+/) : undefined
    } else {
      body.url = formUrl.trim()
    }

    const isEdit = !!editingServer
    const url = isEdit
      ? `/api/v1/mcp/servers/${encodeURIComponent(editingServer.name)}`
      : '/api/v1/mcp/servers'
    const method = isEdit ? 'PUT' : 'POST'

    try {
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (res.ok) {
        addToast(`Server "${formName}" ${isEdit ? 'updated' : 'created'} successfully`, 'success')
        closeModal()
        fetchServers()
      } else {
        const data = await res.json().catch(() => ({}))
        const detail = (data as Record<string, string>).detail
        addToast(detail || `Failed to ${isEdit ? 'update' : 'create'} server`, 'error')
      }
    } catch {
      addToast(`Failed to ${isEdit ? 'update' : 'create'} server`, 'error')
    } finally {
      setIsSaving(false)
    }
  }, [formName, formTransport, formCommand, formArgs, formUrl, formEnv, formDescription, editingServer, parseEnvVars, addToast, fetchServers])

  const handleDelete = useCallback(async (name: string) => {
    try {
      const res = await fetch(`/api/v1/mcp/servers/${encodeURIComponent(name)}`, { method: 'DELETE' })
      if (res.ok) {
        addToast(`Server "${name}" deleted`, 'success')
        setDeleteTarget(null)
        fetchServers()
      } else {
        const data = await res.json().catch(() => ({}))
        const detail = (data as Record<string, string>).detail
        addToast(detail || `Failed to delete "${name}"`, 'error')
      }
    } catch {
      addToast(`Failed to delete "${name}"`, 'error')
    }
  }, [addToast, fetchServers])

  const handleToggle = useCallback(async (name: string) => {
    try {
      const res = await fetch(`/api/v1/mcp/servers/${encodeURIComponent(name)}/toggle`, { method: 'POST' })
      if (res.ok) {
        fetchServers()
      } else {
        addToast(`Failed to toggle "${name}"`, 'error')
      }
    } catch {
      addToast(`Failed to toggle "${name}"`, 'error')
    }
  }, [addToast, fetchServers])

  const handleTest = useCallback(async (name: string) => {
    setTestingServer(name)
    setTestResults(prev => {
      const next = { ...prev }
      delete next[name]
      return next
    })

    try {
      const res = await fetch(`/api/v1/mcp/servers/${encodeURIComponent(name)}/test`, { method: 'POST' })
      if (res.ok) {
        const data: TestResult = await res.json()
        setTestResults(prev => ({ ...prev, [name]: data }))
        addToast(data.success ? `"${name}" connected successfully` : `"${name}" test failed: ${data.message}`, data.success ? 'success' : 'error')
      } else {
        setTestResults(prev => ({ ...prev, [name]: { success: false, message: 'Test request failed' } }))
        addToast(`Test request for "${name}" failed`, 'error')
      }
    } catch {
      setTestResults(prev => ({ ...prev, [name]: { success: false, message: 'Network error' } }))
      addToast(`Network error testing "${name}"`, 'error')
    } finally {
      setTestingServer(null)
    }
  }, [addToast])

  /* ---------------------------------------------------------------- */
  /*  Tool browser                                                     */
  /* ---------------------------------------------------------------- */

  const toggleToolBrowser = useCallback(async (name: string) => {
    if (expandedServer === name) {
      setExpandedServer(null)
      return
    }
    setExpandedServer(name)

    if (serverTools[name]) return // already loaded

    setLoadingTools(name)
    try {
      const res = await fetch(`/api/v1/mcp/servers/${encodeURIComponent(name)}/tools`)
      if (res.ok) {
        const data = await res.json()
        setServerTools(prev => ({ ...prev, [name]: data.tools ?? [] }))
      }
    } catch {
      console.error('Failed to fetch tools for', name)
    } finally {
      setLoadingTools(null)
    }
  }, [expandedServer, serverTools])

  /* ---------------------------------------------------------------- */
  /*  Modal helpers                                                    */
  /* ---------------------------------------------------------------- */

  const openAddModal = useCallback(() => {
    setEditingServer(null)
    setFormName('')
    setFormTransport('stdio')
    setFormCommand('')
    setFormArgs('')
    setFormUrl('')
    setFormEnv('')
    setFormDescription('')
    setShowModal(true)
  }, [])

  const openEditModal = useCallback((server: MCPServer) => {
    setEditingServer(server)
    setFormName(server.name)
    setFormTransport(server.transport)
    setFormCommand(server.command ?? '')
    setFormArgs(server.args?.join(' ') ?? '')
    setFormUrl(server.url ?? '')
    setFormEnv(
      server.env
        ? Object.entries(server.env).map(([k, v]) => `${k}=${v}`).join('\n')
        : ''
    )
    setFormDescription(server.description ?? '')
    setShowModal(true)
  }, [])

  const closeModal = useCallback(() => {
    setShowModal(false)
    setEditingServer(null)
  }, [])

  /* ---------------------------------------------------------------- */
  /*  Render                                                           */
  /* ---------------------------------------------------------------- */

  return (
    <>
      {/* Inline keyframes */}
      <style>{styleTag}</style>

      {/* Toast notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="space-y-6 animate-fadeIn">
        {/* Header */}
        <div
          className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              <div className="p-2 bg-brand-500/20 rounded-lg">
                <Plug className="w-6 h-6 text-brand-400" />
              </div>
              MCP Servers
            </h2>
            <p className="text-dark-400 mt-1 ml-14">Manage Model Context Protocol server connections and tools</p>
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw
                className="w-4 h-4 mr-2"
                style={refreshing ? { animation: 'refreshSpin 0.8s linear infinite' } : undefined}
              />
              Refresh
            </Button>
            <Button onClick={openAddModal}>
              <Plus className="w-4 h-4 mr-2" />
              Add Server
            </Button>
          </div>
        </div>

        {/* Summary Stats */}
        {servers.length > 0 && (
          <div
            className="grid grid-cols-1 sm:grid-cols-3 gap-4"
            style={{ animation: 'fadeSlideIn 0.35s ease-out' }}
          >
            <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-500/15 rounded-lg">
                  <Server className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-dark-400 text-sm">Total Servers</p>
                  <p className="text-2xl font-bold text-white">{servers.length}</p>
                </div>
              </div>
            </div>
            <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-500/15 rounded-lg">
                  <CheckCircle2 className="w-5 h-5 text-green-400" />
                </div>
                <div>
                  <p className="text-dark-400 text-sm">Enabled</p>
                  <p className="text-2xl font-bold text-green-400">{enabledCount}</p>
                </div>
              </div>
            </div>
            <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-brand-500/15 rounded-lg">
                  <Wrench className="w-5 h-5 text-brand-400" />
                </div>
                <div>
                  <p className="text-dark-400 text-sm">Total Tools</p>
                  <p className="text-2xl font-bold text-brand-400">{totalTools}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Server List */}
        <div style={{ animation: 'fadeSlideIn 0.4s ease-out' }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">
              Configured Servers
              <span className="text-dark-500 text-sm font-normal ml-2">
                {servers.length} server{servers.length !== 1 ? 's' : ''}
              </span>
            </h3>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16">
              <RefreshCw className="w-6 h-6 text-dark-400 animate-spin" />
            </div>
          ) : servers.length === 0 ? (
            <Card>
              <div className="text-center py-16" style={{ animation: 'fadeSlideIn 0.4s ease-out' }}>
                <div className="w-20 h-20 bg-dark-700/30 rounded-full flex items-center justify-center mx-auto mb-5">
                  <Server className="w-10 h-10 text-dark-500" />
                </div>
                <p className="text-dark-300 font-semibold text-lg">No MCP servers configured</p>
                <p className="text-dark-500 text-sm mt-2 max-w-md mx-auto">
                  Add a server to connect external tools via Model Context Protocol
                </p>
                <Button className="mt-6" onClick={openAddModal}>
                  <Plus className="w-4 h-4 mr-2" />
                  Add First Server
                </Button>
              </div>
            </Card>
          ) : (
            <div className="space-y-3">
              {servers.map((server, idx) => (
                <div
                  key={server.name}
                  className="bg-dark-800 border border-dark-700/50 rounded-xl overflow-hidden hover:border-dark-600 transition-colors"
                  style={{ animation: `fadeSlideIn ${0.2 + idx * 0.06}s ease-out` }}
                >
                  {/* Server Row */}
                  <div className="p-4 sm:p-5">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3 sm:gap-4 flex-1 min-w-0">
                        {/* Icon */}
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
                          server.enabled ? 'bg-green-500/15' : 'bg-dark-700/50'
                        }`}>
                          <Server className={`w-5 h-5 ${server.enabled ? 'text-green-400' : 'text-dark-500'}`} />
                        </div>

                        <div className="flex-1 min-w-0">
                          {/* Name + badges */}
                          <div className="flex items-center gap-3 flex-wrap">
                            <p className="font-semibold text-white text-base sm:text-lg truncate">{server.name}</p>
                            <TransportBadge transport={server.transport} />
                            {server.is_builtin && (
                              <span className="px-2 py-0.5 text-xs rounded-full bg-yellow-500/20 text-yellow-400 font-medium">
                                builtin
                              </span>
                            )}
                            <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${
                              server.enabled
                                ? 'bg-green-500/15 text-green-400 border border-green-500/30'
                                : 'bg-dark-700 text-dark-400 border border-dark-600'
                            }`}>
                              {server.enabled ? 'enabled' : 'disabled'}
                            </span>
                          </div>

                          {/* Description */}
                          {server.description && (
                            <p className="text-sm text-dark-400 mt-1">{server.description}</p>
                          )}

                          {/* Meta row */}
                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-sm text-dark-400">
                            {server.transport === 'stdio' && server.command && (
                              <span className="flex items-center gap-1.5">
                                <Terminal className="w-3.5 h-3.5" />
                                <code className="text-dark-300 text-xs bg-dark-900/50 px-1.5 py-0.5 rounded">
                                  {server.command}{server.args?.length ? ` ${server.args.join(' ')}` : ''}
                                </code>
                              </span>
                            )}
                            {server.transport === 'sse' && server.url && (
                              <span className="flex items-center gap-1.5">
                                <Wifi className="w-3.5 h-3.5" />
                                <code className="text-dark-300 text-xs bg-dark-900/50 px-1.5 py-0.5 rounded">
                                  {server.url}
                                </code>
                              </span>
                            )}
                            <span className="flex items-center gap-1.5">
                              <Wrench className="w-3.5 h-3.5" />
                              {server.tool_count} tool{server.tool_count !== 1 ? 's' : ''}
                            </span>
                          </div>

                          {/* Env vars indicator */}
                          {server.env && Object.keys(server.env).length > 0 && (
                            <div className="flex flex-wrap gap-1.5 mt-2">
                              {Object.keys(server.env).map(key => (
                                <span key={key} className="px-1.5 py-0.5 text-[10px] bg-dark-700 text-dark-400 rounded font-mono">
                                  {key}
                                </span>
                              ))}
                            </div>
                          )}

                          {/* Test result badge */}
                          {testResults[server.name] && (
                            <div className={`inline-flex items-center gap-1.5 mt-2 px-3 py-1 rounded-lg text-xs font-medium ${
                              testResults[server.name].success
                                ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                                : 'bg-red-500/10 text-red-400 border border-red-500/30'
                            }`}
                              style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
                            >
                              {testResults[server.name].success
                                ? <CheckCircle2 className="w-3.5 h-3.5" />
                                : <AlertTriangle className="w-3.5 h-3.5" />
                              }
                              {testResults[server.name].message}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                        {/* Toggle */}
                        <ToggleSwitch enabled={server.enabled} onToggle={() => handleToggle(server.name)} />

                        {/* Tool browser toggle */}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => toggleToolBrowser(server.name)}
                          title="Browse tools"
                        >
                          {expandedServer === server.name
                            ? <ChevronDown className="w-4 h-4 text-brand-400" />
                            : <ChevronRight className="w-4 h-4 text-dark-400" />
                          }
                        </Button>

                        {/* Test */}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleTest(server.name)}
                          disabled={testingServer === server.name}
                          title="Test connection"
                        >
                          {testingServer === server.name
                            ? <Loader2 className="w-4 h-4 text-dark-400 animate-spin" />
                            : <Plug className="w-4 h-4 text-blue-400" />
                          }
                        </Button>

                        {/* Edit */}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEditModal(server)}
                          title="Edit server"
                        >
                          <Pencil className="w-4 h-4 text-dark-300" />
                        </Button>

                        {/* Delete */}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(server.name)}
                          disabled={server.is_builtin}
                          title={server.is_builtin ? 'Cannot delete builtin server' : 'Delete server'}
                        >
                          <Trash2 className={`w-4 h-4 ${server.is_builtin ? 'text-dark-600' : 'text-red-400'}`} />
                        </Button>
                      </div>
                    </div>
                  </div>

                  {/* Expandable Tool Browser */}
                  {expandedServer === server.name && (
                    <div
                      className="border-t border-dark-700/50 bg-dark-900/30 p-4"
                      style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
                    >
                      <h4 className="text-sm font-medium text-dark-200 mb-3 flex items-center gap-2">
                        <Wrench className="w-4 h-4 text-brand-400" />
                        Available Tools
                        {serverTools[server.name] && (
                          <span className="text-dark-500 font-normal">({serverTools[server.name].length})</span>
                        )}
                      </h4>

                      {loadingTools === server.name ? (
                        <div className="flex items-center justify-center py-8">
                          <Loader2 className="w-5 h-5 text-dark-400 animate-spin" />
                          <span className="text-dark-400 text-sm ml-3">Loading tools...</span>
                        </div>
                      ) : serverTools[server.name]?.length ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {serverTools[server.name].map((tool, tIdx) => (
                            <div
                              key={tool.name}
                              className="p-3 bg-dark-800 border border-dark-700/50 rounded-lg hover:border-dark-600 transition-colors"
                              style={{ animation: `fadeSlideIn ${0.15 + tIdx * 0.04}s ease-out` }}
                            >
                              <div className="flex items-start gap-2">
                                <Wrench className="w-3.5 h-3.5 text-brand-400 flex-shrink-0 mt-0.5" />
                                <div className="min-w-0">
                                  <p className="text-sm font-medium text-white truncate">{tool.name}</p>
                                  {tool.description && (
                                    <p className="text-xs text-dark-400 mt-0.5 line-clamp-2">{tool.description}</p>
                                  )}
                                  {tool.input_schema && Object.keys(tool.input_schema).length > 0 && (
                                    <div className="flex flex-wrap gap-1 mt-1.5">
                                      {getToolParams(tool.input_schema).slice(0, 4).map(param => (
                                        <span key={param} className="px-1.5 py-0.5 text-[10px] bg-dark-700 text-dark-300 rounded">
                                          {param}
                                        </span>
                                      ))}
                                      {getToolParams(tool.input_schema).length > 4 && (
                                        <span className="px-1.5 py-0.5 text-[10px] bg-dark-700 text-dark-400 rounded">
                                          +{getToolParams(tool.input_schema).length - 4}
                                        </span>
                                      )}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-center py-8">
                          <div className="w-12 h-12 bg-dark-700/30 rounded-full flex items-center justify-center mx-auto mb-3">
                            <Wrench className="w-6 h-6 text-dark-500" />
                          </div>
                          <p className="text-sm text-dark-500">No tools available or server not connected</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Add / Edit Modal */}
        {showModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Backdrop */}
            <div
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
              onClick={closeModal}
            />

            {/* Modal Panel */}
            <div
              className="relative w-full max-w-lg bg-dark-800 border border-dark-700 rounded-xl shadow-2xl mx-4 max-h-[90vh] overflow-y-auto"
              style={{ animation: 'fadeSlideIn 0.2s ease-out' }}
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between p-5 border-b border-dark-700">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-brand-500/15">
                    {editingServer
                      ? <Pencil className="w-5 h-5 text-brand-400" />
                      : <Plus className="w-5 h-5 text-brand-400" />
                    }
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">
                      {editingServer ? 'Edit Server' : 'Add MCP Server'}
                    </h3>
                    <p className="text-dark-400 text-sm mt-0.5">
                      {editingServer
                        ? `Editing "${editingServer.name}" configuration`
                        : 'Configure a new Model Context Protocol server connection'
                      }
                    </p>
                  </div>
                </div>
                <button
                  onClick={closeModal}
                  className="p-1.5 rounded-lg text-dark-400 hover:text-white hover:bg-dark-700 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Modal Body */}
              <div className="p-5 space-y-5">
                {/* Name */}
                <Input
                  label="Server Name"
                  placeholder="my-mcp-server"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  disabled={!!editingServer}
                  helperText={editingServer ? 'Name cannot be changed after creation' : 'Unique identifier for this server'}
                />

                {/* Transport */}
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-2">Transport</label>
                  <div className="flex gap-3">
                    <button
                      onClick={() => setFormTransport('stdio')}
                      className={`flex-1 flex items-center gap-3 p-3 rounded-lg border-2 transition-all ${
                        formTransport === 'stdio'
                          ? 'border-brand-500 bg-brand-500/10'
                          : 'border-dark-600 bg-dark-900/50 hover:border-dark-500'
                      }`}
                    >
                      <Terminal className={`w-5 h-5 ${formTransport === 'stdio' ? 'text-brand-400' : 'text-dark-400'}`} />
                      <div className="text-left">
                        <p className={`text-sm font-medium ${formTransport === 'stdio' ? 'text-white' : 'text-dark-300'}`}>stdio</p>
                        <p className="text-xs text-dark-500">Local process</p>
                      </div>
                    </button>
                    <button
                      onClick={() => setFormTransport('sse')}
                      className={`flex-1 flex items-center gap-3 p-3 rounded-lg border-2 transition-all ${
                        formTransport === 'sse'
                          ? 'border-brand-500 bg-brand-500/10'
                          : 'border-dark-600 bg-dark-900/50 hover:border-dark-500'
                      }`}
                    >
                      <Wifi className={`w-5 h-5 ${formTransport === 'sse' ? 'text-brand-400' : 'text-dark-400'}`} />
                      <div className="text-left">
                        <p className={`text-sm font-medium ${formTransport === 'sse' ? 'text-white' : 'text-dark-300'}`}>sse</p>
                        <p className="text-xs text-dark-500">Remote HTTP</p>
                      </div>
                    </button>
                  </div>
                </div>

                {/* Transport-specific fields */}
                {formTransport === 'stdio' ? (
                  <div className="space-y-4">
                    <Input
                      label="Command"
                      placeholder="npx"
                      value={formCommand}
                      onChange={(e) => setFormCommand(e.target.value)}
                      helperText="The executable to run (e.g. npx, python, node)"
                    />
                    <Input
                      label="Arguments"
                      placeholder="-y @modelcontextprotocol/server-filesystem /tmp"
                      value={formArgs}
                      onChange={(e) => setFormArgs(e.target.value)}
                      helperText="Space-separated command arguments"
                    />
                  </div>
                ) : (
                  <Input
                    label="Server URL"
                    placeholder="http://localhost:3001/sse"
                    value={formUrl}
                    onChange={(e) => setFormUrl(e.target.value)}
                    helperText="Full URL to the SSE endpoint"
                  />
                )}

                {/* Environment Variables */}
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">
                    Environment Variables
                  </label>
                  <textarea
                    className="w-full px-4 py-2.5 bg-dark-900 border border-dark-700 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors font-mono text-sm resize-y min-h-[80px]"
                    placeholder={'API_KEY=your-key-here\nANOTHER_VAR=value'}
                    value={formEnv}
                    onChange={(e) => setFormEnv(e.target.value)}
                    rows={3}
                  />
                  <p className="mt-1 text-sm text-dark-400">One KEY=VALUE per line. Passed to the server process.</p>
                </div>

                {/* Description */}
                <Input
                  label="Description"
                  placeholder="What this server provides..."
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  helperText="Optional description for this server"
                />
              </div>

              {/* Modal Footer */}
              <div className="flex items-center justify-end gap-3 p-5 border-t border-dark-700">
                <Button variant="secondary" onClick={closeModal}>
                  Cancel
                </Button>
                <Button onClick={handleSave} isLoading={isSaving}>
                  {editingServer ? (
                    <>
                      <Pencil className="w-4 h-4 mr-2" />
                      Update Server
                    </>
                  ) : (
                    <>
                      <Plus className="w-4 h-4 mr-2" />
                      Add Server
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Delete Confirmation Modal */}
        {deleteTarget && (
          <DeleteModal
            name={deleteTarget}
            onConfirm={() => handleDelete(deleteTarget)}
            onCancel={() => setDeleteTarget(null)}
          />
        )}
      </div>
    </>
  )
}
