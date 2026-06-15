import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Plug,
  RefreshCw,
  Search,
  CheckCircle,
  XCircle,
  Trash2,
  TestTube,
  Key,
  Wifi,
  Loader2,
  X,
  Plus,
  AlertCircle,
  Activity,
  Zap,
  Clock,
  Shield,
} from 'lucide-react'

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

const API = '/api/v1/providers'

/* ---------- Types ---------- */

interface Account {
  id: string
  label: string
  source: string
  credential_type: string
  is_active: boolean
  tokens_used: number
  last_used: string | null
  expires_at: number | null
  model_override: string | null
}

interface Provider {
  id: string
  name: string
  auth_type: string
  api_format: string
  tier: number
  default_model: string
  accounts: Account[]
  connected: boolean
  enabled: boolean
}

interface ProviderStatus {
  enabled: boolean
  total_requests: number
  total_tokens: number
}

/* ---------- Toast notification system ---------- */

interface Toast {
  id: number
  message: string
  type: 'success' | 'error' | 'info'
}

let _toastId = 0

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null
  const borderColor: Record<string, string> = {
    info: 'border-blue-500',
    success: 'border-green-500',
    error: 'border-red-500',
  }
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`bg-dark-800 border-l-4 ${borderColor[t.type]} rounded-lg px-4 py-3 shadow-xl flex items-start gap-3`}
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

/* ---------- Provider visual config ---------- */

const PROVIDER_COLORS: Record<string, string> = {
  claude_code: 'bg-orange-500',
  codex_cli: 'bg-green-500',
  gemini_cli: 'bg-blue-400',
  cursor: 'bg-purple-500',
  copilot: 'bg-gray-500',
  iflow: 'bg-cyan-400',
  qwen_code: 'bg-indigo-500',
  kiro: 'bg-yellow-500',
  anthropic: 'bg-orange-600',
  openai: 'bg-emerald-600',
  gemini: 'bg-blue-500',
  openrouter: 'bg-violet-500',
  glm: 'bg-red-500',
  kimi: 'bg-pink-500',
  minimax: 'bg-amber-500',
  together: 'bg-teal-500',
  fireworks: 'bg-rose-500',
  ollama: 'bg-gray-600',
  lmstudio: 'bg-slate-500',
}

const PROVIDER_INITIALS: Record<string, string> = {
  claude_code: 'CC',
  codex_cli: 'CX',
  gemini_cli: 'GC',
  cursor: 'CU',
  copilot: 'CP',
  iflow: 'iF',
  qwen_code: 'QC',
  kiro: 'KI',
  anthropic: 'AN',
  openai: 'OA',
  gemini: 'GM',
  openrouter: 'OR',
  glm: 'GL',
  kimi: 'KM',
  minimax: 'MM',
  together: 'TG',
  fireworks: 'FW',
  ollama: 'OL',
  lmstudio: 'LS',
}

const TIER_LABELS: Record<number, string> = {
  1: 'Tier 1',
  2: 'Tier 2 - Budget',
  3: 'Tier 3 - Free',
}

const TIER_COLORS: Record<number, string> = {
  1: 'text-yellow-400 bg-yellow-400/10',
  2: 'text-blue-400 bg-blue-400/10',
  3: 'text-green-400 bg-green-400/10',
}

/* ---------- Helpers ---------- */

function relativeTime(dateStr: string | null): string {
  if (!dateStr) return 'Never'
  const now = Date.now()
  const then = new Date(dateStr).getTime()
  const diff = now - then
  if (diff < 0) return 'Just now'
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return 'Just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  return `${months}mo ago`
}

function formatExpiryTime(expiresAt: number | null): { label: string; isExpired: boolean; urgency: string } {
  if (!expiresAt) return { label: '', isExpired: false, urgency: '' }
  const nowSec = Date.now() / 1000
  const diff = expiresAt - nowSec
  if (diff <= 0) return { label: 'Expired', isExpired: true, urgency: 'text-red-400' }
  const minutes = Math.floor(diff / 60)
  if (minutes < 60) return { label: `${minutes}m left`, isExpired: false, urgency: 'text-yellow-400' }
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return { label: `${hours}h left`, isExpired: false, urgency: hours < 2 ? 'text-yellow-400' : 'text-green-400' }
  const days = Math.floor(hours / 24)
  return { label: `${days}d left`, isExpired: false, urgency: 'text-green-400' }
}

/* ---------- Main Component ---------- */

export default function ProvidersPage() {
  const [providers, setProviders] = useState<Provider[]>([])
  const [enabled, setEnabled] = useState(false)
  const [loading, setLoading] = useState(true)
  const [detecting, setDetecting] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [selectedProvider, setSelectedProvider] = useState<Provider | null>(null)
  const [status, setStatus] = useState<ProviderStatus | null>(null)
  const [showEnvEditor, setShowEnvEditor] = useState(false)
  const [envVars, setEnvVars] = useState<Record<string, string>>({})
  const [envAllowedKeys, setEnvAllowedKeys] = useState<string[]>([])
  const [envEditing, setEnvEditing] = useState<Record<string, string>>({})
  const [envSaving, setEnvSaving] = useState<string | null>(null)
  const [envSearch, setEnvSearch] = useState('')
  const [toasts, setToasts] = useState<Toast[]>([])

  /* ---------- Toast helpers ---------- */
  const addToast = useCallback((message: string, type: Toast['type']) => {
    const id = ++_toastId
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  /* ---------- Data fetching ---------- */
  const fetchProviders = useCallback(async () => {
    try {
      const res = await fetch(API)
      const data = await res.json()
      setEnabled(data.enabled)
      setProviders(data.providers || [])
    } catch {
      setEnabled(false)
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/status`)
      const data: ProviderStatus = await res.json()
      setStatus(data)
    } catch {
      // ignore
    }
  }, [])

  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    await Promise.all([fetchProviders(), fetchStatus()])
    setRefreshing(false)
  }, [fetchProviders, fetchStatus])

  useEffect(() => {
    fetchProviders()
    fetchStatus()
  }, [fetchProviders, fetchStatus])

  /* ---------- Derived data ---------- */
  const oauthProviders = useMemo(
    () => providers.filter((p) => p.auth_type === 'oauth'),
    [providers]
  )

  const apiKeyProviders = useMemo(
    () => providers.filter((p) => p.auth_type === 'api_key'),
    [providers]
  )

  const connectedCount = useMemo(
    () => providers.filter((p) => p.connected).length,
    [providers]
  )

  const totalTokensUsed = useMemo(
    () => providers.reduce((sum, p) => sum + p.accounts.reduce((s, a) => s + a.tokens_used, 0), 0),
    [providers]
  )

  const totalAccounts = useMemo(
    () => providers.reduce((sum, p) => sum + p.accounts.length, 0),
    [providers]
  )

  const filteredEnvKeys = useMemo(() => {
    if (!envSearch.trim()) return envAllowedKeys
    const q = envSearch.toLowerCase()
    return envAllowedKeys.filter(k => k.toLowerCase().includes(q))
  }, [envAllowedKeys, envSearch])

  /* ---------- Handlers ---------- */
  const handleDetectAll = useCallback(async () => {
    setDetecting(true)
    try {
      const res = await fetch(`${API}/detect-all`, { method: 'POST' })
      const data = await res.json()
      if (data.detected_count > 0) {
        await fetchProviders()
        addToast(`Detected ${data.detected_count} CLI token(s)`, 'success')
      } else {
        addToast('No new CLI tokens detected', 'info')
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error'
      addToast(`Detection failed: ${msg}`, 'error')
    } finally {
      setDetecting(false)
    }
  }, [fetchProviders, addToast])

  const handleToggleProvider = useCallback(async (providerId: string, currentEnabled: boolean) => {
    try {
      const res = await fetch(`${API}/${providerId}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !currentEnabled }),
      })
      if (res.ok) {
        setProviders(prev => prev.map(p =>
          p.id === providerId ? { ...p, enabled: !currentEnabled } : p
        ))
        addToast(`Provider ${!currentEnabled ? 'enabled' : 'disabled'}`, 'success')
      }
    } catch {
      addToast('Failed to toggle provider', 'error')
    }
  }, [addToast])

  const fetchEnvVars = useCallback(async () => {
    try {
      const res = await fetch(`${API}/env`)
      const data = await res.json()
      setEnvVars(data.env || {})
      setEnvAllowedKeys(data.allowed_keys || [])
      setEnvEditing({ ...data.env })
    } catch {
      addToast('Failed to load environment variables', 'error')
    }
  }, [addToast])

  const handleSaveEnvVar = useCallback(async (key: string) => {
    setEnvSaving(key)
    try {
      const res = await fetch(`${API}/env`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value: envEditing[key] || '' }),
      })
      if (res.ok) {
        setEnvVars(prev => ({ ...prev, [key]: envEditing[key] || '' }))
        addToast(`Saved ${key}`, 'success')
      }
    } catch {
      addToast(`Failed to save ${key}`, 'error')
    }
    setEnvSaving(null)
  }, [envEditing, addToast])

  const handleEnvEditorToggle = useCallback(() => {
    setShowEnvEditor(prev => {
      if (!prev) fetchEnvVars()
      return !prev
    })
  }, [fetchEnvVars])

  const handleEnvEditingChange = useCallback((key: string, value: string) => {
    setEnvEditing(prev => ({ ...prev, [key]: value }))
  }, [])

  const handleSelectProvider = useCallback((p: Provider) => {
    setSelectedProvider(p)
  }, [])

  const handleCloseModal = useCallback(() => {
    setSelectedProvider(null)
    fetchProviders()
  }, [fetchProviders])

  /* ---------- Render ---------- */

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <Loader2 className="w-8 h-8 animate-spin text-primary-500" />
        <span className="text-dark-400 text-sm">Loading providers...</span>
      </div>
    )
  }

  return (
    <>
      {/* Inline keyframes */}
      <style>{styleTag}</style>

      {/* Toast notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="space-y-6">
        {/* Header */}
        <div
          className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <div className="p-2 bg-primary-500/20 rounded-lg">
                <Plug className="w-6 h-6 text-primary-400" />
              </div>
              LLM Providers
            </h1>
            <p className="text-dark-400 mt-1 ml-14">
              {enabled
                ? `Smart Router active -- ${connectedCount}/${providers.length} providers connected`
                : 'Smart Router disabled. Set ENABLE_SMART_ROUTER=true in .env'}
            </p>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            {status?.enabled && (
              <div className="text-sm text-dark-400 flex items-center gap-3">
                <span className="flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-primary-400" />
                  <span className="text-primary-400">{status.total_requests || 0}</span> requests
                </span>
                <span className="flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-primary-400" />
                  <span className="text-primary-400">{(status.total_tokens || 0).toLocaleString()}</span> tokens
                </span>
              </div>
            )}
            <button
              onClick={handleDetectAll}
              disabled={!enabled || detecting}
              className="btn-secondary flex items-center gap-2"
            >
              {detecting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Search className="w-4 h-4" />
              )}
              Detect All CLIs
            </button>
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="btn-secondary flex items-center gap-2"
            >
              <RefreshCw
                className="w-4 h-4"
                style={refreshing ? { animation: 'refreshSpin 0.8s linear infinite' } : undefined}
              />
              Refresh
            </button>
          </div>
        </div>

        {/* Disabled Banner */}
        {!enabled && (
          <div
            className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-center gap-3"
            style={{ animation: 'fadeSlideIn 0.35s ease-out' }}
          >
            <AlertCircle className="w-5 h-5 text-yellow-500 flex-shrink-0" />
            <div>
              <p className="text-yellow-400 font-medium">Smart Router is disabled</p>
              <p className="text-dark-400 text-sm">
                Add <code className="bg-dark-700 px-1.5 py-0.5 rounded text-xs font-mono">ENABLE_SMART_ROUTER=true</code> to your .env file and restart the server.
              </p>
            </div>
          </div>
        )}

        {/* Summary Stats */}
        {providers.length > 0 && (
          <div
            className="grid grid-cols-1 sm:grid-cols-4 gap-4"
            style={{ animation: 'fadeSlideIn 0.4s ease-out' }}
          >
            <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-500/15 rounded-lg">
                  <Plug className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-dark-400 text-sm">Providers</p>
                  <p className="text-2xl font-bold text-white">{providers.length}</p>
                </div>
              </div>
            </div>
            <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-500/15 rounded-lg">
                  <CheckCircle className="w-5 h-5 text-green-400" />
                </div>
                <div>
                  <p className="text-dark-400 text-sm">Connected</p>
                  <p className="text-2xl font-bold text-green-400">{connectedCount}</p>
                </div>
              </div>
            </div>
            <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-500/15 rounded-lg">
                  <Shield className="w-5 h-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-dark-400 text-sm">Accounts</p>
                  <p className="text-2xl font-bold text-white">{totalAccounts}</p>
                </div>
              </div>
            </div>
            <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary-500/15 rounded-lg">
                  <Zap className="w-5 h-5 text-primary-400" />
                </div>
                <div>
                  <p className="text-dark-400 text-sm">Total Tokens</p>
                  <p className="text-2xl font-bold text-primary-400">{totalTokensUsed.toLocaleString()}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* OAuth Providers Grid */}
        {oauthProviders.length > 0 && (
          <div style={{ animation: 'fadeSlideIn 0.45s ease-out' }}>
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Wifi className="w-5 h-5 text-blue-400" />
              OAuth Providers
              <span className="text-xs text-dark-500 font-normal ml-1">CLI Token Detection</span>
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {oauthProviders.map((p, idx) => (
                <ProviderCard
                  key={p.id}
                  provider={p}
                  onClick={() => handleSelectProvider(p)}
                  enabled={enabled}
                  onToggle={() => handleToggleProvider(p.id, p.enabled)}
                  animationDelay={0.1 + idx * 0.05}
                />
              ))}
            </div>
          </div>
        )}

        {/* API Key Providers Grid */}
        {apiKeyProviders.length > 0 && (
          <div style={{ animation: 'fadeSlideIn 0.5s ease-out' }}>
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Key className="w-5 h-5 text-amber-400" />
              API Key Providers
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {apiKeyProviders.map((p, idx) => (
                <ProviderCard
                  key={p.id}
                  provider={p}
                  onClick={() => handleSelectProvider(p)}
                  enabled={enabled}
                  onToggle={() => handleToggleProvider(p.id, p.enabled)}
                  animationDelay={0.1 + idx * 0.05}
                />
              ))}
            </div>
          </div>
        )}

        {/* Empty state */}
        {providers.length === 0 && !loading && (
          <div
            className="bg-dark-800 border border-dark-700/50 rounded-xl p-16 text-center"
            style={{ animation: 'fadeSlideIn 0.4s ease-out' }}
          >
            <div className="w-20 h-20 bg-dark-700/30 rounded-full flex items-center justify-center mx-auto mb-5">
              <Plug className="w-10 h-10 text-dark-500" />
            </div>
            <p className="text-dark-300 font-semibold text-lg">No providers configured</p>
            <p className="text-dark-500 text-sm mt-2 max-w-md mx-auto">
              Enable Smart Router and add API keys or detect CLI tokens to get started
            </p>
          </div>
        )}

        {/* Environment Variables Editor */}
        <div className="mt-2" style={{ animation: 'fadeSlideIn 0.55s ease-out' }}>
          <button
            onClick={handleEnvEditorToggle}
            className="flex items-center gap-2 text-sm text-dark-400 hover:text-white transition-colors group"
          >
            <div className="p-1.5 bg-dark-700/50 rounded-lg group-hover:bg-dark-700 transition-colors">
              <Key className="w-4 h-4" />
            </div>
            {showEnvEditor ? 'Hide' : 'Show'} API Key & Config Manager
          </button>

          {showEnvEditor && (
            <div
              className="mt-4 bg-dark-800 border border-dark-700 rounded-xl p-5 space-y-4"
              style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
            >
              <div className="flex items-center justify-between">
                <h3 className="text-white font-semibold text-sm">Environment Variables (.env)</h3>
                {envAllowedKeys.length > 0 && (
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-dark-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Filter variables..."
                      value={envSearch}
                      onChange={(e) => setEnvSearch(e.target.value)}
                      className="pl-8 pr-3 py-1.5 bg-dark-900 border border-dark-600 rounded-lg text-white text-xs placeholder-dark-500 focus:outline-none focus:border-primary-500 w-48"
                    />
                  </div>
                )}
              </div>
              {envAllowedKeys.length === 0 ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-5 h-5 text-dark-400 animate-spin" />
                  <span className="text-dark-500 text-sm ml-3">Loading...</span>
                </div>
              ) : filteredEnvKeys.length === 0 ? (
                <div className="text-center py-8">
                  <Search className="w-6 h-6 text-dark-500 mx-auto mb-2" />
                  <p className="text-dark-500 text-sm">No variables matching "{envSearch}"</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-2 max-h-96 overflow-y-auto pr-1">
                  {filteredEnvKeys.map(key => {
                    const isModified = envEditing[key] !== envVars[key]
                    return (
                      <div
                        key={key}
                        className={`flex items-center gap-2 rounded-lg px-3 py-2 transition-colors ${
                          isModified ? 'bg-primary-500/5 border border-primary-500/20' : 'bg-dark-900 border border-transparent'
                        }`}
                      >
                        <span className="text-xs text-dark-400 font-mono w-48 flex-shrink-0 truncate" title={key}>
                          {key}
                        </span>
                        <input
                          type={key.includes('KEY') || key.includes('TOKEN') || key.includes('SECRET') ? 'password' : 'text'}
                          value={envEditing[key] || ''}
                          onChange={e => handleEnvEditingChange(key, e.target.value)}
                          placeholder="Not set"
                          className="flex-1 px-2 py-1 bg-dark-800 border border-dark-600 rounded text-white text-xs font-mono placeholder-dark-500 focus:outline-none focus:border-primary-500 transition-colors"
                        />
                        <button
                          onClick={() => handleSaveEnvVar(key)}
                          disabled={envSaving === key || !isModified}
                          className={`px-2.5 py-1 text-xs rounded font-medium transition-all ${
                            isModified
                              ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                              : 'bg-dark-700 text-dark-500 cursor-not-allowed'
                          }`}
                        >
                          {envSaving === key ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Save'}
                        </button>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Config Modal */}
        {selectedProvider && (
          <ConfigModal
            provider={selectedProvider}
            onClose={handleCloseModal}
            enabled={enabled}
            addToast={addToast}
          />
        )}
      </div>
    </>
  )
}

/* ---------- ProviderCard ---------- */

function ProviderCard({
  provider,
  onClick,
  enabled,
  onToggle,
  animationDelay,
}: {
  provider: Provider
  onClick: () => void
  enabled: boolean
  onToggle: () => void
  animationDelay: number
}) {
  const color = PROVIDER_COLORS[provider.id] || 'bg-gray-500'
  const initials = PROVIDER_INITIALS[provider.id] || provider.id.substring(0, 2).toUpperCase()
  const tierColor = TIER_COLORS[provider.tier] || 'text-gray-400 bg-gray-400/10'
  const totalTokens = provider.accounts.reduce((sum, a) => sum + a.tokens_used, 0)
  const isProviderEnabled = provider.enabled !== false
  const activeAccounts = provider.accounts.filter(a => a.is_active).length

  return (
    <div
      className={`bg-dark-800 border rounded-xl p-4 text-left transition-all hover:border-primary-500/50 hover:bg-dark-750 group ${
        provider.connected && isProviderEnabled ? 'border-green-500/30' :
        !isProviderEnabled ? 'border-red-500/20' : 'border-dark-700'
      } ${!enabled || !isProviderEnabled ? 'opacity-60' : ''}`}
      style={{ animation: `fadeSlideIn ${animationDelay}s ease-out` }}
    >
      <div className="flex items-start justify-between mb-3">
        <div
          className={`w-12 h-12 ${color} rounded-xl flex items-center justify-center cursor-pointer shadow-lg transition-transform group-hover:scale-105`}
          onClick={enabled ? onClick : undefined}
        >
          <span className="text-white font-bold text-sm">{initials}</span>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${tierColor}`}>
            {TIER_LABELS[provider.tier]}
          </span>
          {/* Enable/Disable Toggle */}
          <label
            className="flex items-center gap-1.5 cursor-pointer select-none"
            onClick={(e) => e.stopPropagation()}
          >
            <span className={`text-[10px] font-medium ${isProviderEnabled ? 'text-green-400' : 'text-red-400'}`}>
              {isProviderEnabled ? 'ON' : 'OFF'}
            </span>
            <button
              onClick={(e) => { e.preventDefault(); e.stopPropagation(); onToggle() }}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-offset-dark-900 ${
                isProviderEnabled ? 'bg-green-500 focus:ring-green-500/50' : 'bg-dark-600 focus:ring-dark-500/50'
              }`}
              role="switch"
              aria-checked={isProviderEnabled}
              title={isProviderEnabled ? 'Disable provider' : 'Enable provider'}
            >
              <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-sm transition-transform duration-200 ${
                isProviderEnabled ? 'translate-x-[18px]' : 'translate-x-[3px]'
              }`} />
            </button>
          </label>
        </div>
      </div>
      <div className="cursor-pointer" onClick={enabled ? onClick : undefined}>
        <div className="flex items-center gap-2">
          <h3 className="font-semibold text-white">{provider.name}</h3>
          {provider.connected && isProviderEnabled && (
            <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
          )}
          {!isProviderEnabled && (
            <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
          )}
        </div>
        <p className="text-xs text-dark-400 mt-1 font-mono">{provider.default_model}</p>
        <div className="flex items-center justify-between mt-3 text-xs text-dark-500">
          <span className={activeAccounts > 0 && isProviderEnabled ? 'text-green-400/70' : ''}>
            {activeAccounts}/{provider.accounts.length} active
          </span>
          {totalTokens > 0 && (
            <span className="flex items-center gap-1">
              <Zap className="w-3 h-3" />
              {totalTokens.toLocaleString()}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

/* ---------- ConfigModal ---------- */

function ConfigModal({
  provider,
  onClose,
  enabled,
  addToast,
}: {
  provider: Provider
  onClose: () => void
  enabled: boolean
  addToast: (message: string, type: Toast['type']) => void
}) {
  const [accounts, setAccounts] = useState<Account[]>(provider.accounts)
  const [detecting, setDetecting] = useState(false)
  const [testing, setTesting] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [newKey, setNewKey] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [adding, setAdding] = useState(false)

  const color = PROVIDER_COLORS[provider.id] || 'bg-gray-500'
  const initials = PROVIDER_INITIALS[provider.id] || provider.id.substring(0, 2).toUpperCase()

  const activeAccounts = useMemo(
    () => accounts.filter(a => a.is_active).length,
    [accounts]
  )

  const handleDetect = useCallback(async () => {
    setDetecting(true)
    setTestResult(null)
    try {
      const res = await fetch(`${API}/${provider.id}/detect`, { method: 'POST' })
      const data = await res.json()
      if (data.detected) {
        setAccounts((prev) => [
          ...prev,
          {
            id: data.account_id,
            label: data.label,
            source: 'cli_detect',
            credential_type: data.credential_type,
            is_active: true,
            tokens_used: 0,
            last_used: null,
            expires_at: data.expires_at,
            model_override: null,
          },
        ])
        setTestResult({ success: true, message: `Detected: ${data.label}` })
        addToast(`Detected: ${data.label}`, 'success')
      } else {
        setTestResult({ success: false, message: data.message || 'No token found' })
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error'
      setTestResult({ success: false, message: msg })
    } finally {
      setDetecting(false)
    }
  }, [provider.id, addToast])

  const handleConnect = useCallback(async () => {
    if (!newKey.trim()) return
    setAdding(true)
    setTestResult(null)
    try {
      const res = await fetch(`${API}/${provider.id}/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: newLabel || 'API Key',
          credential: newKey,
          credential_type: 'api_key',
        }),
      })
      const data = await res.json()
      if (data.success) {
        setAccounts((prev) => [
          ...prev,
          {
            id: data.account_id,
            label: newLabel || 'API Key',
            source: 'manual',
            credential_type: 'api_key',
            is_active: true,
            tokens_used: 0,
            last_used: null,
            expires_at: null,
            model_override: null,
          },
        ])
        setNewKey('')
        setNewLabel('')
        setTestResult({ success: true, message: 'Connected successfully' })
        addToast('Account connected successfully', 'success')
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error'
      setTestResult({ success: false, message: msg })
    } finally {
      setAdding(false)
    }
  }, [newKey, newLabel, provider.id, addToast])

  const handleTest = useCallback(async (accountId: string) => {
    setTesting(accountId)
    setTestResult(null)
    try {
      const res = await fetch(`${API}/test/${provider.id}/${accountId}`, { method: 'POST' })
      const data = await res.json()
      setTestResult({ success: data.success, message: data.message })
      if (data.success) {
        addToast('Connection test passed', 'success')
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error'
      setTestResult({ success: false, message: msg })
    } finally {
      setTesting(null)
    }
  }, [provider.id, addToast])

  const handleRemove = useCallback(async (accountId: string) => {
    try {
      await fetch(`${API}/${provider.id}/accounts/${accountId}`, { method: 'DELETE' })
      setAccounts((prev) => prev.filter((a) => a.id !== accountId))
      setTestResult({ success: true, message: 'Account removed' })
      addToast('Account removed', 'success')
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error'
      setTestResult({ success: false, message: msg })
    }
  }, [provider.id, addToast])

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div
        className="bg-dark-800 border border-dark-700 rounded-2xl w-full max-w-lg max-h-[85vh] overflow-y-auto shadow-2xl"
        style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
      >
        {/* Header */}
        <div className="p-5 border-b border-dark-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 ${color} rounded-xl flex items-center justify-center shadow-lg`}>
              <span className="text-white font-bold text-sm">{initials}</span>
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">{provider.name}</h2>
              <p className="text-xs text-dark-400 font-mono">{provider.api_format} / {provider.default_model}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-dark-500">
              {activeAccounts}/{accounts.length} active
            </span>
            <button
              onClick={onClose}
              className="text-dark-400 hover:text-white p-1.5 rounded-lg hover:bg-dark-700 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="p-5 space-y-5">
          {/* Actions */}
          <div className="flex gap-3">
            {provider.auth_type === 'oauth' && (
              <button
                onClick={handleDetect}
                disabled={detecting || !enabled}
                className="btn-primary flex-1 flex items-center justify-center gap-2"
              >
                {detecting ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Search className="w-4 h-4" />
                )}
                Detect CLI Token
              </button>
            )}
          </div>

          {/* Add API Key */}
          <div className="space-y-2">
            <label className="text-sm font-medium text-dark-300">Add Credential</label>
            <input
              type="text"
              placeholder="Label (optional)"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              className="input-field w-full"
            />
            <div className="flex gap-2">
              <input
                type="password"
                placeholder={provider.auth_type === 'oauth' ? 'OAuth Token' : 'API Key'}
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
                className="input-field flex-1"
              />
              <button
                onClick={handleConnect}
                disabled={!newKey.trim() || adding || !enabled}
                className="btn-primary flex items-center gap-1 px-4"
              >
                {adding ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                Add
              </button>
            </div>
          </div>

          {/* Status Message */}
          {testResult && (
            <div
              className={`flex items-center gap-2 p-3 rounded-lg text-sm ${
                testResult.success
                  ? 'bg-green-500/10 border border-green-500/30 text-green-400'
                  : 'bg-red-500/10 border border-red-500/30 text-red-400'
              }`}
              style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
            >
              {testResult.success ? (
                <CheckCircle className="w-4 h-4 flex-shrink-0" />
              ) : (
                <XCircle className="w-4 h-4 flex-shrink-0" />
              )}
              <span className="truncate">{testResult.message}</span>
            </div>
          )}

          {/* Accounts List */}
          <div>
            <h3 className="text-sm font-medium text-dark-300 mb-2">
              Accounts ({accounts.length})
            </h3>
            {accounts.length === 0 ? (
              <div className="text-center py-8">
                <div className="w-12 h-12 bg-dark-700/30 rounded-full flex items-center justify-center mx-auto mb-3">
                  <Shield className="w-6 h-6 text-dark-500" />
                </div>
                <p className="text-dark-500 text-sm">No accounts connected</p>
                <p className="text-dark-600 text-xs mt-1">
                  {provider.auth_type === 'oauth' ? 'Detect a CLI token or add one manually' : 'Add an API key above'}
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {accounts.map((acct, idx) => {
                  const expiry = formatExpiryTime(acct.expires_at)
                  return (
                    <div
                      key={acct.id}
                      className={`bg-dark-750 border rounded-lg p-3 flex items-center justify-between transition-all ${
                        acct.is_active ? 'border-dark-700' : 'border-red-500/20 opacity-60'
                      }`}
                      style={{ animation: `fadeSlideIn ${0.15 + idx * 0.05}s ease-out` }}
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium truncate">{acct.label}</span>
                          <span
                            className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                              acct.source === 'cli_detect'
                                ? 'bg-blue-500/20 text-blue-400'
                                : acct.source === 'env_var'
                                ? 'bg-green-500/20 text-green-400'
                                : 'bg-dark-600 text-dark-400'
                            }`}
                          >
                            {acct.source === 'cli_detect'
                              ? 'CLI'
                              : acct.source === 'env_var'
                              ? 'ENV'
                              : 'Manual'}
                          </span>
                          {!acct.is_active && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-medium">
                              Inactive
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-dark-500">
                          <span className="flex items-center gap-1">
                            <Zap className="w-3 h-3" />
                            {acct.tokens_used.toLocaleString()} tokens
                          </span>
                          {acct.last_used && (
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {relativeTime(acct.last_used)}
                            </span>
                          )}
                          {expiry.label && (
                            <span className={`flex items-center gap-1 ${expiry.urgency}`}>
                              {expiry.isExpired ? <XCircle className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
                              {expiry.label}
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 ml-2 flex-shrink-0">
                        <button
                          onClick={() => handleTest(acct.id)}
                          disabled={testing === acct.id || !enabled}
                          className="p-1.5 text-dark-400 hover:text-primary-400 transition-colors rounded-lg hover:bg-primary-500/10"
                          title="Test connection"
                        >
                          {testing === acct.id ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            <TestTube className="w-4 h-4" />
                          )}
                        </button>
                        <button
                          onClick={() => handleRemove(acct.id)}
                          disabled={!enabled}
                          className="p-1.5 text-dark-400 hover:text-red-400 transition-colors rounded-lg hover:bg-red-500/10"
                          title="Remove account"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
