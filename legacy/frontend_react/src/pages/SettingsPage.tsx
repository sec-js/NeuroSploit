import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Save,
  Shield,
  Trash2,
  RefreshCw,
  AlertTriangle,
  Brain,
  Router,
  Eye,
  ChevronDown,
  Loader2,
  Bell,
  Send,
  Phone,
  MessageCircle,
  Hash,
  X,
  Settings,
  Database,
  Zap,
  CheckCircle2,
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface Settings {
  llm_provider: string
  llm_model: string
  has_anthropic_key: boolean
  has_openai_key: boolean
  has_openrouter_key: boolean
  has_gemini_key: boolean
  has_together_key: boolean
  has_fireworks_key: boolean
  ollama_base_url: string
  lmstudio_base_url: string
  max_concurrent_scans: number
  aggressive_mode: boolean
  default_scan_type: string
  recon_enabled_by_default: boolean
  enable_model_routing: boolean
  enable_knowledge_augmentation: boolean
  enable_browser_validation: boolean
  max_output_tokens: number | null
  // Notifications
  enable_notifications: boolean
  has_discord_webhook: boolean
  has_telegram_bot: boolean
  has_twilio_credentials: boolean
  notification_severity_filter: string
}

interface DbStats {
  scans: number
  vulnerabilities: number
  endpoints: number
  reports: number
}

interface ModelInfo {
  model_id: string
  display_name: string
  size?: string
  context_length?: number
  is_local: boolean
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
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const PROVIDERS = [
  { id: 'claude', label: 'Claude', color: 'orange' },
  { id: 'openai', label: 'OpenAI', color: 'emerald' },
  { id: 'gemini', label: 'Gemini', color: 'blue' },
  { id: 'openrouter', label: 'OpenRouter', color: 'violet' },
  { id: 'together', label: 'Together AI', color: 'teal' },
  { id: 'fireworks', label: 'Fireworks AI', color: 'rose' },
  { id: 'ollama', label: 'Ollama', color: 'gray' },
  { id: 'lmstudio', label: 'LM Studio', color: 'slate' },
] as const

const FEATURE_TOGGLES = [
  {
    key: 'modelRouting' as const,
    icon: Router,
    iconColor: 'text-blue-400',
    title: 'Model Routing',
    description: 'Route tasks to specialized LLM profiles by type (reasoning, analysis, generation)',
  },
  {
    key: 'knowledgeAugmentation' as const,
    icon: Brain,
    iconColor: 'text-purple-400',
    title: 'Knowledge Augmentation',
    description: 'Enrich AI context with bug bounty pattern datasets (19 vuln types)',
  },
  {
    key: 'browserValidation' as const,
    icon: Eye,
    iconColor: 'text-green-400',
    title: 'Browser Validation',
    description: 'Playwright-based browser validation with screenshot capture',
  },
] as const

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

/* ------------------------------------------------------------------ */
/*  Page Component                                                     */
/* ------------------------------------------------------------------ */

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [dbStats, setDbStats] = useState<DbStats | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [openaiKey, setOpenaiKey] = useState('')
  const [openrouterKey, setOpenrouterKey] = useState('')
  const [geminiKey, setGeminiKey] = useState('')
  const [togetherKey, setTogetherKey] = useState('')
  const [fireworksKey, setFireworksKey] = useState('')
  const [ollamaUrl, setOllamaUrl] = useState('')
  const [lmstudioUrl, setLmstudioUrl] = useState('')
  const [llmProvider, setLlmProvider] = useState('claude')
  const [llmModel, setLlmModel] = useState('')
  const [maxConcurrentScans, setMaxConcurrentScans] = useState('3')
  const [maxOutputTokens, setMaxOutputTokens] = useState('')
  const [aggressiveMode, setAggressiveMode] = useState(false)
  const [enableModelRouting, setEnableModelRouting] = useState(false)
  const [enableKnowledgeAugmentation, setEnableKnowledgeAugmentation] = useState(false)
  const [enableBrowserValidation, setEnableBrowserValidation] = useState(false)
  // Notifications
  const [enableNotifications, setEnableNotifications] = useState(false)
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState('')
  const [telegramBotToken, setTelegramBotToken] = useState('')
  const [telegramChatId, setTelegramChatId] = useState('')
  const [twilioAccountSid, setTwilioAccountSid] = useState('')
  const [twilioAuthToken, setTwilioAuthToken] = useState('')
  const [twilioFromNumber, setTwilioFromNumber] = useState('')
  const [twilioToNumber, setTwilioToNumber] = useState('')
  const [notificationSeverityFilter, setNotificationSeverityFilter] = useState('critical,high')
  const [testingChannel, setTestingChannel] = useState<string | null>(null)

  const [isSaving, setIsSaving] = useState(false)
  const [isClearing, setIsClearing] = useState(false)
  const [showClearConfirm, setShowClearConfirm] = useState(false)
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([])
  const [loadingModels, setLoadingModels] = useState(false)
  const [refreshSpinning, setRefreshSpinning] = useState(false)
  const [statsRefreshing, setStatsRefreshing] = useState(false)
  const [toasts, setToasts] = useState<Toast[]>([])

  /* ---------- Toast helpers ---------- */
  const addToast = useCallback((message: string, severity: Toast['severity']) => {
    const id = ++_toastId
    setToasts(prev => [...prev, { id, message, severity }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  /* ---------- Derived data ---------- */
  const totalDbRecords = useMemo(() => {
    if (!dbStats) return 0
    return dbStats.scans + dbStats.vulnerabilities + dbStats.endpoints + dbStats.reports
  }, [dbStats])

  const activeProviderLabel = useMemo(() => {
    return PROVIDERS.find(p => p.id === llmProvider)?.label || llmProvider
  }, [llmProvider])

  const hasApiKeyForProvider = useMemo((): boolean => {
    if (!settings) return false
    const keyMap: Record<string, boolean> = {
      claude: settings.has_anthropic_key,
      openai: settings.has_openai_key,
      gemini: settings.has_gemini_key,
      openrouter: settings.has_openrouter_key,
      together: settings.has_together_key,
      fireworks: settings.has_fireworks_key,
      ollama: true,
      lmstudio: true,
    }
    return keyMap[llmProvider] ?? false
  }, [settings, llmProvider])

  const enabledFeaturesCount = useMemo(() => {
    return [enableModelRouting, enableKnowledgeAugmentation, enableBrowserValidation].filter(Boolean).length
  }, [enableModelRouting, enableKnowledgeAugmentation, enableBrowserValidation])

  /* ---------- Data fetching ---------- */
  const fetchSettings = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/settings')
      if (response.ok) {
        const data: Settings = await response.json()
        setSettings(data)
        setLlmProvider(data.llm_provider)
        setLlmModel(data.llm_model || '')
        setMaxConcurrentScans(String(data.max_concurrent_scans))
        setAggressiveMode(data.aggressive_mode)
        setEnableModelRouting(data.enable_model_routing ?? false)
        setEnableKnowledgeAugmentation(data.enable_knowledge_augmentation ?? false)
        setEnableBrowserValidation(data.enable_browser_validation ?? false)
        setMaxOutputTokens(data.max_output_tokens ? String(data.max_output_tokens) : '')
        setOllamaUrl(data.ollama_base_url || '')
        setLmstudioUrl(data.lmstudio_base_url || '')
        setEnableNotifications(data.enable_notifications ?? false)
        setNotificationSeverityFilter(data.notification_severity_filter || 'critical,high')
      }
    } catch (error) {
      console.error('Failed to fetch settings:', error)
      addToast('Failed to load settings', 'error')
    }
  }, [addToast])

  const fetchDbStats = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/settings/stats')
      if (response.ok) {
        const data: DbStats = await response.json()
        setDbStats(data)
      }
    } catch (error) {
      console.error('Failed to fetch db stats:', error)
    }
  }, [])

  const fetchModels = useCallback(async (provider: string) => {
    setLoadingModels(true)
    try {
      const response = await fetch(`/api/v1/settings/models/${provider}`)
      if (response.ok) {
        const data = await response.json()
        setAvailableModels((data.models as ModelInfo[]) || [])
      } else {
        setAvailableModels([])
      }
    } catch {
      setAvailableModels([])
    } finally {
      setLoadingModels(false)
    }
  }, [])

  useEffect(() => {
    fetchSettings()
    fetchDbStats()
  }, [fetchSettings, fetchDbStats])

  useEffect(() => {
    fetchModels(llmProvider)
  }, [llmProvider, fetchModels])

  /* ---------- Handlers ---------- */
  const handleSave = useCallback(async () => {
    setIsSaving(true)

    try {
      const body: Record<string, unknown> = {
        llm_provider: llmProvider,
        llm_model: llmModel || undefined,
        max_concurrent_scans: parseInt(maxConcurrentScans),
        aggressive_mode: aggressiveMode,
        enable_model_routing: enableModelRouting,
        enable_knowledge_augmentation: enableKnowledgeAugmentation,
        enable_browser_validation: enableBrowserValidation,
        max_output_tokens: maxOutputTokens ? parseInt(maxOutputTokens) : null,
        enable_notifications: enableNotifications,
        notification_severity_filter: notificationSeverityFilter,
      }

      // Notification credentials (only send if changed)
      if (discordWebhookUrl) body.discord_webhook_url = discordWebhookUrl
      if (telegramBotToken) body.telegram_bot_token = telegramBotToken
      if (telegramChatId) body.telegram_chat_id = telegramChatId
      if (twilioAccountSid) body.twilio_account_sid = twilioAccountSid
      if (twilioAuthToken) body.twilio_auth_token = twilioAuthToken
      if (twilioFromNumber) body.twilio_from_number = twilioFromNumber
      if (twilioToNumber) body.twilio_to_number = twilioToNumber

      // Only send keys that were changed
      if (apiKey) body.anthropic_api_key = apiKey
      if (openaiKey) body.openai_api_key = openaiKey
      if (openrouterKey) body.openrouter_api_key = openrouterKey
      if (geminiKey) body.gemini_api_key = geminiKey
      if (togetherKey) body.together_api_key = togetherKey
      if (fireworksKey) body.fireworks_api_key = fireworksKey
      if (ollamaUrl) body.ollama_base_url = ollamaUrl
      if (lmstudioUrl) body.lmstudio_base_url = lmstudioUrl

      const response = await fetch('/api/v1/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      if (response.ok) {
        const data: Settings = await response.json()
        setSettings(data)
        setApiKey('')
        setOpenaiKey('')
        setOpenrouterKey('')
        setGeminiKey('')
        setTogetherKey('')
        setFireworksKey('')
        setDiscordWebhookUrl('')
        setTelegramBotToken('')
        setTelegramChatId('')
        setTwilioAccountSid('')
        setTwilioAuthToken('')
        setTwilioFromNumber('')
        setTwilioToNumber('')
        addToast('Settings saved successfully!', 'success')
      } else {
        addToast('Failed to save settings', 'error')
      }
    } catch {
      addToast('Failed to save settings', 'error')
    } finally {
      setIsSaving(false)
    }
  }, [
    llmProvider, llmModel, maxConcurrentScans, aggressiveMode,
    enableModelRouting, enableKnowledgeAugmentation, enableBrowserValidation,
    maxOutputTokens, enableNotifications, notificationSeverityFilter,
    discordWebhookUrl, telegramBotToken, telegramChatId,
    twilioAccountSid, twilioAuthToken, twilioFromNumber, twilioToNumber,
    apiKey, openaiKey, openrouterKey, geminiKey, togetherKey, fireworksKey,
    ollamaUrl, lmstudioUrl, addToast,
  ])

  const handleClearDatabase = useCallback(async () => {
    setIsClearing(true)

    try {
      const response = await fetch('/api/v1/settings/clear-database', {
        method: 'POST',
      })

      if (response.ok) {
        addToast('Database cleared successfully!', 'success')
        setShowClearConfirm(false)
        fetchDbStats()
      } else {
        const data = await response.json()
        addToast(data.detail || 'Failed to clear database', 'error')
      }
    } catch {
      addToast('Failed to clear database', 'error')
    } finally {
      setIsClearing(false)
    }
  }, [addToast, fetchDbStats])

  const handleTestNotification = useCallback(async (channel: string) => {
    setTestingChannel(channel)
    try {
      const response = await fetch(`/api/v1/settings/notifications/test/${channel}`, { method: 'POST' })
      const data = await response.json()
      if (data.success) {
        addToast(data.message || `Test sent to ${channel}`, 'success')
      } else {
        addToast(data.error || `Test failed for ${channel}`, 'error')
      }
    } catch {
      addToast(`Failed to send test to ${channel}`, 'error')
    } finally {
      setTestingChannel(null)
    }
  }, [addToast])

  const handleRefreshModels = useCallback(() => {
    setRefreshSpinning(true)
    fetchModels(llmProvider)
    setTimeout(() => setRefreshSpinning(false), 800)
  }, [fetchModels, llmProvider])

  const handleRefreshStats = useCallback(() => {
    setStatsRefreshing(true)
    fetchDbStats()
    setTimeout(() => setStatsRefreshing(false), 800)
  }, [fetchDbStats])

  const handleProviderSelect = useCallback((providerId: string) => {
    setLlmProvider(providerId)
  }, [])

  const handleModelChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
    setLlmModel(e.target.value)
  }, [])

  const featureToggleSetters = useMemo(() => ({
    modelRouting: () => setEnableModelRouting(prev => !prev),
    knowledgeAugmentation: () => setEnableKnowledgeAugmentation(prev => !prev),
    browserValidation: () => setEnableBrowserValidation(prev => !prev),
  }), [])

  const featureToggleValues = useMemo(() => ({
    modelRouting: enableModelRouting,
    knowledgeAugmentation: enableKnowledgeAugmentation,
    browserValidation: enableBrowserValidation,
  }), [enableModelRouting, enableKnowledgeAugmentation, enableBrowserValidation])

  /* ---------- Sub-components ---------- */
  const ToggleSwitch = useCallback(({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) => (
    <button
      onClick={onToggle}
      className={`relative w-12 h-6 rounded-full transition-colors duration-200 ${enabled ? 'bg-primary-500' : 'bg-dark-700'}`}
    >
      <div
        className={`absolute top-0.5 w-5 h-5 bg-white rounded-full shadow-md transform transition-transform duration-200 ${enabled ? 'translate-x-6' : 'translate-x-0.5'}`}
      />
    </button>
  ), [])

  /* ---------- Render ---------- */
  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Inline keyframes */}
      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes spinOnce {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
      `}</style>

      {/* Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Page Header */}
      <div
        className="flex items-center justify-between"
        style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
      >
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-primary-500/10 rounded-xl">
            <Settings className="w-6 h-6 text-primary-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Settings</h1>
            <p className="text-sm text-dark-400">
              {activeProviderLabel} provider
              {hasApiKeyForProvider && (
                <span className="inline-flex items-center ml-2 text-xs text-green-400">
                  <CheckCircle2 className="w-3 h-3 mr-1" />
                  Key configured
                </span>
              )}
              {enabledFeaturesCount > 0 && (
                <span className="ml-2 text-xs text-purple-400">
                  {enabledFeaturesCount} feature{enabledFeaturesCount !== 1 ? 's' : ''} active
                </span>
              )}
            </p>
          </div>
        </div>
        <Button onClick={handleSave} isLoading={isSaving}>
          <Save className="w-4 h-4 mr-2" />
          Save Settings
        </Button>
      </div>

      {/* LLM Configuration */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.05s both' }}>
        <Card title="LLM Configuration" subtitle="Configure AI model for vulnerability analysis">
          <div className="space-y-4">
            {/* Provider selection */}
            <div>
              <label className="block text-sm font-medium text-dark-200 mb-2">
                LLM Provider
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {PROVIDERS.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => handleProviderSelect(p.id)}
                    className={`relative px-3 py-2.5 rounded-lg border text-sm font-medium transition-all duration-200 ${
                      llmProvider === p.id
                        ? 'bg-primary-500/15 border-primary-500/50 text-primary-400 shadow-lg shadow-primary-500/10'
                        : 'bg-dark-900/50 border-dark-700 text-dark-300 hover:bg-dark-800 hover:border-dark-600'
                    }`}
                  >
                    {p.label}
                    {llmProvider === p.id && (
                      <span className="absolute top-1 right-1.5">
                        <CheckCircle2 className="w-3 h-3 text-primary-400" />
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Model Picker */}
            <div>
              <label className="block text-sm font-medium text-dark-200 mb-2">
                Model
                {loadingModels && <Loader2 className="w-3 h-3 inline ml-2 animate-spin" />}
              </label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <select
                    value={llmModel}
                    onChange={handleModelChange}
                    className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-white appearance-none cursor-pointer focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/20 transition-colors"
                  >
                    <option value="">Provider default</option>
                    {availableModels.map((m) => (
                      <option key={m.model_id} value={m.model_id}>
                        {m.display_name}{m.size ? ` (${m.size})` : ''}{m.context_length ? ` - ${(m.context_length / 1000).toFixed(0)}k ctx` : ''}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-3 top-3 w-4 h-4 text-dark-400 pointer-events-none" />
                </div>
                <Button variant="secondary" onClick={handleRefreshModels} title="Refresh models">
                  <RefreshCw
                    className="w-4 h-4"
                    style={refreshSpinning ? { animation: 'spinOnce 0.6s ease-in-out' } : undefined}
                  />
                </Button>
              </div>
              {llmModel && (
                <p className="text-xs text-dark-400 mt-1.5 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-green-500" />
                  Selected: <span className="text-dark-200 font-mono">{llmModel}</span>
                </p>
              )}
              {['ollama', 'lmstudio'].includes(llmProvider) && availableModels.length === 0 && !loadingModels && (
                <p className="text-xs text-yellow-400 mt-1.5 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  No models found. Make sure {llmProvider === 'ollama' ? 'Ollama' : 'LM Studio'} is running.
                </p>
              )}
            </div>

            {/* API Key inputs */}
            {llmProvider === 'claude' && (
              <div style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                <Input
                  label="Anthropic API Key"
                  type="password"
                  placeholder={settings?.has_anthropic_key ? '••••••••••••••••' : 'sk-ant-...'}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  helperText={settings?.has_anthropic_key ? 'API key is configured. Enter a new key to update.' : 'Required for Claude-powered analysis'}
                />
              </div>
            )}

            {llmProvider === 'openai' && (
              <div style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                <Input
                  label="OpenAI API Key"
                  type="password"
                  placeholder={settings?.has_openai_key ? '••••••••••••••••' : 'sk-...'}
                  value={openaiKey}
                  onChange={(e) => setOpenaiKey(e.target.value)}
                  helperText={settings?.has_openai_key ? 'API key is configured. Enter a new key to update.' : 'Required for OpenAI-powered analysis'}
                />
              </div>
            )}

            {llmProvider === 'gemini' && (
              <div style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                <Input
                  label="Gemini API Key"
                  type="password"
                  placeholder={settings?.has_gemini_key ? '••••••••••••••••' : 'AI...'}
                  value={geminiKey}
                  onChange={(e) => setGeminiKey(e.target.value)}
                  helperText={settings?.has_gemini_key ? 'API key is configured.' : 'Required for Gemini models'}
                />
              </div>
            )}

            {llmProvider === 'openrouter' && (
              <div style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                <Input
                  label="OpenRouter API Key"
                  type="password"
                  placeholder={settings?.has_openrouter_key ? '••••••••••••••••' : 'sk-or-...'}
                  value={openrouterKey}
                  onChange={(e) => setOpenrouterKey(e.target.value)}
                  helperText={settings?.has_openrouter_key ? 'API key is configured.' : 'Required for OpenRouter model access'}
                />
              </div>
            )}

            {llmProvider === 'together' && (
              <div style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                <Input
                  label="Together AI API Key"
                  type="password"
                  placeholder={settings?.has_together_key ? '••••••••••••••••' : '...'}
                  value={togetherKey}
                  onChange={(e) => setTogetherKey(e.target.value)}
                  helperText={settings?.has_together_key ? 'API key is configured.' : 'Required for Together AI models (Llama, Qwen, Mixtral, etc.)'}
                />
              </div>
            )}

            {llmProvider === 'fireworks' && (
              <div style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                <Input
                  label="Fireworks AI API Key"
                  type="password"
                  placeholder={settings?.has_fireworks_key ? '••••••••••••••••' : '...'}
                  value={fireworksKey}
                  onChange={(e) => setFireworksKey(e.target.value)}
                  helperText={settings?.has_fireworks_key ? 'API key is configured.' : 'Required for Fireworks AI models'}
                />
              </div>
            )}

            {llmProvider === 'ollama' && (
              <div style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                <Input
                  label="Ollama Base URL"
                  type="text"
                  placeholder="http://localhost:11434"
                  value={ollamaUrl}
                  onChange={(e) => setOllamaUrl(e.target.value)}
                  helperText="URL of your local Ollama instance. Supports Llama, Qwen, DeepSeek, Mistral, etc."
                />
              </div>
            )}

            {llmProvider === 'lmstudio' && (
              <div style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                <Input
                  label="LM Studio Base URL"
                  type="text"
                  placeholder="http://localhost:1234"
                  value={lmstudioUrl}
                  onChange={(e) => setLmstudioUrl(e.target.value)}
                  helperText="URL of your local LM Studio server."
                />
              </div>
            )}

            <Input
              label="Max Output Tokens"
              type="number"
              min="1024"
              max="64000"
              placeholder="Default (profile-based)"
              value={maxOutputTokens}
              onChange={(e) => setMaxOutputTokens(e.target.value)}
              helperText="Override max output tokens (up to 64000 for Claude). Leave empty for profile defaults."
            />
          </div>
        </Card>
      </div>

      {/* Advanced Features */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.1s both' }}>
        <Card title="Advanced Features" subtitle="Optional AI enhancement modules">
          <div className="space-y-3">
            {FEATURE_TOGGLES.map((feature, idx) => {
              const Icon = feature.icon
              return (
                <div
                  key={feature.key}
                  className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg border border-dark-700/30 hover:border-dark-600/50 transition-colors"
                  style={{ animation: `fadeSlideIn 0.3s ease-out ${0.12 + idx * 0.04}s both` }}
                >
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${featureToggleValues[feature.key] ? 'bg-primary-500/10' : 'bg-dark-800'}`}>
                      <Icon className={`w-5 h-5 ${feature.iconColor}`} />
                    </div>
                    <div>
                      <p className="font-medium text-white text-sm">{feature.title}</p>
                      <p className="text-xs text-dark-400 mt-0.5">{feature.description}</p>
                    </div>
                  </div>
                  <ToggleSwitch
                    enabled={featureToggleValues[feature.key]}
                    onToggle={featureToggleSetters[feature.key]}
                  />
                </div>
              )
            })}
          </div>
        </Card>
      </div>

      {/* Notifications */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}>
        <Card title="Notifications" subtitle="Send scan alerts to Discord, Telegram, and WhatsApp">
          <div className="space-y-4">
            {/* Master toggle */}
            <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg border border-dark-700/30">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${enableNotifications ? 'bg-yellow-500/10' : 'bg-dark-800'}`}>
                  <Bell className={`w-5 h-5 ${enableNotifications ? 'text-yellow-400' : 'text-dark-500'}`} />
                </div>
                <div>
                  <p className="font-medium text-white text-sm">Enable Notifications</p>
                  <p className="text-xs text-dark-400 mt-0.5">Send alerts when scans start, find vulnerabilities, or complete</p>
                </div>
              </div>
              <ToggleSwitch enabled={enableNotifications} onToggle={() => setEnableNotifications(!enableNotifications)} />
            </div>

            {enableNotifications && (
              <div className="space-y-4" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                {/* Severity filter */}
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-2">
                    <Hash className="w-4 h-4 inline mr-1" />
                    Severity Filter (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={notificationSeverityFilter}
                    onChange={(e) => setNotificationSeverityFilter(e.target.value)}
                    placeholder="critical,high"
                    className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-white text-sm focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/20 transition-colors"
                  />
                  <p className="text-xs text-dark-500 mt-1">Only notify for vulnerabilities matching these severities</p>
                </div>

                {/* Discord */}
                <div
                  className="p-4 bg-dark-900/50 rounded-lg space-y-3 border border-dark-700/30"
                  style={{ animation: 'fadeSlideIn 0.3s ease-out 0.05s both' }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <MessageCircle className="w-4 h-4 text-indigo-400" />
                      <span className="text-white font-medium text-sm">Discord</span>
                      {settings?.has_discord_webhook && (
                        <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full border border-green-500/20">
                          Configured
                        </span>
                      )}
                    </div>
                    <button
                      onClick={() => handleTestNotification('discord')}
                      disabled={testingChannel === 'discord' || !settings?.has_discord_webhook}
                      className="text-xs px-3 py-1.5 bg-indigo-500/20 text-indigo-400 rounded-lg hover:bg-indigo-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200"
                    >
                      {testingChannel === 'discord' ? <Loader2 className="w-3 h-3 animate-spin inline" /> : 'Test'}
                    </button>
                  </div>
                  <Input
                    label="Webhook URL"
                    type="password"
                    placeholder={settings?.has_discord_webhook ? '••••••••••••••••' : 'https://discord.com/api/webhooks/...'}
                    value={discordWebhookUrl}
                    onChange={(e) => setDiscordWebhookUrl(e.target.value)}
                    helperText={settings?.has_discord_webhook ? 'Webhook configured. Enter new URL to update.' : 'Create a webhook in your Discord channel settings'}
                  />
                </div>

                {/* Telegram */}
                <div
                  className="p-4 bg-dark-900/50 rounded-lg space-y-3 border border-dark-700/30"
                  style={{ animation: 'fadeSlideIn 0.3s ease-out 0.1s both' }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Send className="w-4 h-4 text-blue-400" />
                      <span className="text-white font-medium text-sm">Telegram</span>
                      {settings?.has_telegram_bot && (
                        <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full border border-green-500/20">
                          Configured
                        </span>
                      )}
                    </div>
                    <button
                      onClick={() => handleTestNotification('telegram')}
                      disabled={testingChannel === 'telegram' || !settings?.has_telegram_bot}
                      className="text-xs px-3 py-1.5 bg-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200"
                    >
                      {testingChannel === 'telegram' ? <Loader2 className="w-3 h-3 animate-spin inline" /> : 'Test'}
                    </button>
                  </div>
                  <Input
                    label="Bot Token"
                    type="password"
                    placeholder={settings?.has_telegram_bot ? '••••••••••••••••' : '123456:ABC-DEF...'}
                    value={telegramBotToken}
                    onChange={(e) => setTelegramBotToken(e.target.value)}
                    helperText="Get from @BotFather on Telegram"
                  />
                  <Input
                    label="Chat ID"
                    type="text"
                    placeholder="-1001234567890"
                    value={telegramChatId}
                    onChange={(e) => setTelegramChatId(e.target.value)}
                    helperText="Channel or group chat ID (use @userinfobot to find)"
                  />
                </div>

                {/* WhatsApp (Twilio) */}
                <div
                  className="p-4 bg-dark-900/50 rounded-lg space-y-3 border border-dark-700/30"
                  style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Phone className="w-4 h-4 text-green-400" />
                      <span className="text-white font-medium text-sm">WhatsApp (Twilio)</span>
                      {settings?.has_twilio_credentials && (
                        <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full border border-green-500/20">
                          Configured
                        </span>
                      )}
                    </div>
                    <button
                      onClick={() => handleTestNotification('whatsapp')}
                      disabled={testingChannel === 'whatsapp' || !settings?.has_twilio_credentials}
                      className="text-xs px-3 py-1.5 bg-green-500/20 text-green-400 rounded-lg hover:bg-green-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200"
                    >
                      {testingChannel === 'whatsapp' ? <Loader2 className="w-3 h-3 animate-spin inline" /> : 'Test'}
                    </button>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <Input
                      label="Account SID"
                      type="password"
                      placeholder={settings?.has_twilio_credentials ? '••••••••' : 'AC...'}
                      value={twilioAccountSid}
                      onChange={(e) => setTwilioAccountSid(e.target.value)}
                    />
                    <Input
                      label="Auth Token"
                      type="password"
                      placeholder={settings?.has_twilio_credentials ? '••••••••' : '...'}
                      value={twilioAuthToken}
                      onChange={(e) => setTwilioAuthToken(e.target.value)}
                    />
                    <Input
                      label="From Number"
                      type="text"
                      placeholder="+14155238886"
                      value={twilioFromNumber}
                      onChange={(e) => setTwilioFromNumber(e.target.value)}
                    />
                    <Input
                      label="To Number"
                      type="text"
                      placeholder="+1234567890"
                      value={twilioToNumber}
                      onChange={(e) => setTwilioToNumber(e.target.value)}
                    />
                  </div>
                  <p className="text-xs text-dark-500">Requires Twilio account with WhatsApp sandbox enabled</p>
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Scan Settings */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.2s both' }}>
        <Card title="Scan Settings" subtitle="Configure default scan behavior">
          <div className="space-y-4">
            <Input
              label="Max Concurrent Scans"
              type="number"
              min="1"
              max="10"
              value={maxConcurrentScans}
              onChange={(e) => setMaxConcurrentScans(e.target.value)}
              helperText="Maximum number of scans that can run simultaneously"
            />

            <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg border border-dark-700/30 hover:border-dark-600/50 transition-colors">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${aggressiveMode ? 'bg-red-500/10' : 'bg-dark-800'}`}>
                  <Zap className={`w-5 h-5 ${aggressiveMode ? 'text-red-400' : 'text-dark-500'}`} />
                </div>
                <div>
                  <p className="font-medium text-white text-sm">Enable Aggressive Mode</p>
                  <p className="text-xs text-dark-400 mt-0.5">
                    Use more payloads and bypass techniques (may be slower)
                  </p>
                </div>
              </div>
              <ToggleSwitch enabled={aggressiveMode} onToggle={() => setAggressiveMode(!aggressiveMode)} />
            </div>
          </div>
        </Card>
      </div>

      {/* Database Management */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.25s both' }}>
        <Card title="Database Management" subtitle="Manage stored data">
          <div className="space-y-4">
            {/* Stats */}
            {dbStats && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {([
                  { label: 'Scans', value: dbStats.scans, color: 'text-blue-400', bg: 'bg-blue-500/10' },
                  { label: 'Vulnerabilities', value: dbStats.vulnerabilities, color: 'text-red-400', bg: 'bg-red-500/10' },
                  { label: 'Endpoints', value: dbStats.endpoints, color: 'text-green-400', bg: 'bg-green-500/10' },
                  { label: 'Reports', value: dbStats.reports, color: 'text-purple-400', bg: 'bg-purple-500/10' },
                ] as const).map((stat, idx) => (
                  <div
                    key={stat.label}
                    className={`text-center p-4 ${stat.bg} rounded-lg border border-dark-700/30`}
                    style={{ animation: `fadeSlideIn 0.3s ease-out ${0.27 + idx * 0.04}s both` }}
                  >
                    <p className={`text-2xl font-bold ${stat.color}`}>{formatNumber(stat.value)}</p>
                    <p className="text-xs text-dark-400 mt-1">{stat.label}</p>
                  </div>
                ))}
              </div>
            )}

            {totalDbRecords > 0 && (
              <p className="text-xs text-dark-500 text-center">
                {totalDbRecords.toLocaleString()} total records stored
              </p>
            )}

            {/* Clear Database */}
            {!showClearConfirm ? (
              <div className="flex items-center justify-between p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                <div className="flex items-center gap-3">
                  <Database className="w-5 h-5 text-red-400/60" />
                  <div>
                    <p className="font-medium text-white text-sm">Clear All Data</p>
                    <p className="text-xs text-dark-400 mt-0.5">
                      Remove all scans, vulnerabilities, and reports
                    </p>
                  </div>
                </div>
                <Button variant="danger" onClick={() => setShowClearConfirm(true)}>
                  <Trash2 className="w-4 h-4 mr-2" />
                  Clear Database
                </Button>
              </div>
            ) : (
              <div
                className="p-4 bg-red-500/20 border border-red-500/50 rounded-lg space-y-4"
                style={{ animation: 'fadeSlideIn 0.2s ease-out' }}
              >
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium text-red-400">Are you sure?</p>
                    <p className="text-sm text-dark-300 mt-1">
                      This will permanently delete all scans, vulnerabilities, endpoints, and reports.
                      This action cannot be undone.
                    </p>
                  </div>
                </div>
                <div className="flex gap-3 justify-end">
                  <Button variant="secondary" onClick={() => setShowClearConfirm(false)}>
                    Cancel
                  </Button>
                  <Button variant="danger" onClick={handleClearDatabase} isLoading={isClearing}>
                    <Trash2 className="w-4 h-4 mr-2" />
                    Yes, Clear Everything
                  </Button>
                </div>
              </div>
            )}

            {/* Refresh Stats */}
            <Button variant="secondary" onClick={handleRefreshStats} className="w-full">
              <RefreshCw
                className="w-4 h-4 mr-2"
                style={statsRefreshing ? { animation: 'spinOnce 0.6s ease-in-out' } : undefined}
              />
              Refresh Statistics
            </Button>
          </div>
        </Card>
      </div>

      {/* About */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.3s both' }}>
        <Card title="About NeuroSploit">
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-primary-500/10 rounded-xl">
                <Shield className="w-8 h-8 text-primary-500" />
              </div>
              <div>
                <p className="font-bold text-white text-lg">NeuroSploit v3.0</p>
                <p className="text-sm text-dark-400">AI-Powered Penetration Testing Platform</p>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {[
                'Dynamic vulnerability testing driven by AI prompts',
                '100+ vulnerability types across 10 categories',
                'Multi-provider LLM support (8 providers)',
                'Custom knowledge learning from security research',
                'Adaptive learning from TP/FP feedback',
                'MCP server integration for extended tooling',
                'Playwright browser validation with screenshots',
                'OHVR-structured PoC reporting',
              ].map((feature, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2 text-sm text-dark-400"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-primary-500/60 flex-shrink-0 mt-0.5" />
                  <span>{feature}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* Sticky Save Button (bottom) */}
      <div
        className="flex justify-end pb-4"
        style={{ animation: 'fadeSlideIn 0.3s ease-out 0.35s both' }}
      >
        <Button onClick={handleSave} isLoading={isSaving} size="lg">
          <Save className="w-5 h-5 mr-2" />
          Save Settings
        </Button>
      </div>
    </div>
  )
}
