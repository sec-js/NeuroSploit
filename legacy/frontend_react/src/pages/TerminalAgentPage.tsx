import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import {
  Terminal, Send, Play, Bot, Globe, ArrowRightLeft, ShieldAlert, Wifi,
  Plus, Trash2, Circle, Loader2, X, Upload, MessageSquare, Command,
  ChevronRight, Clock, Zap
} from 'lucide-react'
import { terminalApi } from '../services/api'

// ---------------------------------------------------------------------------
// Inline keyframes
// ---------------------------------------------------------------------------

const styleTag = `
@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(-8px); }
  to   { opacity: 1; transform: translateY(0); }
}
@keyframes terminalBlink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}
@keyframes pulseGlow {
  0%, 100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4); }
  50% { box-shadow: 0 0 8px 2px rgba(34, 197, 94, 0.2); }
}
`

// ---------------------------------------------------------------------------
// Toast notification system
// ---------------------------------------------------------------------------

interface Toast {
  id: number
  message: string
  type: 'success' | 'error' | 'info'
}

let _toastId = 0

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null
  const border: Record<string, string> = {
    info: 'border-blue-500',
    success: 'border-green-500',
    error: 'border-red-500',
  }
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`bg-dark-800 border-l-4 ${border[t.type]} rounded-lg px-4 py-3 shadow-xl flex items-start gap-3`}
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <span className="text-sm text-dark-200 flex-1">{t.message}</span>
          <button onClick={() => onDismiss(t.id)} className="text-dark-500 hover:text-white transition-colors">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TerminalSessionSummary {
  session_id: string
  name: string
  target: string
  template_id: string | null
  messages_count: number
  commands_count: number
  created_at: string
}

interface TerminalMessage {
  role: 'user' | 'assistant' | 'tool' | 'system'
  content: string
  timestamp: string
  suggested_commands?: string[]
  exit_code?: number
  command?: string
  duration?: number
}

interface ExploitationStep {
  description: string
  command: string
  result: string
  step_type: 'recon' | 'exploit' | 'pivot' | 'escalate' | 'action'
  timestamp: string
}

interface TerminalSessionData {
  session_id: string
  name: string
  target: string
  template_id: string | null
  messages: TerminalMessage[]
  exploitation_path: ExploitationStep[]
  vpn_status: VpnStatus | null
  created_at: string
}

interface VpnStatus {
  connected: boolean
  ip: string | null
  interface: string | null
  latency_ms: number | null
}

interface SessionTemplate {
  id: string
  name: string
  description: string
  icon: string
  accent: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STEP_TYPE_COLORS: Record<string, string> = {
  recon: 'bg-blue-500',
  exploit: 'bg-red-500',
  pivot: 'bg-orange-500',
  escalate: 'bg-purple-500',
  action: 'bg-green-500',
}

const STEP_TYPE_TEXT_COLORS: Record<string, string> = {
  recon: 'text-blue-400',
  exploit: 'text-red-400',
  pivot: 'text-orange-400',
  escalate: 'text-purple-400',
  action: 'text-green-400',
}

const STEP_TYPE_BORDER_COLORS: Record<string, string> = {
  recon: 'border-blue-500/30',
  exploit: 'border-red-500/30',
  pivot: 'border-orange-500/30',
  escalate: 'border-purple-500/30',
  action: 'border-green-500/30',
}

const DEFAULT_TEMPLATES: SessionTemplate[] = [
  {
    id: 'network_scanner',
    name: 'Network Scanner',
    description: 'Discover hosts, open ports, and running services across a target network.',
    icon: 'globe',
    accent: 'blue',
  },
  {
    id: 'lateral_movement',
    name: 'Lateral Movement',
    description: 'Pivot across compromised hosts and expand access within the network.',
    icon: 'arrows',
    accent: 'orange',
  },
  {
    id: 'privilege_escalation',
    name: 'Privilege Escalation',
    description: 'Identify and exploit misconfigurations to elevate privileges on a host.',
    icon: 'shield',
    accent: 'red',
  },
  {
    id: 'vpn_recon',
    name: 'VPN Reconnaissance',
    description: 'Enumerate VPN endpoints, test credentials, and map internal networks.',
    icon: 'wifi',
    accent: 'green',
  },
]

const ACCENT_CLASSES: Record<string, { bg: string; border: string; text: string; icon: string }> = {
  blue: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30 hover:border-blue-500/60',
    text: 'text-blue-400',
    icon: 'text-blue-400',
  },
  orange: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30 hover:border-orange-500/60',
    text: 'text-orange-400',
    icon: 'text-orange-400',
  },
  red: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/30 hover:border-red-500/60',
    text: 'text-red-400',
    icon: 'text-red-400',
  },
  green: {
    bg: 'bg-green-500/10',
    border: 'border-green-500/30 hover:border-green-500/60',
    text: 'text-green-400',
    icon: 'text-green-400',
  },
}

// ---------------------------------------------------------------------------
// Helper: template icon component
// ---------------------------------------------------------------------------

function TemplateIcon({ icon, className }: { icon: string; className?: string }) {
  switch (icon) {
    case 'globe':
      return <Globe className={className} />
    case 'arrows':
      return <ArrowRightLeft className={className} />
    case 'shield':
      return <ShieldAlert className={className} />
    case 'wifi':
      return <Wifi className={className} />
    default:
      return <Terminal className={className} />
  }
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function TerminalAgentPage() {
  // Refs
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const promptInputRef = useRef<HTMLInputElement>(null)
  const commandInputRef = useRef<HTMLInputElement>(null)

  // Session list
  const [sessions, setSessions] = useState<TerminalSessionSummary[]>([])
  const [activeSession, setActiveSession] = useState<string | null>(null)
  const [sessionData, setSessionData] = useState<TerminalSessionData | null>(null)

  // Chat / command inputs
  const [message, setMessage] = useState('')
  const [command, setCommand] = useState('')
  const [useSandbox, setUseSandbox] = useState(true)

  // UI state
  const [loading, setLoading] = useState(false)
  const [sendingMessage, setSendingMessage] = useState(false)
  const [executingCommand, setExecutingCommand] = useState(false)
  const [showNewSession, setShowNewSession] = useState(false)
  const [newSessionTarget, setNewSessionTarget] = useState('')
  const [newSessionName, setNewSessionName] = useState('')
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null)
  const [templates, setTemplates] = useState<SessionTemplate[]>(DEFAULT_TEMPLATES)

  // Toast notifications
  const [toasts, setToasts] = useState<Toast[]>([])

  // VPN polling
  const [vpnStatus, setVpnStatus] = useState<VpnStatus | null>(null)

  // VPN upload/connect state
  const [vpnFile, setVpnFile] = useState<File | null>(null)
  const [vpnUsername, setVpnUsername] = useState('')
  const [vpnPassword, setVpnPassword] = useState('')
  const [vpnUploading, setVpnUploading] = useState(false)
  const [vpnConnecting, setVpnConnecting] = useState(false)
  const [vpnError, setVpnError] = useState<string | null>(null)
  const vpnFileInputRef = useRef<HTMLInputElement>(null)

  // ------------------------------------------------------------------
  // Toast helpers
  // ------------------------------------------------------------------

  const addToast = useCallback((message: string, type: Toast['type']) => {
    const id = ++_toastId
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  // ------------------------------------------------------------------
  // Derived data with useMemo
  // ------------------------------------------------------------------

  const sessionMessageCount = useMemo(() => {
    return sessionData?.messages.length ?? 0
  }, [sessionData?.messages])

  const exploitationStepCounts = useMemo(() => {
    if (!sessionData?.exploitation_path) return {}
    const counts: Record<string, number> = {}
    for (const step of sessionData.exploitation_path) {
      counts[step.step_type] = (counts[step.step_type] || 0) + 1
    }
    return counts
  }, [sessionData?.exploitation_path])

  const hasExploitationSteps = useMemo(() => {
    return (sessionData?.exploitation_path?.length ?? 0) > 0
  }, [sessionData?.exploitation_path])

  // ------------------------------------------------------------------
  // Load sessions + templates on mount
  // ------------------------------------------------------------------
  useEffect(() => {
    loadSessions()
    loadTemplates()
  }, [])

  // ------------------------------------------------------------------
  // Poll VPN status every 3 seconds for active session
  // ------------------------------------------------------------------
  useEffect(() => {
    if (!activeSession) return

    let cancelled = false

    const poll = async () => {
      try {
        const status = await terminalApi.getVpnStatus(activeSession)
        if (!cancelled) setVpnStatus(status)
      } catch {
        // VPN status is optional; ignore errors
      }
    }

    poll()
    const interval = setInterval(poll, 3000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [activeSession])

  // ------------------------------------------------------------------
  // Auto-scroll chat to bottom on new messages
  // ------------------------------------------------------------------
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [sessionData?.messages])

  // ------------------------------------------------------------------
  // Data loaders
  // ------------------------------------------------------------------

  const loadSessions = async () => {
    try {
      const data = await terminalApi.listSessions()
      setSessions(data.sessions || data || [])
    } catch (err) {
      console.error('Failed to load terminal sessions:', err)
    }
  }

  const loadTemplates = async () => {
    try {
      const data = await terminalApi.listTemplates()
      if (data && Array.isArray(data) && data.length > 0) {
        setTemplates(data)
      }
    } catch {
      // Fall back to DEFAULT_TEMPLATES already set
    }
  }

  const loadSession = useCallback(async (sessionId: string) => {
    setLoading(true)
    try {
      const data = await terminalApi.getSession(sessionId)
      setActiveSession(sessionId)
      setSessionData(data)
      if (data.vpn_status) setVpnStatus(data.vpn_status)
    } catch (err) {
      console.error('Failed to load session:', err)
      addToast('Failed to load session', 'error')
    } finally {
      setLoading(false)
    }
  }, [addToast])

  // ------------------------------------------------------------------
  // Session CRUD
  // ------------------------------------------------------------------

  const createSession = async () => {
    if (!newSessionTarget.trim()) return
    setLoading(true)
    try {
      const result = await terminalApi.createSession(
        newSessionTarget.trim(),
        newSessionName.trim() || undefined,
        selectedTemplate || undefined,
      )
      await loadSessions()
      await loadSession(result.session_id)
      setShowNewSession(false)
      setNewSessionTarget('')
      setNewSessionName('')
      setSelectedTemplate(null)
      addToast('Session created successfully', 'success')
    } catch (err) {
      console.error('Failed to create session:', err)
      addToast('Failed to create session', 'error')
    } finally {
      setLoading(false)
    }
  }

  const deleteSession = async (sessionId: string) => {
    if (!confirm('Delete this terminal session?')) return
    try {
      await terminalApi.deleteSession(sessionId)
      if (activeSession === sessionId) {
        setActiveSession(null)
        setSessionData(null)
        setVpnStatus(null)
      }
      await loadSessions()
      addToast('Session deleted', 'info')
    } catch (err) {
      console.error('Failed to delete session:', err)
      addToast('Failed to delete session', 'error')
    }
  }

  // ------------------------------------------------------------------
  // Messaging
  // ------------------------------------------------------------------

  const sendMessage = async () => {
    if (!message.trim() || !activeSession || sendingMessage) return

    const userMsg: TerminalMessage = {
      role: 'user',
      content: message.trim(),
      timestamp: new Date().toISOString(),
    }

    setSessionData(prev =>
      prev ? { ...prev, messages: [...prev.messages, userMsg] } : prev,
    )
    setMessage('')
    setSendingMessage(true)

    try {
      const result = await terminalApi.sendMessage(activeSession, message.trim())

      const assistantMsg: TerminalMessage = {
        role: 'assistant',
        content: result.response,
        timestamp: new Date().toISOString(),
        suggested_commands: result.suggested_commands || [],
      }

      setSessionData(prev =>
        prev ? { ...prev, messages: [...prev.messages, assistantMsg] } : prev,
      )
      promptInputRef.current?.focus()
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } }; message?: string }
      const errorMsg: TerminalMessage = {
        role: 'system',
        content: `Error: ${error?.response?.data?.detail || error?.message || 'Failed to send message'}`,
        timestamp: new Date().toISOString(),
      }
      setSessionData(prev =>
        prev ? { ...prev, messages: [...prev.messages, errorMsg] } : prev,
      )
      addToast('Failed to send message', 'error')
    } finally {
      setSendingMessage(false)
    }
  }

  // ------------------------------------------------------------------
  // Command execution
  // ------------------------------------------------------------------

  const executeCommand = useCallback(async (cmd?: string) => {
    const toRun = cmd || command
    if (!toRun.trim() || !activeSession || executingCommand) return

    const userCmd: TerminalMessage = {
      role: 'user',
      content: `$ ${toRun.trim()}`,
      timestamp: new Date().toISOString(),
    }

    setSessionData(prev =>
      prev ? { ...prev, messages: [...prev.messages, userCmd] } : prev,
    )
    if (!cmd) setCommand('')
    setExecutingCommand(true)

    try {
      const result = await terminalApi.executeCommand(
        activeSession,
        toRun.trim(),
        useSandbox ? 'sandbox' : 'direct',
      )

      const output = [
        result.stdout || '',
        result.stderr ? `\n[stderr]\n${result.stderr}` : '',
      ]
        .filter(Boolean)
        .join('')

      const toolMsg: TerminalMessage = {
        role: 'tool',
        content: output || '(no output)',
        timestamp: new Date().toISOString(),
        exit_code: result.exit_code,
        command: result.command,
        duration: result.duration,
      }

      setSessionData(prev =>
        prev ? { ...prev, messages: [...prev.messages, toolMsg] } : prev,
      )
      commandInputRef.current?.focus()
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } }; message?: string }
      const errorMsg: TerminalMessage = {
        role: 'tool',
        content: error?.response?.data?.detail || error?.message || 'Command execution failed',
        timestamp: new Date().toISOString(),
        exit_code: -1,
      }
      setSessionData(prev =>
        prev ? { ...prev, messages: [...prev.messages, errorMsg] } : prev,
      )
      addToast('Command execution failed', 'error')
    } finally {
      setExecutingCommand(false)
    }
  }, [activeSession, command, executingCommand, useSandbox, addToast])

  // ------------------------------------------------------------------
  // Exploitation path refresh
  // ------------------------------------------------------------------

  const refreshExploitationPath = useCallback(async () => {
    if (!activeSession) return
    try {
      const path = await terminalApi.getExploitationPath(activeSession)
      setSessionData(prev =>
        prev ? { ...prev, exploitation_path: path.steps || path || [] } : prev,
      )
    } catch {
      // non-critical
    }
  }, [activeSession])

  // Refresh exploitation path when messages change
  useEffect(() => {
    if (activeSession && sessionData && sessionData.messages.length > 0) {
      refreshExploitationPath()
    }
  }, [activeSession, sessionData?.messages.length, refreshExploitationPath])

  // ------------------------------------------------------------------
  // VPN handlers
  // ------------------------------------------------------------------

  const handleVpnUploadAndConnect = async () => {
    if (!vpnFile || !activeSession) return
    setVpnUploading(true)
    setVpnError(null)
    try {
      await terminalApi.uploadVpnConfig(
        activeSession,
        vpnFile,
        vpnUsername || undefined,
        vpnPassword || undefined,
      )
      setVpnUploading(false)
      setVpnConnecting(true)
      await terminalApi.connectVpn(activeSession)
      setVpnFile(null)
      setVpnUsername('')
      setVpnPassword('')
      addToast('VPN connected successfully', 'success')
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } }; message?: string }
      const errMsg = error?.response?.data?.detail || error?.message || 'VPN connection failed'
      setVpnError(errMsg)
      addToast(errMsg, 'error')
    } finally {
      setVpnUploading(false)
      setVpnConnecting(false)
    }
  }

  const handleVpnDisconnect = async () => {
    if (!activeSession) return
    try {
      await terminalApi.disconnectVpn(activeSession)
      addToast('VPN disconnected', 'info')
    } catch {
      addToast('Failed to disconnect VPN', 'error')
    }
  }

  // ------------------------------------------------------------------
  // Render helpers
  // ------------------------------------------------------------------

  const renderMessage = useCallback((msg: TerminalMessage, index: number) => {
    const animDelay = `${Math.min(index * 0.02, 0.3)}s`

    switch (msg.role) {
      case 'user':
        return (
          <div key={index} className="flex justify-end" style={{ animation: `fadeSlideIn 0.3s ease-out ${animDelay} both` }}>
            <div className="max-w-[80%] rounded-xl px-4 py-3 border-l-4 border-primary-500 bg-dark-800 text-white shadow-lg hover:shadow-xl transition-shadow">
              <div className="whitespace-pre-wrap text-sm leading-relaxed break-words">
                {msg.content}
              </div>
              <div className="flex items-center gap-1.5 text-[10px] mt-2 text-dark-500">
                <Clock className="w-2.5 h-2.5" />
                {new Date(msg.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </div>
        )

      case 'assistant':
        return (
          <div key={index} className="flex justify-start" style={{ animation: `fadeSlideIn 0.3s ease-out ${animDelay} both` }}>
            <div className="max-w-[85%] rounded-xl px-4 py-3 bg-dark-800/80 text-dark-200 shadow-lg border border-dark-700/50 hover:shadow-xl transition-shadow">
              <div className="flex items-center gap-2 mb-2 text-xs text-dark-400">
                <div className="p-1 bg-primary-500/20 rounded">
                  <Bot className="w-3 h-3 text-primary-500" />
                </div>
                <span className="font-medium">Terminal Agent</span>
              </div>
              <div className="whitespace-pre-wrap text-sm leading-relaxed break-words">
                {msg.content}
              </div>

              {/* Suggested commands */}
              {msg.suggested_commands && msg.suggested_commands.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-dark-700/50">
                  {msg.suggested_commands.map((cmd, i) => (
                    <button
                      key={i}
                      onClick={() => executeCommand(cmd)}
                      disabled={executingCommand}
                      className="px-3 py-1.5 text-xs font-mono bg-green-500/10 text-green-400 rounded-lg hover:bg-green-500/20 transition-all disabled:opacity-50 flex items-center gap-1.5 border border-green-500/20 hover:border-green-500/40 hover:scale-[1.02] active:scale-[0.98]"
                    >
                      <Play className="w-3 h-3" />
                      {cmd}
                    </button>
                  ))}
                </div>
              )}

              <div className="flex items-center gap-1.5 text-[10px] mt-2 text-dark-500">
                <Clock className="w-2.5 h-2.5" />
                {new Date(msg.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </div>
        )

      case 'tool':
        return (
          <div key={index} className="flex justify-start" style={{ animation: `fadeSlideIn 0.3s ease-out ${animDelay} both` }}>
            <div
              className={`max-w-[90%] rounded-xl px-4 py-3 bg-dark-950 shadow-lg border-l-4 ${
                msg.exit_code !== undefined && msg.exit_code !== 0
                  ? 'border-red-500'
                  : 'border-green-500/50'
              }`}
            >
              {/* Command header */}
              {msg.command && (
                <div className="flex items-center gap-2 mb-2 text-xs flex-wrap">
                  <div className="p-1 bg-green-500/10 rounded">
                    <Terminal className="w-3 h-3 text-green-400" />
                  </div>
                  <span className="font-mono text-green-400">{msg.command}</span>
                  {msg.exit_code !== undefined && (
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                        msg.exit_code === 0
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-red-500/10 text-red-400'
                      }`}
                    >
                      exit {msg.exit_code}
                    </span>
                  )}
                  {msg.duration !== undefined && (
                    <span className="text-dark-500 flex items-center gap-1">
                      <Zap className="w-2.5 h-2.5" />
                      {msg.duration < 1 ? '<1s' : `${msg.duration.toFixed(1)}s`}
                    </span>
                  )}
                </div>
              )}
              <pre className="font-mono text-xs text-green-400 whitespace-pre-wrap break-all leading-relaxed max-h-80 overflow-y-auto scrollbar-thin scrollbar-thumb-dark-600">
                {msg.content}
              </pre>
              <div className="flex items-center gap-1.5 text-[10px] mt-2 text-dark-500">
                <Clock className="w-2.5 h-2.5" />
                {new Date(msg.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </div>
        )

      case 'system':
        return (
          <div key={index} className="flex justify-center" style={{ animation: `fadeSlideIn 0.3s ease-out ${animDelay} both` }}>
            <p className="text-dark-400 text-xs italic text-center px-4 py-2 max-w-[70%] bg-dark-800/30 rounded-lg border border-dark-700/30">
              {msg.content}
            </p>
          </div>
        )

      default:
        return null
    }
  }, [executeCommand, executingCommand])

  // ------------------------------------------------------------------
  // JSX
  // ------------------------------------------------------------------

  return (
    <>
      {/* Inline keyframes */}
      <style>{styleTag}</style>

      {/* Toast notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="h-[calc(100vh-80px)] flex gap-0" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
        {/* ====== LEFT PANEL: Sessions ====== */}
        <div className="w-72 flex-shrink-0 bg-dark-800 border-r border-dark-700 flex flex-col">
          {/* Header */}
          <div className="p-4 border-b border-dark-700" style={{ animation: 'fadeSlideIn 0.3s ease-out 0.05s both' }}>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-white font-semibold flex items-center gap-2">
                <div className="p-1.5 bg-primary-500/20 rounded-lg">
                  <Terminal className="w-4.5 h-4.5 text-primary-500" />
                </div>
                Terminal Agent
              </h2>
            </div>
            <button
              onClick={() => setShowNewSession(true)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-primary-500 hover:bg-primary-600 text-white text-sm font-medium rounded-lg transition-all hover:shadow-lg hover:shadow-primary-500/20 active:scale-[0.98]"
            >
              <Plus className="w-4 h-4" />
              New Session
            </button>
          </div>

          {/* Sessions list */}
          <div className="flex-1 overflow-y-auto p-3 space-y-1.5">
            {sessions.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                <div className="w-12 h-12 bg-dark-700/50 rounded-xl flex items-center justify-center mb-3">
                  <MessageSquare className="w-6 h-6 text-dark-600" />
                </div>
                <p className="text-dark-500 text-sm font-medium mb-1">No sessions yet</p>
                <p className="text-dark-600 text-xs">Create a new session to get started</p>
              </div>
            ) : (
              sessions.map((s, idx) => (
                <div
                  key={s.session_id}
                  onClick={() => loadSession(s.session_id)}
                  style={{ animation: `fadeSlideIn 0.3s ease-out ${0.03 * idx}s both` }}
                  className={`p-3 rounded-lg cursor-pointer transition-all group ${
                    activeSession === s.session_id
                      ? 'bg-primary-500/15 text-primary-500 border border-primary-500/30 shadow-md shadow-primary-500/5'
                      : 'bg-dark-900/50 hover:bg-dark-900 border border-transparent hover:border-dark-700 text-dark-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <p className="font-medium text-sm truncate flex-1">
                      {s.name || s.target}
                    </p>
                    <button
                      onClick={e => {
                        e.stopPropagation()
                        deleteSession(s.session_id)
                      }}
                      className="p-1 text-dark-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all rounded hover:bg-red-500/10"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <p className="text-dark-500 text-xs truncate mt-0.5 flex items-center gap-1">
                    <Globe className="w-3 h-3" />
                    {s.target}
                  </p>
                  <div className="flex items-center gap-3 mt-1.5 text-[10px] text-dark-500">
                    <span className="flex items-center gap-1">
                      <MessageSquare className="w-2.5 h-2.5" />
                      {s.messages_count}
                    </span>
                    <span className="flex items-center gap-1">
                      <Command className="w-2.5 h-2.5" />
                      {s.commands_count}
                    </span>
                    {s.template_id && (
                      <span className="bg-dark-700 px-1.5 py-0.5 rounded text-dark-400">
                        {s.template_id.replace(/_/g, ' ')}
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* ====== CENTER PANEL: Chat / Terminal ====== */}
        <div className="flex-1 flex flex-col bg-dark-900 min-w-0">
          {activeSession && sessionData ? (
            <>
              {/* Session header bar */}
              <div
                className="flex items-center justify-between px-6 py-3 border-b border-dark-700 bg-dark-800/50 flex-shrink-0 backdrop-blur-sm"
                style={{ animation: 'fadeSlideIn 0.3s ease-out 0.1s both' }}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="p-1.5 bg-primary-500/20 rounded-lg flex-shrink-0">
                    <Terminal className="w-4 h-4 text-primary-500" />
                  </div>
                  <div className="min-w-0">
                    <h3 className="text-white font-medium text-sm truncate">
                      {sessionData.name || 'Terminal Session'}
                    </h3>
                    <p className="text-dark-400 text-xs truncate flex items-center gap-1">
                      <Globe className="w-2.5 h-2.5" />
                      {sessionData.target}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {sessionData.template_id && (
                    <span className="text-dark-400 text-xs bg-dark-700/80 px-2.5 py-1 rounded-md border border-dark-600/50">
                      {sessionData.template_id.replace(/_/g, ' ')}
                    </span>
                  )}
                  <span className="text-dark-500 text-xs flex items-center gap-1">
                    <MessageSquare className="w-3 h-3" />
                    {sessionMessageCount}
                  </span>
                </div>
              </div>

              {/* Messages area */}
              <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4 scroll-smooth">
                {sessionData.messages.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-center" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                    <div className="w-20 h-20 bg-gradient-to-br from-primary-500/10 to-green-500/10 rounded-2xl flex items-center justify-center mb-4 border border-dark-700/50">
                      <Terminal className="w-10 h-10 text-dark-500" />
                    </div>
                    <p className="text-dark-300 text-sm font-medium mb-1">Session ready</p>
                    <p className="text-dark-500 text-xs max-w-md leading-relaxed">
                      Use the prompt input to ask the AI agent for guidance, or use the
                      command input to execute commands directly on the target.
                    </p>
                    <div className="flex items-center gap-4 mt-4">
                      <div className="flex items-center gap-1.5 text-dark-500 text-xs">
                        <Send className="w-3 h-3 text-primary-500" />
                        <span>Chat with AI</span>
                      </div>
                      <div className="w-px h-3 bg-dark-700" />
                      <div className="flex items-center gap-1.5 text-dark-500 text-xs">
                        <Play className="w-3 h-3 text-green-500" />
                        <span>Execute commands</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  sessionData.messages.map((msg, i) => renderMessage(msg, i))
                )}

                {/* Loading indicators */}
                {sendingMessage && (
                  <div className="flex justify-start" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                    <div className="flex items-center gap-2 px-4 py-3 bg-dark-800 border border-dark-700/50 rounded-xl text-dark-400 text-sm shadow-md">
                      <Loader2 className="w-4 h-4 animate-spin text-primary-500" />
                      <span>Agent is thinking</span>
                      <span style={{ animation: 'terminalBlink 1.5s ease-in-out infinite' }}>...</span>
                    </div>
                  </div>
                )}
                {executingCommand && (
                  <div className="flex justify-start" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                    <div className="flex items-center gap-2 px-4 py-3 bg-dark-950 border border-green-500/20 rounded-xl text-green-400 text-sm font-mono shadow-md">
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Executing command</span>
                      <span style={{ animation: 'terminalBlink 1.5s ease-in-out infinite' }}>...</span>
                    </div>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>

              {/* Dual input bar */}
              <div className="border-t border-dark-700 bg-dark-800 px-6 py-4 flex-shrink-0 space-y-3" style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}>
                {/* Prompt input row */}
                <div className="flex gap-2">
                  <div className="flex-1 relative">
                    <input
                      ref={promptInputRef}
                      type="text"
                      value={message}
                      onChange={e => setMessage(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault()
                          sendMessage()
                        }
                      }}
                      placeholder="Ask the AI agent for guidance..."
                      disabled={sendingMessage || executingCommand}
                      className="w-full bg-dark-900 border border-dark-700 rounded-lg pl-10 pr-4 py-2.5 text-white text-sm placeholder-dark-500 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 disabled:opacity-50 transition-all"
                    />
                    <Bot className="w-4 h-4 text-dark-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  </div>
                  <button
                    onClick={sendMessage}
                    disabled={!message.trim() || sendingMessage || executingCommand}
                    className="px-4 py-2.5 bg-primary-500 hover:bg-primary-600 text-white rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5 hover:shadow-lg hover:shadow-primary-500/20 active:scale-[0.97]"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </div>

                {/* Command input row */}
                <div className="flex gap-2 items-center">
                  <div className="flex-1 flex items-center bg-dark-950 border border-dark-700 rounded-lg overflow-hidden focus-within:border-green-500/50 focus-within:ring-1 focus-within:ring-green-500/30 transition-all">
                    <span className="pl-4 pr-1 text-green-400 font-mono text-sm select-none">$</span>
                    <input
                      ref={commandInputRef}
                      type="text"
                      value={command}
                      onChange={e => setCommand(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault()
                          executeCommand()
                        }
                      }}
                      placeholder="Enter command to execute..."
                      disabled={sendingMessage || executingCommand}
                      className="flex-1 bg-transparent py-2.5 pr-4 text-green-400 font-mono text-sm placeholder-dark-500 focus:outline-none disabled:opacity-50"
                    />
                  </div>
                  <button
                    onClick={() => executeCommand()}
                    disabled={!command.trim() || sendingMessage || executingCommand}
                    className="px-4 py-2.5 bg-green-500/20 hover:bg-green-500/30 text-green-400 border border-green-500/30 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5 hover:shadow-lg hover:shadow-green-500/10 active:scale-[0.97]"
                  >
                    <Play className="w-4 h-4" />
                  </button>

                  {/* Sandbox toggle */}
                  <div className="flex items-center gap-2 pl-2 border-l border-dark-700">
                    <button
                      onClick={() => setUseSandbox(!useSandbox)}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                        useSandbox ? 'bg-green-500' : 'bg-red-500/60'
                      }`}
                    >
                      <span
                        className="inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform shadow-sm"
                        style={{ transform: useSandbox ? 'translateX(16px)' : 'translateX(2px)' }}
                      />
                    </button>
                    <span className={`text-xs font-medium whitespace-nowrap ${useSandbox ? 'text-green-400' : 'text-red-400'}`}>
                      {useSandbox ? 'Sandbox' : 'Direct'}
                    </span>
                  </div>
                </div>
              </div>
            </>
          ) : (
            /* No active session placeholder */
            <div className="flex-1 flex flex-col items-center justify-center" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
              <div className="w-20 h-20 bg-gradient-to-br from-primary-500/20 to-green-500/20 rounded-2xl flex items-center justify-center mb-6 border border-dark-700/50 shadow-lg shadow-primary-500/5">
                <Terminal className="w-10 h-10 text-primary-400" />
              </div>
              <h3 className="text-white text-lg font-semibold mb-2">Terminal Agent</h3>
              <p className="text-dark-400 text-center mb-8 max-w-md text-sm leading-relaxed">
                Interactive AI-assisted terminal for infrastructure pentesting.
                Create a new session or select an existing one to get started.
              </p>
              <button
                onClick={() => setShowNewSession(true)}
                className="flex items-center gap-2 px-6 py-3 bg-primary-500 hover:bg-primary-600 text-white font-medium rounded-lg transition-all hover:shadow-lg hover:shadow-primary-500/20 active:scale-[0.98]"
              >
                <Plus className="w-4 h-4" />
                New Session
              </button>
              {loading && (
                <div className="flex items-center gap-2 mt-4 text-dark-400 text-sm" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Loading...
                </div>
              )}
            </div>
          )}
        </div>

        {/* ====== RIGHT PANEL: Exploitation Path + VPN ====== */}
        <div className="w-72 flex-shrink-0 bg-dark-800 border-l border-dark-700 flex flex-col">
          {/* VPN Connection Panel */}
          <div className="p-4 border-b border-dark-700" style={{ animation: 'fadeSlideIn 0.3s ease-out 0.1s both' }}>
            <h3 className="text-dark-300 text-xs font-semibold uppercase tracking-wider mb-3 flex items-center gap-2">
              <Wifi className="w-3.5 h-3.5 text-dark-500" />
              VPN Connection
            </h3>

            {vpnStatus?.connected ? (
              <div
                className="flex items-center gap-3 p-3 rounded-lg border bg-green-500/10 border-green-500/30 mb-3"
                style={{ animation: 'pulseGlow 3s ease-in-out infinite' }}
              >
                <div className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-green-400">Connected</p>
                  {vpnStatus.ip && <p className="text-xs text-dark-400 font-mono truncate">{vpnStatus.ip}</p>}
                  {vpnStatus.interface && <p className="text-xs text-dark-500 truncate">{vpnStatus.interface}</p>}
                  {vpnStatus.latency_ms != null && (
                    <p className="text-xs text-dark-500">{vpnStatus.latency_ms}ms latency</p>
                  )}
                </div>
                <button
                  onClick={handleVpnDisconnect}
                  className="text-xs px-2 py-1 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition-all hover:scale-105 active:scale-95"
                >
                  Disconnect
                </button>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-3 p-3 rounded-lg border bg-dark-900 border-dark-700 mb-3">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500 flex-shrink-0" />
                  <span className="text-dark-400 text-sm">
                    {activeSession ? 'Not connected' : 'No session'}
                  </span>
                </div>

                {activeSession && (
                  <div className="space-y-2" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                    <input
                      ref={vpnFileInputRef}
                      type="file"
                      accept=".ovpn,.conf"
                      onChange={(e) => setVpnFile(e.target.files?.[0] || null)}
                      className="hidden"
                    />
                    <button
                      onClick={() => vpnFileInputRef.current?.click()}
                      className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs bg-dark-900 border border-dark-700 rounded-lg text-dark-300 hover:border-dark-600 transition-all hover:bg-dark-850 active:scale-[0.98]"
                    >
                      <Upload className="w-3.5 h-3.5" />
                      {vpnFile ? (
                        <span className="truncate">{vpnFile.name}</span>
                      ) : (
                        'Select .ovpn file'
                      )}
                    </button>

                    {vpnFile && (
                      <div className="space-y-2" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                        <input
                          type="text"
                          placeholder="VPN Username (optional)"
                          value={vpnUsername}
                          onChange={(e) => setVpnUsername(e.target.value)}
                          className="w-full px-3 py-1.5 text-xs bg-dark-900 border border-dark-700 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:border-green-500/50 transition-all"
                        />
                        <input
                          type="password"
                          placeholder="VPN Password (optional)"
                          value={vpnPassword}
                          onChange={(e) => setVpnPassword(e.target.value)}
                          className="w-full px-3 py-1.5 text-xs bg-dark-900 border border-dark-700 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:border-green-500/50 transition-all"
                        />
                        <button
                          onClick={handleVpnUploadAndConnect}
                          disabled={vpnUploading || vpnConnecting}
                          className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg hover:bg-green-500/30 transition-all disabled:opacity-50 active:scale-[0.98]"
                        >
                          {vpnUploading || vpnConnecting ? (
                            <>
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              {vpnUploading ? 'Uploading...' : 'Connecting...'}
                            </>
                          ) : (
                            <>
                              <Wifi className="w-3.5 h-3.5" />
                              Connect VPN
                            </>
                          )}
                        </button>
                      </div>
                    )}

                    {vpnError && (
                      <p className="text-red-400 text-xs mt-1 flex items-center gap-1" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                        <X className="w-3 h-3 flex-shrink-0" />
                        {vpnError}
                      </p>
                    )}
                  </div>
                )}
              </>
            )}
          </div>

          {/* Exploitation path */}
          <div className="flex-1 overflow-y-auto p-4" style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}>
            <h3 className="text-dark-300 text-xs font-semibold uppercase tracking-wider mb-4 flex items-center gap-2">
              <ChevronRight className="w-3.5 h-3.5 text-dark-500" />
              Exploitation Path
              {hasExploitationSteps && (
                <span className="ml-auto text-dark-500 text-[10px] font-normal normal-case">
                  {sessionData?.exploitation_path.length} steps
                </span>
              )}
            </h3>

            {hasExploitationSteps && sessionData ? (
              <div className="relative">
                {/* Vertical timeline line */}
                <div className="absolute left-[7px] top-2 bottom-2 w-0.5 bg-gradient-to-b from-dark-600 via-dark-700 to-transparent" />

                <div className="space-y-4">
                  {sessionData.exploitation_path.map((step, i) => {
                    const dotColor = STEP_TYPE_COLORS[step.step_type] || 'bg-dark-500'
                    const textColor = STEP_TYPE_TEXT_COLORS[step.step_type] || 'text-dark-400'
                    const borderColor = STEP_TYPE_BORDER_COLORS[step.step_type] || 'border-dark-700'

                    return (
                      <div
                        key={i}
                        className="relative pl-6"
                        style={{ animation: `fadeSlideIn 0.3s ease-out ${0.05 * i}s both` }}
                      >
                        {/* Timeline dot */}
                        <div
                          className={`absolute left-0 top-1 w-[15px] h-[15px] rounded-full border-2 border-dark-800 ${dotColor} z-10`}
                        />

                        <div className={`bg-dark-900 rounded-lg p-3 border ${borderColor} hover:border-opacity-60 transition-all hover:shadow-sm`}>
                          {/* Step type label */}
                          <span
                            className={`text-[10px] font-semibold uppercase tracking-wider ${textColor}`}
                          >
                            {step.step_type}
                          </span>

                          {/* Description */}
                          <p className="text-dark-300 text-xs mt-1 leading-relaxed">
                            {step.description}
                          </p>

                          {/* Command */}
                          {step.command && (
                            <p className="font-mono text-[10px] text-green-400/70 mt-1.5 truncate bg-dark-950 px-2 py-1 rounded border border-dark-800">
                              $ {step.command}
                            </p>
                          )}

                          {/* Result preview */}
                          {step.result && (
                            <p className="text-dark-500 text-[10px] mt-1 truncate">
                              {step.result}
                            </p>
                          )}

                          {/* Timestamp */}
                          <p className="text-dark-600 text-[9px] mt-1.5 flex items-center gap-1">
                            <Clock className="w-2 h-2" />
                            {new Date(step.timestamp).toLocaleTimeString()}
                          </p>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center text-center py-8" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                <div className="w-12 h-12 bg-dark-700/30 rounded-xl flex items-center justify-center mb-3 border border-dark-700/50">
                  <Circle className="w-6 h-6 text-dark-600" />
                </div>
                <p className="text-dark-500 text-xs leading-relaxed max-w-[180px]">
                  {activeSession
                    ? 'No exploitation steps yet. Start interacting to build the attack path.'
                    : 'Select a session to view the exploitation path.'}
                </p>
              </div>
            )}
          </div>

          {/* Step type legend */}
          {hasExploitationSteps && (
            <div className="p-4 border-t border-dark-700" style={{ animation: 'fadeSlideIn 0.3s ease-out 0.2s both' }}>
              <div className="flex flex-wrap gap-x-3 gap-y-1.5">
                {Object.entries(STEP_TYPE_COLORS).map(([type, color]) => (
                  <div key={type} className="flex items-center gap-1.5">
                    <div className={`w-2 h-2 rounded-full ${color}`} />
                    <span className="text-dark-500 text-[10px] capitalize">
                      {type}
                      {exploitationStepCounts[type] ? ` (${exploitationStepCounts[type]})` : ''}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ====== NEW SESSION MODAL ====== */}
        {showNewSession && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
            <div
              className="bg-dark-800 border border-dark-700 rounded-2xl w-full max-w-lg mx-4 shadow-2xl"
              style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
            >
              {/* Modal header */}
              <div className="flex items-center justify-between p-6 pb-4">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <div className="p-1.5 bg-primary-500/20 rounded-lg">
                    <Terminal className="w-5 h-5 text-primary-500" />
                  </div>
                  New Terminal Session
                </h3>
                <button
                  onClick={() => {
                    setShowNewSession(false)
                    setSelectedTemplate(null)
                    setNewSessionTarget('')
                    setNewSessionName('')
                  }}
                  className="text-dark-400 hover:text-white transition-colors p-1 hover:bg-dark-700 rounded-lg"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="px-6 pb-6 space-y-5">
                {/* Template selector grid */}
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-2">
                    Session Template
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    {templates.map((tmpl, idx) => {
                      const accent = ACCENT_CLASSES[tmpl.accent] || ACCENT_CLASSES.blue
                      const isSelected = selectedTemplate === tmpl.id

                      return (
                        <button
                          key={tmpl.id}
                          onClick={() =>
                            setSelectedTemplate(isSelected ? null : tmpl.id)
                          }
                          style={{ animation: `fadeSlideIn 0.3s ease-out ${0.05 * idx}s both` }}
                          className={`p-4 rounded-xl border text-left transition-all hover:scale-[1.02] active:scale-[0.98] ${
                            isSelected
                              ? `${accent.bg} ${accent.border.replace('hover:', '')} ring-1 ring-${tmpl.accent}-500/30 shadow-md`
                              : `bg-dark-900 border-dark-700 hover:border-dark-600`
                          }`}
                        >
                          <TemplateIcon
                            icon={tmpl.icon}
                            className={`w-6 h-6 mb-2 ${
                              isSelected ? accent.icon : 'text-dark-500'
                            }`}
                          />
                          <p
                            className={`text-sm font-medium ${
                              isSelected ? accent.text : 'text-dark-300'
                            }`}
                          >
                            {tmpl.name}
                          </p>
                          <p className="text-dark-500 text-xs mt-1 leading-relaxed line-clamp-2">
                            {tmpl.description}
                          </p>
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* Target input */}
                <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.2s both' }}>
                  <label className="block text-sm font-medium text-dark-300 mb-1.5">
                    Target <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    value={newSessionTarget}
                    onChange={e => setNewSessionTarget(e.target.value)}
                    placeholder="10.10.10.1 or 192.168.1.0/24 or vpn.target.htb"
                    autoFocus
                    className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-white text-sm placeholder-dark-500 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 transition-all"
                  />
                </div>

                {/* Session name */}
                <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.25s both' }}>
                  <label className="block text-sm font-medium text-dark-300 mb-1.5">
                    Session Name <span className="text-dark-600">(optional)</span>
                  </label>
                  <input
                    type="text"
                    value={newSessionName}
                    onChange={e => setNewSessionName(e.target.value)}
                    placeholder="e.g. HTB Machine - Recon Phase"
                    className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-white text-sm placeholder-dark-500 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 transition-all"
                  />
                </div>

                {/* Action buttons */}
                <div className="flex justify-end gap-3 pt-2" style={{ animation: 'fadeSlideIn 0.3s ease-out 0.3s both' }}>
                  <button
                    onClick={() => {
                      setShowNewSession(false)
                      setSelectedTemplate(null)
                      setNewSessionTarget('')
                      setNewSessionName('')
                    }}
                    className="px-4 py-2 text-sm text-dark-400 hover:text-white transition-colors rounded-lg hover:bg-dark-700"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={createSession}
                    disabled={!newSessionTarget.trim() || loading}
                    className="flex items-center gap-2 px-5 py-2 bg-primary-500 hover:bg-primary-600 text-white text-sm font-medium rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-lg hover:shadow-primary-500/20 active:scale-[0.97]"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Creating...
                      </>
                    ) : (
                      <>
                        <Plus className="w-4 h-4" />
                        Create Session
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  )
}
