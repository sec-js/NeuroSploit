import { useEffect, useMemo, useState, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Globe, FileText, StopCircle, RefreshCw, ChevronDown, ChevronRight,
  ExternalLink, Copy, Shield, AlertTriangle, Cpu, CheckCircle, XCircle, Clock,
  SkipForward, Check, Minus, Pause, Play, Download, Sparkles, Bug, Search,
  ScrollText, X, Terminal
} from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { SeverityBadge } from '../components/common/Badge'
import { scansApi, reportsApi, agentTasksApi, agentApi, vulnerabilitiesApi, providersApi } from '../services/api'
import { wsService } from '../services/websocket'
import { useScanStore } from '../store'
import type { Endpoint, Vulnerability, WSMessage, ScanAgentTask, Report, AgentStatus, AgentFinding, AgentLog, ToolExecution, ContainerStatus } from '../types'

// ─── Constants ────────────────────────────────────────────────────────────────

const POLL_INTERVAL = 4000
const POLL_INTERVAL_ERROR = 8000
const TOAST_DURATION = 5000
const MAX_TOASTS = 5

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500',
  low: 'bg-blue-500', info: 'bg-gray-500',
}

const SEVERITY_CHART_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280',
}

const CONFIDENCE_STYLES: Record<string, string> = {
  green: 'bg-green-500/15 text-green-400 border-green-500/30',
  yellow: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  red: 'bg-red-500/15 text-red-400 border-red-500/30',
}

const LOG_FILTERS = [
  { key: 'all', label: 'All', color: '' },
  { key: 'stream1', label: 'Recon', color: 'text-blue-400' },
  { key: 'stream2', label: 'Junior', color: 'text-purple-400' },
  { key: 'stream3', label: 'Tools', color: 'text-orange-400' },
  { key: 'deep', label: 'Deep', color: 'text-cyan-400' },
  { key: 'error', label: 'Errors', color: 'text-red-400' },
]

// ─── Types ────────────────────────────────────────────────────────────────────

interface Toast {
  id: string
  message: string
  severity: string
  timestamp: number
}

// ─── Utility Functions ────────────────────────────────────────────────────────

function formatElapsed(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600)
  const m = Math.floor((totalSeconds % 3600) / 60)
  const s = totalSeconds % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
}

function getConfidenceDisplay(finding: { confidence_score?: number; confidence?: string }): { score: number; color: string; label: string } | null {
  let score: number | null = null

  if (typeof finding.confidence_score === 'number') {
    score = finding.confidence_score
  } else if (finding.confidence) {
    const parsed = Number(finding.confidence)
    if (!isNaN(parsed)) {
      score = parsed
    } else {
      const map: Record<string, number> = { high: 90, medium: 60, low: 30 }
      score = map[finding.confidence.toLowerCase()] ?? null
    }
  }

  if (score === null || score === undefined) {
    return { score: 0, color: 'red', label: 'Unknown' }
  }

  const color = score >= 90 ? 'green' : score >= 60 ? 'yellow' : 'red'
  const label = score >= 90 ? 'Confirmed' : score >= 60 ? 'Likely' : score > 0 ? 'Low' : 'Rejected'
  return { score, color, label }
}

function logMessageColor(message: string): string {
  if (message.startsWith('[STREAM 1]')) return 'text-blue-400'
  if (message.startsWith('[STREAM 2]')) return 'text-purple-400'
  if (message.startsWith('[STREAM 3]')) return 'text-orange-400'
  if (message.startsWith('[TOOL]')) return 'text-orange-300'
  if (message.startsWith('[DEEP]')) return 'text-cyan-400'
  if (message.startsWith('[FINAL]')) return 'text-green-400'
  if (message.startsWith('[CONTAINER]')) return 'text-cyan-300'
  if (message.startsWith('[PHASE]')) return 'text-yellow-400'
  if (message.startsWith('[WAF]')) return 'text-amber-400'
  if (message.startsWith('[SITE ANALYZER]')) return 'text-emerald-400'
  return ''
}

function matchLogFilter(log: AgentLog, filter: string): boolean {
  if (filter === 'all') return true
  if (filter === 'stream1') return log.message.startsWith('[STREAM 1]')
  if (filter === 'stream2') return log.message.startsWith('[STREAM 2]')
  if (filter === 'stream3') return log.message.startsWith('[STREAM 3]')
  if (filter === 'deep') return log.message.startsWith('[DEEP]')
  if (filter === 'error') return log.level === 'error' || log.level === 'warning'
  return true
}

function mapAgentFindingToVuln(f: AgentFinding, scanId: string): Vulnerability {
  return {
    id: f.id,
    scan_id: scanId,
    title: f.title,
    vulnerability_type: f.vulnerability_type,
    severity: f.severity,
    cvss_score: f.cvss_score || null,
    cvss_vector: f.cvss_vector || null,
    cwe_id: f.cwe_id || null,
    description: f.description || null,
    affected_endpoint: f.affected_endpoint || null,
    poc_request: f.request || null,
    poc_response: f.response || null,
    poc_payload: f.payload || null,
    poc_parameter: f.parameter || null,
    poc_evidence: f.evidence || null,
    poc_code: f.poc_code || null,
    impact: f.impact || null,
    remediation: f.remediation || null,
    references: f.references || [],
    ai_analysis: f.evidence || null,
    validation_status: f.ai_status === 'rejected' ? 'ai_rejected' : 'ai_confirmed',
    ai_rejection_reason: f.rejection_reason || null,
    confidence_score: f.confidence_score,
    confidence_breakdown: f.confidence_breakdown,
    proof_of_execution: f.proof_of_execution,
    negative_controls: f.negative_controls,
    created_at: new Date().toISOString()
  }
}

// ─── Sub-Components ───────────────────────────────────────────────────────────

function SeverityMiniChart({ vulnCounts }: { vulnCounts: Record<string, number> }) {
  const data = ['critical', 'high', 'medium', 'low', 'info']
    .filter(s => (vulnCounts[s] || 0) > 0)
    .map(s => ({ name: s, value: vulnCounts[s] || 0 }))

  if (data.length === 0) return null

  return (
    <div className="w-20 h-20 flex-shrink-0">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={32} innerRadius={16} strokeWidth={0}>
            {data.map(entry => (
              <Cell key={entry.name} fill={SEVERITY_CHART_COLORS[entry.name]} />
            ))}
          </Pie>
          <RechartsTooltip
            contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #334155', borderRadius: '8px', fontSize: '11px', padding: '4px 8px' }}
            itemStyle={{ color: '#e2e8f0' }}
            formatter={(value: number, name: string) => [`${value}`, name.charAt(0).toUpperCase() + name.slice(1)]}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}

function ToolExecutionRow({ exec, expanded, onToggle }: {
  exec: ToolExecution; expanded: boolean; onToggle: () => void
}) {
  const hasExpandable = !!(exec.stdout_preview || exec.stderr_preview || exec.reason)
  return (
    <div className="border-b border-dark-800 last:border-0">
      <button
        onClick={hasExpandable ? onToggle : undefined}
        className={`w-full grid grid-cols-[50px_70px_1fr_50px_65px_55px_20px] sm:grid-cols-[60px_80px_1fr_50px_70px_60px_24px] gap-2 items-center px-2 py-2 text-xs transition-colors ${
          hasExpandable ? 'hover:bg-dark-700/50 cursor-pointer' : 'cursor-default'
        }`}
      >
        <span className="font-mono text-dark-500 truncate">{exec.task_id?.slice(0, 6) || '---'}</span>
        <span className="text-cyan-400 font-medium truncate">{exec.tool}</span>
        <span className="text-dark-300 truncate text-left" title={exec.command}>{exec.command}</span>
        <span className={`font-bold text-center ${exec.exit_code === 0 ? 'text-green-400' : exec.exit_code !== null ? 'text-red-400' : 'text-dark-500'}`}>
          {exec.exit_code ?? '...'}
        </span>
        <span className="text-dark-400 text-right">{exec.duration !== null ? `${exec.duration.toFixed(1)}s` : '---'}</span>
        <span className="text-dark-300 text-center">{exec.findings_count ?? 0}</span>
        <span className="text-dark-500">
          {hasExpandable ? (expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />) : null}
        </span>
      </button>
      {expanded && (
        <div className="px-3 pb-3 space-y-2 bg-dark-900/50 border-t border-dark-800">
          {exec.reason && (
            <p className="text-xs text-dark-400 pt-2"><span className="text-dark-500 font-medium">Reason: </span>{exec.reason}</p>
          )}
          {exec.stdout_preview && (
            <div>
              <p className="text-[10px] font-medium text-dark-500 mb-1 uppercase tracking-wider">stdout</p>
              <pre className="bg-dark-950 rounded p-2 text-xs text-green-400/80 max-h-[200px] overflow-y-auto whitespace-pre-wrap font-mono">{exec.stdout_preview}</pre>
            </div>
          )}
          {exec.stderr_preview && (
            <div>
              <p className="text-[10px] font-medium text-dark-500 mb-1 uppercase tracking-wider">stderr</p>
              <pre className="bg-dark-950 rounded p-2 text-xs text-red-400/70 max-h-[200px] overflow-y-auto whitespace-pre-wrap font-mono">{exec.stderr_preview}</pre>
            </div>
          )}
          {exec.container_name && (
            <p className="text-[10px] text-dark-500">Container: <span className="font-mono text-dark-400">{exec.container_name}</span></p>
          )}
        </div>
      )}
    </div>
  )
}

function LogViewer({ logs, logFilter, setLogFilter, logSearch, setLogSearch, logsEndRef }: {
  logs: AgentLog[]; logFilter: string; setLogFilter: (f: string) => void
  logSearch: string; setLogSearch: (s: string) => void; logsEndRef: React.RefObject<HTMLDivElement>
}) {
  const filteredLogs = useMemo(() =>
    logs.filter(log => {
      if (!matchLogFilter(log, logFilter)) return false
      if (logSearch && !log.message.toLowerCase().includes(logSearch.toLowerCase())) return false
      return true
    }), [logs, logFilter, logSearch]
  )

  return (
    <div className="bg-dark-900 rounded-xl overflow-hidden">
      <div className="flex items-center gap-1.5 p-2 border-b border-dark-700 flex-wrap">
        {LOG_FILTERS.map(f => (
          <button
            key={f.key}
            onClick={() => setLogFilter(f.key)}
            className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
              logFilter === f.key ? 'bg-dark-700 text-white' : `text-dark-500 hover:text-dark-300 ${f.color}`
            }`}
          >
            {f.label}
          </button>
        ))}
        <div className="flex-1 min-w-0" />
        <div className="relative">
          <Search className="w-3 h-3 absolute left-2 top-1/2 -translate-y-1/2 text-dark-500 pointer-events-none" />
          <input
            type="text"
            value={logSearch}
            onChange={e => setLogSearch(e.target.value)}
            placeholder="Search..."
            className="pl-6 pr-2 py-1 bg-dark-800 border border-dark-700 rounded text-xs text-white placeholder-dark-500 focus:outline-none focus:border-dark-500 w-32 sm:w-40"
          />
        </div>
        <span className="text-[10px] text-dark-600 tabular-nums">{filteredLogs.length}/{logs.length}</span>
      </div>
      <div className="p-3 max-h-[400px] overflow-y-auto font-mono text-xs space-y-px">
        {filteredLogs.length === 0 ? (
          <p className="text-dark-500 text-center py-4">
            {logs.length === 0 ? 'Waiting for activity...' : 'No logs match filter'}
          </p>
        ) : (
          filteredLogs.map((log, i) => (
            <div key={i} className="flex gap-2 py-0.5 hover:bg-dark-800/30 rounded px-1 -mx-1">
              <span className="text-dark-600 flex-shrink-0 text-[10px] tabular-nums">{log.time?.slice(11, 19) || new Date(log.time).toLocaleTimeString().slice(0, 8)}</span>
              <span className={`flex-shrink-0 uppercase w-10 text-[10px] ${
                log.level === 'error' ? 'text-red-400' :
                log.level === 'warning' ? 'text-yellow-400' :
                log.level === 'success' ? 'text-green-400' :
                log.level === 'info' ? 'text-blue-400' : 'text-dark-500'
              }`}>{log.level}</span>
              <span className={`break-all ${logMessageColor(log.message) || (log.source === 'llm' ? 'text-purple-400' : 'text-dark-300')}`}>
                {log.message}
              </span>
            </div>
          ))
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  )
}

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: string) => void }) {
  if (toasts.length === 0) return null
  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 max-w-sm pointer-events-none">
      {toasts.map(toast => (
        <div
          key={toast.id}
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
          className={`flex items-center gap-2 px-4 py-3 rounded-xl border shadow-2xl pointer-events-auto ${
            toast.severity === 'critical' ? 'bg-red-950/90 border-red-500/40 text-red-300' :
            toast.severity === 'high' ? 'bg-orange-950/90 border-orange-500/40 text-orange-300' :
            toast.severity === 'medium' ? 'bg-yellow-950/90 border-yellow-500/40 text-yellow-300' :
            toast.severity === 'completed' ? 'bg-green-950/90 border-green-500/40 text-green-300' :
            toast.severity === 'error' ? 'bg-red-950/90 border-red-500/40 text-red-300' :
            'bg-dark-800/95 border-dark-600 text-dark-300'
          }`}
        >
          {toast.severity === 'completed' ? (
            <CheckCircle className="w-4 h-4 flex-shrink-0" />
          ) : toast.severity === 'error' || toast.severity === 'critical' ? (
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          ) : (
            <Bug className="w-4 h-4 flex-shrink-0" />
          )}
          <span className="text-sm flex-1 line-clamp-2">{toast.message}</span>
          <button onClick={() => onDismiss(toast.id)} className="text-dark-500 hover:text-white flex-shrink-0">
            <X className="w-3 h-3" />
          </button>
        </div>
      ))}
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ScanDetailsPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const {
    currentScan, endpoints, vulnerabilities, logs, agentTasks,
    setCurrentScan, setEndpoints, setVulnerabilities,
    addEndpoint, addVulnerability, addLog, updateScan,
    addAgentTask, updateAgentTask, setAgentTasks,
    loadScanData, saveScanData, getVulnCounts
  } = useScanStore()

  // Core state
  const [isGeneratingReport, setIsGeneratingReport] = useState(false)
  const [isGeneratingAiReport, setIsGeneratingAiReport] = useState(false)
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set())
  const [activeTab, setActiveTab] = useState<'vulns' | 'endpoints' | 'tasks' | 'logs'>('vulns')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [autoGeneratedReport, setAutoGeneratedReport] = useState<Report | null>(null)
  const [agentData, setAgentData] = useState<AgentStatus | null>(null)

  // Phase stepper
  const [skipConfirm, setSkipConfirm] = useState<string | null>(null)
  const [skippedPhases, setSkippedPhases] = useState<Set<string>>(new Set())

  // Validation
  const [validationFilter, setValidationFilter] = useState<'all' | 'confirmed' | 'rejected' | 'validated'>('all')
  const [feedbackVulnId, setFeedbackVulnId] = useState<string | null>(null)
  const [feedbackIsTp, setFeedbackIsTp] = useState(true)
  const [feedbackText, setFeedbackText] = useState('')
  const [feedbackSubmitting, setFeedbackSubmitting] = useState(false)
  const [learningPatternCount, setLearningPatternCount] = useState<number | null>(null)

  // Report model picker
  const [availableModels, setAvailableModels] = useState<Array<{ provider_id: string; provider_name: string; default_model: string; tier: number; available_models: string[] }>>([])
  const [reportProvider, setReportProvider] = useState('')
  const [reportModel, setReportModel] = useState('')
  const [showReportModelPicker, setShowReportModelPicker] = useState(false)

  // Live stats
  const [elapsedSeconds, setElapsedSeconds] = useState(0)

  // Agent logs (from agent API, richer than scan store logs)
  const [agentLogs, setAgentLogs] = useState<AgentLog[]>([])
  const [logFilter, setLogFilter] = useState('all')
  const [logSearch, setLogSearch] = useState('')

  // Tool execution & container
  const [expandedTool, setExpandedTool] = useState<string | null>(null)

  // Toast notifications
  const [toasts, setToasts] = useState<Toast[]>([])
  const [newFindingIds, setNewFindingIds] = useState<Set<string>>(new Set())
  const [connectionLost, setConnectionLost] = useState(false)

  // Refs
  const logsEndRef = useRef<HTMLDivElement>(null)
  const seenVulnIdsRef = useRef<Set<string>>(new Set())
  const prevPhaseRef = useRef<string | null>(null)
  const consecutiveErrorsRef = useRef(0)
  const newFindingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // ─── Derived ─────────────────────────────────────────────────────────────

  const vulnCounts = useMemo(() => getVulnCounts(), [vulnerabilities])
  const isRunning = currentScan?.status === 'running' || currentScan?.status === 'paused'
  const toolExecutions: ToolExecution[] = agentData?.tool_executions || []
  const containerStatus: ContainerStatus | undefined = agentData?.container_status

  // ─── Toast Helper ─────────────────────────────────────────────────────────

  const addToast = useCallback((message: string, severity: string = 'info') => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    setToasts(prev => [...prev.slice(-(MAX_TOASTS - 1)), { id, message, severity, timestamp: Date.now() }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), TOAST_DURATION)
  }, [])

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  // ─── Mount: fetch LLM providers ────────────────────────────────────────────

  useEffect(() => {
    providersApi.getAvailableModels()
      .then(data => setAvailableModels(data.providers || []))
      .catch(() => {})
  }, [])

  // ─── Elapsed Time Ticker ──────────────────────────────────────────────────

  useEffect(() => {
    if (!isRunning || !currentScan?.started_at) return
    const startTime = new Date(currentScan.started_at).getTime()
    const tick = () => setElapsedSeconds(Math.floor((Date.now() - startTime) / 1000))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [isRunning, currentScan?.started_at])

  // ─── Main data fetch + polling + WebSocket ─────────────────────────────────

  useEffect(() => {
    if (!scanId) return

    loadScanData(scanId)

    const fetchData = async () => {
      setIsLoading(true)
      setError(null)
      try {
        const scan = await scansApi.get(scanId)
        setCurrentScan(scan)

        const [endpointsData, vulnsData, tasksData, reportsData] = await Promise.all([
          scansApi.getEndpoints(scanId),
          scansApi.getVulnerabilities(scanId),
          agentTasksApi.list(scanId).catch(() => ({ tasks: [] })),
          reportsApi.list({ scanId, autoGenerated: true }).catch(() => ({ reports: [] }))
        ])

        if (endpointsData.endpoints?.length > 0) setEndpoints(endpointsData.endpoints)
        if (vulnsData.vulnerabilities?.length > 0) setVulnerabilities(vulnsData.vulnerabilities)
        if (tasksData.tasks?.length > 0) setAgentTasks(tasksData.tasks)
        if (reportsData.reports?.length > 0) setAutoGeneratedReport(reportsData.reports[0])

        try {
          const agentStatus = await agentApi.getByScan(scanId)
          if (agentStatus) {
            setAgentData(agentStatus)
            if (!vulnsData.vulnerabilities || vulnsData.vulnerabilities.length === 0) {
              if (agentStatus.findings && agentStatus.findings.length > 0) {
                const confirmed = agentStatus.findings.map(f => mapAgentFindingToVuln(f, scanId))
                const rejected = (agentStatus.rejected_findings || []).map(f => mapAgentFindingToVuln(f, scanId))
                setVulnerabilities([...confirmed, ...rejected])
              }
              if (agentStatus.progress !== undefined) {
                updateScan(scanId, { progress: agentStatus.progress, current_phase: agentStatus.phase })
              }
            }
            // Seed seen vuln IDs
            seenVulnIdsRef.current = new Set((agentStatus.findings || []).map(f => f.id))
          }
        } catch { /* Agent data not available for non-agent scans */ }
      } catch (err: any) {
        console.error('Failed to fetch scan:', err)
        setError(err?.response?.data?.detail || 'Failed to load scan')
      } finally {
        setIsLoading(false)
      }
    }
    fetchData()

    // Poll for updates
    const pollInterval = setInterval(async () => {
      if (currentScan?.status === 'running' || currentScan?.status === 'paused' || !currentScan) {
        try {
          const scan = await scansApi.get(scanId)
          setCurrentScan(scan)
          consecutiveErrorsRef.current = 0
          if (connectionLost) setConnectionLost(false)

          const [endpointsData, vulnsData, tasksData] = await Promise.all([
            scansApi.getEndpoints(scanId),
            scansApi.getVulnerabilities(scanId),
            agentTasksApi.list(scanId).catch(() => ({ tasks: [] }))
          ])

          if (endpointsData.endpoints?.length > 0) setEndpoints(endpointsData.endpoints)
          if (vulnsData.vulnerabilities?.length > 0) setVulnerabilities(vulnsData.vulnerabilities)
          if (tasksData.tasks?.length > 0) setAgentTasks(tasksData.tasks)

          // Poll agent data for tool_executions, container_status, findings
          try {
            const agentStatus = await agentApi.getByScan(scanId)
            if (agentStatus) {
              setAgentData(agentStatus)

              // Phase change detection
              if (prevPhaseRef.current && agentStatus.phase && agentStatus.phase !== prevPhaseRef.current) {
                addToast(`Phase: ${agentStatus.phase}`, 'info')
              }
              prevPhaseRef.current = agentStatus.phase || null

              // New finding detection
              const currentIds = new Set((agentStatus.findings || []).map(f => f.id))
              if (seenVulnIdsRef.current.size > 0) {
                const newIds = [...currentIds].filter(id => !seenVulnIdsRef.current.has(id))
                if (newIds.length > 0) {
                  newIds.forEach(id => {
                    const f = agentStatus.findings?.find(x => x.id === id)
                    if (f) addToast(`${f.severity.toUpperCase()}: ${f.title}`, f.severity)
                  })
                  setNewFindingIds(new Set(newIds))
                  if (newFindingTimerRef.current) clearTimeout(newFindingTimerRef.current)
                  newFindingTimerRef.current = setTimeout(() => setNewFindingIds(new Set()), 3000)
                }
              }
              seenVulnIdsRef.current = currentIds

              if (!vulnsData.vulnerabilities || vulnsData.vulnerabilities.length === 0) {
                if (agentStatus.findings && agentStatus.findings.length > 0) {
                  const confirmed = agentStatus.findings.map(f => mapAgentFindingToVuln(f, scanId))
                  const rejected = (agentStatus.rejected_findings || []).map(f => mapAgentFindingToVuln(f, scanId))
                  setVulnerabilities([...confirmed, ...rejected])
                }
                if (agentStatus.progress !== undefined) {
                  updateScan(scanId, { progress: agentStatus.progress, current_phase: agentStatus.phase })
                }
              }
            }
          } catch { /* Agent data not available */ }

          // Fetch agent logs
          if (agentData?.agent_id) {
            try {
              const logData = await agentApi.getLogs(agentData.agent_id, 300)
              setAgentLogs(logData.logs || [])
            } catch { /* ignore */ }
          }
        } catch (err) {
          consecutiveErrorsRef.current += 1
          if (consecutiveErrorsRef.current >= 3) setConnectionLost(true)
          console.error('Poll error:', err)
        }
      }
    }, connectionLost ? POLL_INTERVAL_ERROR : POLL_INTERVAL)

    // Connect WebSocket
    wsService.connect(scanId)

    const unsubscribe = wsService.subscribe('*', (message: WSMessage) => {
      switch (message.type) {
        case 'progress_update':
          updateScan(scanId, {
            progress: message.progress as number,
            current_phase: message.message as string
          })
          break
        case 'phase_change': {
          const phase = message.phase as string
          updateScan(scanId, { current_phase: phase })
          addLog('info', `Phase: ${phase}`)
          addToast(`Phase: ${phase}`, 'info')
          if (phase.endsWith('_skipped')) {
            setSkippedPhases(prev => new Set([...prev, phase.replace('_skipped', '')]))
          }
          break
        }
        case 'endpoint_found':
          addEndpoint(message.endpoint as Endpoint)
          break
        case 'vuln_found':
          addVulnerability(message.vulnerability as Vulnerability)
          addLog('warning', `Found: ${(message.vulnerability as Vulnerability).title}`)
          addToast(`Found: ${(message.vulnerability as Vulnerability).title}`, (message.vulnerability as Vulnerability).severity || 'medium')
          break
        case 'stats_update':
          if (message.stats) {
            const stats = message.stats as {
              total_vulnerabilities?: number; critical?: number; high?: number
              medium?: number; low?: number; info?: number; total_endpoints?: number
            }
            updateScan(scanId, {
              total_vulnerabilities: stats.total_vulnerabilities,
              critical_count: stats.critical,
              high_count: stats.high,
              medium_count: stats.medium,
              low_count: stats.low,
              info_count: stats.info,
              total_endpoints: stats.total_endpoints
            })
          }
          break
        case 'log_message':
          addLog(message.level as string, message.message as string)
          break
        case 'scan_completed':
          updateScan(scanId, { status: 'completed', progress: 100 })
          addLog('info', 'Scan completed')
          addToast('Scan complete!', 'completed')
          saveScanData(scanId)
          break
        case 'scan_stopped':
          if (message.summary) {
            const summary = message.summary as {
              total_vulnerabilities?: number; critical?: number; high?: number
              medium?: number; low?: number; info?: number; total_endpoints?: number
              duration?: number; progress?: number
            }
            updateScan(scanId, {
              status: 'stopped',
              progress: summary.progress || currentScan?.progress,
              total_vulnerabilities: summary.total_vulnerabilities,
              critical_count: summary.critical,
              high_count: summary.high,
              medium_count: summary.medium,
              low_count: summary.low,
              info_count: summary.info,
              total_endpoints: summary.total_endpoints,
              duration: summary.duration
            })
          } else {
            updateScan(scanId, { status: 'stopped' })
          }
          addLog('warning', 'Scan stopped by user')
          addToast('Scan stopped', 'info')
          saveScanData(scanId)
          break
        case 'scan_failed':
          updateScan(scanId, { status: 'failed' })
          addLog('error', `Scan failed: ${message.error || 'Unknown error'}`)
          addToast('Scan failed', 'error')
          saveScanData(scanId)
          break
        case 'agent_task':
        case 'agent_task_started':
          if (message.task) addAgentTask(message.task as ScanAgentTask)
          break
        case 'agent_task_completed':
          if (message.task) {
            const task = message.task as ScanAgentTask
            updateAgentTask(task.id, task)
          }
          break
        case 'report_generated':
          if (message.report) {
            const report = message.report as Report
            setAutoGeneratedReport(report)
            addLog('info', `Report generated: ${report.title}`)
            addToast('Report generated', 'completed')
          }
          break
        case 'error':
          addLog('error', message.error as string)
          break
      }
    })

    return () => {
      saveScanData(scanId)
      unsubscribe()
      wsService.disconnect()
      clearInterval(pollInterval)
    }
  }, [scanId])

  // Auto-scroll logs
  useEffect(() => {
    if (activeTab === 'logs' && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [agentLogs, logs, activeTab])

  // ─── Actions ──────────────────────────────────────────────────────────────

  const handleStopScan = async () => {
    if (!scanId) return
    try {
      await scansApi.stop(scanId)
      updateScan(scanId, { status: 'stopped' })
      saveScanData(scanId)
    } catch (err) { console.error('Failed to stop scan:', err) }
  }

  const handlePauseScan = async () => {
    if (!scanId) return
    try {
      await scansApi.pause(scanId)
      updateScan(scanId, { status: 'paused' })
    } catch (err) { console.error('Failed to pause scan:', err) }
  }

  const handleResumeScan = async () => {
    if (!scanId) return
    try {
      await scansApi.resume(scanId)
      updateScan(scanId, { status: 'running' })
    } catch (err) { console.error('Failed to resume scan:', err) }
  }

  const handleSkipToPhase = async (phase: string) => {
    if (!scanId) return
    try {
      await scansApi.skipToPhase(scanId, phase)
      setSkipConfirm(null)
      addToast(`Skipping to ${phase}`, 'info')
    } catch (err: any) { console.error('Failed to skip phase:', err) }
  }

  const handleGenerateReport = async () => {
    if (!scanId) return
    setIsGeneratingReport(true)
    try {
      const report = await reportsApi.generate({ scan_id: scanId, format: 'html', include_poc: true, include_remediation: true })
      window.open(reportsApi.getViewUrl(report.id), '_blank')
      addToast('Report generated', 'completed')
    } catch (err) { console.error('Failed to generate report:', err) }
    finally { setIsGeneratingReport(false) }
  }

  const handleGenerateAiReport = async () => {
    if (!scanId) return
    setIsGeneratingAiReport(true)
    setShowReportModelPicker(false)
    try {
      const report = await reportsApi.generateAiReport({
        scan_id: scanId,
        title: `AI Report - ${currentScan?.name || 'Scan'}`,
        preferred_provider: reportProvider || undefined,
        preferred_model: reportModel || undefined,
      })
      window.open(reportsApi.getViewUrl(report.id), '_blank')
      addToast('AI Report generated', 'completed')
    } catch (err) { console.error('Failed to generate AI report:', err) }
    finally { setIsGeneratingAiReport(false) }
  }

  const toggleVuln = (id: string) => {
    const newExpanded = new Set(expandedVulns)
    if (newExpanded.has(id)) newExpanded.delete(id)
    else newExpanded.add(id)
    setExpandedVulns(newExpanded)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    addToast('Copied to clipboard', 'info')
  }

  // ─── Display logs: prefer agent logs if available ──────────────────────────

  const displayLogs: AgentLog[] = agentLogs.length > 0 ? agentLogs : logs

  // ─── Loading / Error / Not Found ───────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-primary-500" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64">
        <AlertTriangle className="w-12 h-12 text-red-500 mb-4" />
        <p className="text-xl text-white mb-2">Failed to load scan</p>
        <p className="text-dark-400 mb-4">{error}</p>
        <Button onClick={() => navigate('/')}>Go to Dashboard</Button>
      </div>
    )
  }

  if (!currentScan) {
    return (
      <div className="flex flex-col items-center justify-center h-64">
        <AlertTriangle className="w-12 h-12 text-yellow-500 mb-4" />
        <p className="text-xl text-white mb-2">Scan not found</p>
        <p className="text-dark-400 mb-4">The scan may still be initializing or does not exist.</p>
        <div className="flex gap-2">
          <Button onClick={() => window.location.reload()}>Refresh</Button>
          <Button variant="secondary" onClick={() => navigate('/')}>Go to Dashboard</Button>
        </div>
      </div>
    )
  }

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4 sm:space-y-6">
      {/* Inline keyframes */}
      <style>{`
        @keyframes fadeSlideIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes glowPulse { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.8; } }
      `}</style>

      {/* Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Connection Lost Banner */}
      {connectionLost && (
        <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-xl flex items-center gap-2" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
          <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0" />
          <span className="text-yellow-400 text-sm flex-1">Connection issues — retrying...</span>
          <RefreshCw className="w-4 h-4 text-yellow-400 animate-spin flex-shrink-0" />
        </div>
      )}

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
        <div className="min-w-0">
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-primary-500 flex-shrink-0" />
            <span className="truncate">{currentScan.name || 'Unnamed Scan'}</span>
          </h2>
          <div className="flex items-center gap-3 mt-2 flex-wrap">
            <SeverityBadge severity={currentScan.status} />
            <span className="text-dark-400 text-sm">
              Started {new Date(currentScan.created_at).toLocaleString()}
            </span>
            {isRunning && elapsedSeconds > 0 && (
              <span className="text-dark-500 text-xs font-mono tabular-nums flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {formatElapsed(elapsedSeconds)}
              </span>
            )}
          </div>
        </div>
        <div className="flex gap-2 flex-wrap flex-shrink-0">
          {agentData?.agent_id && (
            <Button variant="secondary" onClick={() => navigate(`/agent/${agentData.agent_id}`)}>
              <Cpu className="w-4 h-4 mr-2" />
              Agent View
            </Button>
          )}
          {currentScan.status === 'running' && (
            <>
              <Button variant="secondary" onClick={handlePauseScan}>
                <Pause className="w-4 h-4 mr-2" />Pause
              </Button>
              <Button variant="danger" onClick={handleStopScan}>
                <StopCircle className="w-4 h-4 mr-2" />Stop
              </Button>
            </>
          )}
          {currentScan.status === 'paused' && (
            <>
              <Button variant="primary" onClick={handleResumeScan}>
                <Play className="w-4 h-4 mr-2" />Resume
              </Button>
              <Button variant="danger" onClick={handleStopScan}>
                <StopCircle className="w-4 h-4 mr-2" />Stop
              </Button>
            </>
          )}
          {autoGeneratedReport && (
            <>
              <Button variant="secondary" onClick={() => window.open(reportsApi.getViewUrl(autoGeneratedReport.id), '_blank')}>
                <FileText className="w-4 h-4 mr-2" />View Report
              </Button>
              <Button variant="secondary" onClick={() => window.open(reportsApi.getDownloadZipUrl(autoGeneratedReport.id), '_blank')}>
                <Download className="w-4 h-4 mr-2" />ZIP
              </Button>
            </>
          )}
          {(currentScan.status === 'completed' || currentScan.status === 'stopped') && (
            <>
              <Button onClick={handleGenerateReport} isLoading={isGeneratingReport}>
                <FileText className="w-4 h-4 mr-2" />{autoGeneratedReport ? 'New Report' : 'Generate Report'}
              </Button>
              <div className="relative">
                <Button onClick={() => setShowReportModelPicker(!showReportModelPicker)} isLoading={isGeneratingAiReport} variant="secondary"
                  title={reportProvider ? `Using: ${reportProvider}/${reportModel || 'auto'}` : 'Using: auto'}>
                  <Sparkles className="w-4 h-4 mr-2" />AI Report
                  {reportProvider && <span className="text-xs opacity-70 ml-1">({reportProvider})</span>}
                  <ChevronDown className="w-3 h-3 ml-1" />
                </Button>
                {showReportModelPicker && (
                  <div className="absolute right-0 top-full mt-2 w-72 bg-dark-800 border border-dark-600 rounded-xl p-4 shadow-xl z-50 space-y-3" style={{ animation: 'fadeSlideIn 0.2s ease-out' }}>
                    <div>
                      <label className="text-xs text-dark-400 mb-1 block">Provider</label>
                      <select value={reportProvider} onChange={e => { setReportProvider(e.target.value); setReportModel('') }}
                        className="w-full px-3 py-1.5 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm">
                        <option value="">Auto</option>
                        {availableModels.map(p => (<option key={p.provider_id} value={p.provider_id}>{p.provider_name}</option>))}
                      </select>
                    </div>
                    <div>
                      <label className="text-xs text-dark-400 mb-1 block">Model</label>
                      <select value={reportModel} onChange={e => setReportModel(e.target.value)}
                        className="w-full px-3 py-1.5 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm">
                        <option value="">Auto</option>
                        {(reportProvider
                          ? availableModels.find(p => p.provider_id === reportProvider)?.available_models || []
                          : [...new Set(availableModels.flatMap(p => p.available_models))]
                        ).map(m => (<option key={m} value={m}>{m}</option>))}
                      </select>
                    </div>
                    <button onClick={handleGenerateAiReport}
                      className="w-full px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-400 text-sm font-medium transition-colors">
                      Generate AI Report
                    </button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Phase Stepper */}
      {(currentScan.status === 'running' || currentScan.status === 'paused' || currentScan.status === 'completed' || currentScan.status === 'stopped') && (() => {
        const PHASES = [
          { id: 'initializing', label: 'Init', fullLabel: 'Initialization' },
          { id: 'recon', label: 'Recon', fullLabel: 'Reconnaissance' },
          { id: 'analyzing', label: 'Analysis', fullLabel: 'AI Analysis' },
          { id: 'testing', label: 'Testing', fullLabel: 'Vulnerability Testing' },
          { id: 'completed', label: 'Done', fullLabel: 'Completed' },
        ]
        const phaseOrder = PHASES.map(p => p.id)
        const rawPhase = currentScan.current_phase || 'initializing'
        const currentPhase = rawPhase.startsWith('skipping_to_') ? rawPhase.replace('skipping_to_', '') : rawPhase.replace('_skipped', '')
        const currentIdx = phaseOrder.indexOf(currentPhase)
        const scanIsRunning = currentScan.status === 'running' || currentScan.status === 'paused'

        return (
          <Card>
            <div className="space-y-4">
              {/* Phase nodes */}
              <div className="flex items-center justify-between relative">
                {PHASES.map((phase, idx) => {
                  const isCompleted = idx < currentIdx || currentScan.status === 'completed'
                  const isActive = idx === currentIdx && scanIsRunning
                  const isSkipped = skippedPhases.has(phase.id)
                  const isFuture = idx > currentIdx && scanIsRunning
                  const canSkipTo = isFuture && phase.id !== 'initializing'

                  return (
                    <div key={phase.id} className="flex items-center flex-1 last:flex-none">
                      <div className="flex flex-col items-center relative z-10">
                        {canSkipTo ? (
                          skipConfirm === phase.id ? (
                            <div className="flex items-center gap-1">
                              <button onClick={() => handleSkipToPhase(phase.id)}
                                className="w-9 h-9 rounded-full bg-brand-500 text-white flex items-center justify-center hover:bg-brand-400 transition-colors"
                                title={`Skip to ${phase.fullLabel}`}>
                                <Check className="w-4 h-4" />
                              </button>
                              <button onClick={() => setSkipConfirm(null)}
                                className="w-7 h-7 rounded-full bg-dark-600 text-dark-300 flex items-center justify-center hover:bg-dark-500 transition-colors">
                                <XCircle className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          ) : (
                            <button onClick={() => setSkipConfirm(phase.id)}
                              className="w-9 h-9 rounded-full border-2 border-dark-500 bg-dark-800 text-dark-400 flex items-center justify-center hover:border-brand-400 hover:text-brand-400 hover:bg-brand-500/10 transition-all group"
                              title={`Skip to ${phase.fullLabel}`}>
                              <SkipForward className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
                              <span className="absolute text-[10px] group-hover:hidden">{idx + 1}</span>
                            </button>
                          )
                        ) : isCompleted ? (
                          <div className={`w-9 h-9 rounded-full flex items-center justify-center ${
                            isSkipped ? 'bg-yellow-500/20 border-2 border-yellow-500/50' : 'bg-green-500/20 border-2 border-green-500/50'
                          }`}>
                            {isSkipped ? <Minus className="w-4 h-4 text-yellow-400" /> : <Check className="w-4 h-4 text-green-400" />}
                          </div>
                        ) : isActive ? (
                          <div className="w-9 h-9 rounded-full bg-brand-500/20 border-2 border-brand-500 flex items-center justify-center animate-pulse">
                            <div className="w-3 h-3 rounded-full bg-brand-400" />
                          </div>
                        ) : (
                          <div className="w-9 h-9 rounded-full border-2 border-dark-600 bg-dark-800 flex items-center justify-center">
                            <span className="text-xs text-dark-500">{idx + 1}</span>
                          </div>
                        )}
                        <span className={`text-xs mt-2 font-medium ${
                          isActive ? 'text-brand-400' : isCompleted ? (isSkipped ? 'text-yellow-400' : 'text-green-400') : 'text-dark-500'
                        }`}>
                          {isSkipped ? `${phase.label} (skip)` : phase.label}
                        </span>
                        {canSkipTo && skipConfirm === phase.id && (
                          <span className="text-[10px] text-brand-400 mt-0.5">Skip here?</span>
                        )}
                      </div>
                      {idx < PHASES.length - 1 && (
                        <div className={`flex-1 h-0.5 mx-2 mt-[-20px] ${idx < currentIdx ? 'bg-green-500/50' : 'bg-dark-600'}`} />
                      )}
                    </div>
                  )
                })}
              </div>

              {/* Enhanced Progress bar */}
              <div className="flex items-center justify-between text-sm">
                <span className="text-dark-300">
                  {rawPhase.startsWith('skipping_to_')
                    ? `Skipping to ${rawPhase.replace('skipping_to_', '')}...`
                    : currentScan.current_phase || 'Initializing...'}
                </span>
                <span className="text-white font-medium font-mono tabular-nums">{currentScan.progress}%</span>
              </div>
              <div className="relative h-2.5 bg-dark-900 rounded-full overflow-hidden">
                <div className="absolute top-0 left-1/2 w-px h-full bg-dark-700 z-10" />
                <div className="absolute top-0 left-3/4 w-px h-full bg-dark-700 z-10" />
                <div
                  className="h-full rounded-full transition-all duration-700 ease-out relative"
                  style={{ width: `${currentScan.progress}%`, background: 'linear-gradient(90deg, #6366f1, #8b5cf6)' }}
                >
                  {scanIsRunning && (
                    <div className="absolute right-0 top-0 h-full w-6 rounded-full"
                      style={{ background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.25))', animation: 'glowPulse 1.5s ease-in-out infinite' }} />
                  )}
                </div>
              </div>
            </div>
          </Card>
        )
      })()}

      {/* Auto-generated Report Notification */}
      {autoGeneratedReport && (
        <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4 flex items-center justify-between flex-wrap gap-3" style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
          <div className="flex items-center gap-3">
            <div className="bg-green-500/20 rounded-full p-2">
              <FileText className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-white font-medium">
                {autoGeneratedReport.is_partial ? 'Partial Report Generated' : 'Report Generated'}
              </p>
              <p className="text-sm text-dark-400">{autoGeneratedReport.title || 'Scan report is ready to view'}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={() => window.open(reportsApi.getViewUrl(autoGeneratedReport.id), '_blank')}>
              <ExternalLink className="w-4 h-4 mr-2" />View Report
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setAutoGeneratedReport(null)}>Dismiss</Button>
          </div>
        </div>
      )}

      {/* Live Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Endpoints', value: endpoints.length, icon: Globe, color: 'text-blue-400' },
          { label: 'Total Vulns', value: vulnerabilities.length, icon: Bug, color: 'text-white' },
          { label: 'Critical', value: vulnCounts.critical, icon: AlertTriangle, color: 'text-red-500' },
          { label: 'High', value: vulnCounts.high, icon: AlertTriangle, color: 'text-orange-500' },
          { label: 'Medium', value: vulnCounts.medium, icon: AlertTriangle, color: 'text-yellow-500' },
          { label: 'Low', value: vulnCounts.low, icon: Shield, color: 'text-blue-500' },
        ].map(stat => (
          <div key={stat.label} className="bg-dark-800 border border-dark-700 rounded-xl p-4 text-center">
            <p className={`text-2xl font-bold font-mono tabular-nums ${stat.color}`}>{stat.value}</p>
            <p className="text-xs text-dark-400 mt-1">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1.5 flex-wrap border-b border-dark-700 pb-2">
        {([
          { key: 'vulns', label: 'Vulnerabilities', icon: AlertTriangle, count: vulnerabilities.length },
          { key: 'endpoints', label: 'Endpoints', icon: Globe, count: endpoints.length },
          { key: 'tasks', label: 'Agent Tasks', icon: Cpu, count: agentTasks.length },
          { key: 'logs', label: 'Activity Log', icon: ScrollText, count: displayLogs.length },
        ] as const).map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeTab === tab.key
                ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                : 'bg-dark-800 text-dark-400 hover:text-white border border-transparent'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            <span className="hidden sm:inline">{tab.label}</span>
            <span className="text-[10px] opacity-70">({tab.count})</span>
          </button>
        ))}
      </div>

      {/* Container Telemetry (when agent has sandbox) */}
      {containerStatus && activeTab !== 'logs' && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4 sm:p-5">
          <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
            <div className="flex items-center gap-3">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <h3 className="text-white font-semibold text-sm">Container Telemetry</h3>
              <span className={`flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold ${
                containerStatus.online
                  ? 'bg-green-500/20 text-green-400 border border-green-500/40'
                  : 'bg-red-500/20 text-red-400 border border-red-500/40'
              }`}>
                <span className={`w-2 h-2 rounded-full ${containerStatus.online ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
                {containerStatus.online ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>
            {containerStatus.container_id && (
              <span className="text-xs text-dark-400 font-mono">ID: {containerStatus.container_id.slice(0, 12)}</span>
            )}
          </div>

          {toolExecutions.length > 0 ? (
            <div className="space-y-0 max-h-[300px] overflow-y-auto rounded-lg border border-dark-700 bg-dark-900/50">
              <div className="grid grid-cols-[50px_70px_1fr_50px_65px_55px_20px] sm:grid-cols-[60px_80px_1fr_50px_70px_60px_24px] gap-2 text-[10px] text-dark-500 font-semibold uppercase tracking-wider px-2 py-2 border-b border-dark-700 bg-dark-900 sticky top-0">
                <span>Task</span><span>Tool</span><span>Command</span>
                <span className="text-center">Exit</span><span className="text-right">Duration</span>
                <span className="text-center">Finds</span><span />
              </div>
              {toolExecutions.map((exec, i) => (
                <ToolExecutionRow
                  key={exec.task_id || i}
                  exec={exec}
                  expanded={expandedTool === (exec.task_id || String(i))}
                  onToggle={() => setExpandedTool(expandedTool === (exec.task_id || String(i)) ? null : (exec.task_id || String(i)))}
                />
              ))}
            </div>
          ) : (
            <p className="text-dark-500 text-sm text-center py-4">
              {isRunning ? 'Waiting for tool executions...' : 'No tool executions recorded'}
            </p>
          )}
        </div>
      )}

      {/* ═══ Vulnerabilities Tab ═══ */}
      {activeTab === 'vulns' && (
        <div className="space-y-3">
          {/* Validation Filter + Severity chart */}
          {vulnerabilities.length > 0 && (
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex gap-1.5">
                {(['all', 'confirmed', 'rejected', 'validated'] as const).map((filter) => {
                  const count = filter === 'all' ? vulnerabilities.length
                    : filter === 'confirmed' ? vulnerabilities.filter(v => !v.validation_status || v.validation_status === 'ai_confirmed' || v.validation_status === 'validated').length
                    : filter === 'rejected' ? vulnerabilities.filter(v => v.validation_status === 'ai_rejected' || v.validation_status === 'false_positive').length
                    : vulnerabilities.filter(v => v.validation_status === 'validated').length
                  return (
                    <button
                      key={filter}
                      onClick={() => setValidationFilter(filter)}
                      className={`px-3 py-1 text-xs rounded-full transition-colors ${
                        validationFilter === filter
                          ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                          : 'bg-dark-700 text-dark-400 border border-dark-600 hover:text-dark-300'
                      }`}
                    >
                      {filter.charAt(0).toUpperCase() + filter.slice(1)} ({count})
                    </button>
                  )
                })}
              </div>
              <div className="flex gap-1.5 items-center ml-auto">
                {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
                  const count = vulnCounts[sev as keyof typeof vulnCounts] || 0
                  if (count === 0) return null
                  return (
                    <span key={sev} className={`${SEVERITY_COLORS[sev]} text-white px-2 py-0.5 rounded-full text-[10px] font-bold tabular-nums`}>
                      {count}
                    </span>
                  )
                })}
                <SeverityMiniChart vulnCounts={vulnCounts} />
              </div>
            </div>
          )}

          {vulnerabilities.length === 0 ? (
            <Card>
              <p className="text-dark-400 text-center py-8">
                {currentScan.status === 'running' ? (
                  <span className="flex items-center justify-center gap-2">
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    Scanning for vulnerabilities...
                  </span>
                ) : 'No vulnerabilities found'}
              </p>
            </Card>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
              {vulnerabilities
                .filter((vuln) => {
                  if (validationFilter === 'all') return true
                  if (validationFilter === 'confirmed') return !vuln.validation_status || vuln.validation_status === 'ai_confirmed' || vuln.validation_status === 'validated'
                  if (validationFilter === 'rejected') return vuln.validation_status === 'ai_rejected' || vuln.validation_status === 'false_positive'
                  if (validationFilter === 'validated') return vuln.validation_status === 'validated'
                  return true
                })
                .map((vuln, idx) => {
                  const vulnKey = vuln.id || `vuln-${idx}`
                  const isNew = newFindingIds.has(vuln.id)
                  return (
                    <div
                      key={vulnKey}
                      className={`bg-dark-800 rounded-xl border overflow-hidden transition-all duration-300 ${
                        vuln.validation_status === 'ai_rejected' ? 'border-orange-500/40 opacity-70' :
                        vuln.validation_status === 'false_positive' ? 'border-dark-600 opacity-50' :
                        vuln.validation_status === 'validated' ? 'border-green-500/40' :
                        'border-dark-700'
                      } ${isNew ? 'ring-2 ring-primary-500/30' : ''}`}
                      style={isNew ? { animation: 'fadeSlideIn 0.5s ease-out' } : undefined}
                    >
                      {/* Vulnerability Header */}
                      <div className="p-4 cursor-pointer hover:bg-dark-750 transition-colors" onClick={() => toggleVuln(vulnKey)}>
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-2 flex-1 min-w-0">
                            {expandedVulns.has(vulnKey) ? (
                              <ChevronDown className="w-4 h-4 mt-1 text-dark-400 flex-shrink-0" />
                            ) : (
                              <ChevronRight className="w-4 h-4 mt-1 text-dark-400 flex-shrink-0" />
                            )}
                            <div className="flex-1 min-w-0">
                              <p className="font-medium text-white">{vuln.title}</p>
                              <p className="text-sm text-dark-400 truncate mt-1">{vuln.affected_endpoint}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 flex-wrap flex-shrink-0">
                            {vuln.cvss_score && (
                              <span className={`text-sm font-bold px-2 py-0.5 rounded tabular-nums ${
                                vuln.cvss_score >= 9 ? 'bg-red-500/20 text-red-400' :
                                vuln.cvss_score >= 7 ? 'bg-orange-500/20 text-orange-400' :
                                vuln.cvss_score >= 4 ? 'bg-yellow-500/20 text-yellow-400' :
                                'bg-blue-500/20 text-blue-400'
                              }`}>
                                CVSS {vuln.cvss_score.toFixed(1)}
                              </span>
                            )}
                            <SeverityBadge severity={vuln.severity} />
                            {(() => {
                              const conf = getConfidenceDisplay(vuln)
                              if (!conf) return null
                              return (
                                <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border tabular-nums ${CONFIDENCE_STYLES[conf.color]}`}>
                                  {conf.score}/100
                                </span>
                              )
                            })()}
                            {vuln.validation_status === 'ai_rejected' && (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" /> Rejected
                              </span>
                            )}
                            {vuln.validation_status === 'validated' && (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
                                <CheckCircle className="w-3 h-3" /> Validated
                              </span>
                            )}
                            {vuln.validation_status === 'false_positive' && (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-dark-600 text-dark-400 border border-dark-500 flex items-center gap-1">
                                <XCircle className="w-3 h-3" /> FP
                              </span>
                            )}
                            {(!vuln.validation_status || vuln.validation_status === 'ai_confirmed') && (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 hidden sm:inline-flex">
                                AI Confirmed
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Vulnerability Details */}
                      {expandedVulns.has(vulnKey) && (
                        <div className="p-4 pt-0 space-y-4 border-t border-dark-700">
                          {/* Meta Info */}
                          <div className="flex flex-wrap items-center gap-4 text-sm">
                            {vuln.vulnerability_type && (
                              <span className="text-dark-400">Type: <span className="text-white">{vuln.vulnerability_type}</span></span>
                            )}
                            {vuln.cwe_id && (
                              <a href={`https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace('CWE-', '')}.html`}
                                target="_blank" rel="noopener noreferrer" className="text-primary-400 hover:underline flex items-center gap-1">
                                {vuln.cwe_id}<ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                            {vuln.cvss_vector && (
                              <span className="text-xs bg-dark-700 px-2 py-1 rounded font-mono text-dark-300">{vuln.cvss_vector}</span>
                            )}
                          </div>

                          {/* Validation Pipeline */}
                          {(() => {
                            const conf = getConfidenceDisplay(vuln)
                            if (!conf) return null
                            return (
                              <div className={`rounded-lg p-3 border ${CONFIDENCE_STYLES[conf.color]}`}>
                                <div className="flex items-center gap-2 mb-2">
                                  <Shield className="w-4 h-4" />
                                  <span className="text-sm font-semibold">Validation Pipeline</span>
                                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium tabular-nums ${
                                    conf.score >= 90 ? 'bg-green-500/20 text-green-400' :
                                    conf.score >= 60 ? 'bg-yellow-500/20 text-yellow-400' :
                                    'bg-red-500/20 text-red-400'
                                  }`}>
                                    {conf.score}/100 {conf.label}
                                  </span>
                                </div>
                                {vuln.confidence_breakdown && typeof vuln.confidence_breakdown === 'object' && Object.keys(vuln.confidence_breakdown).length > 0 && (
                                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs mt-1 mb-2">
                                    {Object.entries(vuln.confidence_breakdown).map(([key, val]) => (
                                      <div key={key} className="flex justify-between">
                                        <span className="opacity-70 capitalize">{key.replace(/_/g, ' ')}</span>
                                        <span className={`font-mono font-medium tabular-nums ${
                                          Number(val) > 0 ? 'text-green-400' : Number(val) < 0 ? 'text-red-400' : 'opacity-50'
                                        }`}>{Number(val) > 0 ? '+' : ''}{val}</span>
                                      </div>
                                    ))}
                                  </div>
                                )}
                                {vuln.proof_of_execution && (
                                  <div className="text-xs mt-1 flex items-start gap-1">
                                    <CheckCircle className="w-3 h-3 mt-0.5 flex-shrink-0 text-green-400" />
                                    <span className="opacity-80">{vuln.proof_of_execution}</span>
                                  </div>
                                )}
                                {vuln.negative_controls && (
                                  <div className="text-xs mt-1 flex items-start gap-1">
                                    <Shield className="w-3 h-3 mt-0.5 flex-shrink-0 text-blue-400" />
                                    <span className="opacity-80">{vuln.negative_controls}</span>
                                  </div>
                                )}
                              </div>
                            )
                          })()}

                          {vuln.description && (
                            <div>
                              <p className="text-sm font-medium text-dark-300 mb-1">Description</p>
                              <p className="text-sm text-dark-400">{vuln.description}</p>
                            </div>
                          )}

                          {vuln.impact && (
                            <div>
                              <p className="text-sm font-medium text-dark-300 mb-1">Impact</p>
                              <p className="text-sm text-dark-400">{vuln.impact}</p>
                            </div>
                          )}

                          {(vuln.poc_request || vuln.poc_payload) && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <p className="text-sm font-medium text-dark-300">Proof of Concept</p>
                                <Button variant="ghost" size="sm" onClick={() => copyToClipboard(vuln.poc_request || vuln.poc_payload || '')}>
                                  <Copy className="w-3 h-3 mr-1" />Copy
                                </Button>
                              </div>
                              {vuln.poc_payload && (
                                <div className="mb-2">
                                  <p className="text-xs text-dark-500 mb-1">Payload:</p>
                                  <pre className="text-xs bg-dark-900 p-3 rounded overflow-x-auto text-yellow-400 font-mono">{vuln.poc_payload}</pre>
                                </div>
                              )}
                              {vuln.poc_request && (
                                <div>
                                  <p className="text-xs text-dark-500 mb-1">Request:</p>
                                  <pre className="text-xs bg-dark-900 p-3 rounded overflow-x-auto text-dark-300 font-mono">{vuln.poc_request}</pre>
                                </div>
                              )}
                              {vuln.poc_response && (
                                <div className="mt-2">
                                  <p className="text-xs text-dark-500 mb-1">Response:</p>
                                  <pre className="text-xs bg-dark-900 p-3 rounded overflow-x-auto text-dark-300 font-mono max-h-40 overflow-y-auto">{vuln.poc_response}</pre>
                                </div>
                              )}
                            </div>
                          )}

                          {vuln.poc_code && (
                            <div className="mt-3">
                              <p className="text-xs font-medium text-dark-400 mb-1">Exploitation Code</p>
                              <pre className="p-3 bg-dark-950 rounded text-xs text-green-400 overflow-x-auto max-h-[400px] overflow-y-auto whitespace-pre-wrap font-mono">{vuln.poc_code}</pre>
                            </div>
                          )}

                          {vuln.remediation && (
                            <div>
                              <p className="text-sm font-medium text-green-400 mb-1">Remediation</p>
                              <p className="text-sm text-dark-400">{vuln.remediation}</p>
                            </div>
                          )}

                          {vuln.ai_analysis && (
                            <div>
                              <p className="text-sm font-medium text-purple-400 mb-1">AI Analysis</p>
                              <p className="text-sm text-dark-400 whitespace-pre-wrap">{vuln.ai_analysis}</p>
                            </div>
                          )}

                          {vuln.validation_status === 'ai_rejected' && vuln.ai_rejection_reason && (
                            <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg p-3">
                              <p className="text-sm font-medium text-orange-400 mb-1 flex items-center gap-1">
                                <AlertTriangle className="w-4 h-4" /> AI Rejection Reason
                              </p>
                              <p className="text-sm text-orange-300/80">{vuln.ai_rejection_reason}</p>
                            </div>
                          )}

                          {/* Manual Validation Actions */}
                          {vuln.validation_status !== 'validated' && vuln.validation_status !== 'false_positive' && (
                            <div className="flex items-center gap-2 pt-2 border-t border-dark-700 flex-wrap">
                              <span className="text-xs text-dark-500 mr-2">Manual Review:</span>
                              <Button variant="ghost" size="sm" className="text-green-400 hover:bg-green-500/10 border border-green-500/30"
                                onClick={async (e) => {
                                  e.stopPropagation()
                                  try {
                                    await vulnerabilitiesApi.validate(vuln.id, 'validated')
                                    setVulnerabilities(vulnerabilities.map(v => v.id === vuln.id ? { ...v, validation_status: 'validated' as const } : v))
                                    addToast('Finding validated', 'completed')
                                  } catch (err) { console.error('Validate error:', err) }
                                }}>
                                <CheckCircle className="w-3 h-3 mr-1" />Validate
                              </Button>
                              <Button variant="ghost" size="sm" className="text-dark-400 hover:bg-red-500/10 border border-dark-600"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setFeedbackVulnId(vuln.id); setFeedbackIsTp(false); setFeedbackText(''); setLearningPatternCount(null)
                                }}>
                                <XCircle className="w-3 h-3 mr-1" />False Positive
                              </Button>
                              <Button variant="ghost" size="sm" className="text-blue-400 hover:bg-blue-500/10 border border-blue-500/30"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setFeedbackVulnId(vuln.id); setFeedbackIsTp(true); setFeedbackText(''); setLearningPatternCount(null)
                                }}>
                                <Check className="w-3 h-3 mr-1" />Confirm TP
                              </Button>
                              {vuln.validation_status === 'ai_rejected' && (
                                <span className="text-xs text-orange-400/60 ml-2">AI rejected - review evidence above</span>
                              )}
                            </div>
                          )}
                          {(vuln.validation_status === 'validated' || vuln.validation_status === 'false_positive') && (
                            <div className="flex items-center gap-2 pt-2 border-t border-dark-700">
                              <span className="text-xs text-dark-500">
                                {vuln.validation_status === 'validated' ? 'Manually validated by pentester' : 'Marked as false positive'}
                              </span>
                              <Button variant="ghost" size="sm" className="text-dark-500 hover:text-dark-300 text-xs"
                                onClick={async (e) => {
                                  e.stopPropagation()
                                  try {
                                    const revertTo = vuln.ai_rejection_reason ? 'ai_rejected' : 'ai_confirmed'
                                    await vulnerabilitiesApi.validate(vuln.id, revertTo)
                                    setVulnerabilities(vulnerabilities.map(v =>
                                      v.id === vuln.id ? { ...v, validation_status: revertTo as Vulnerability['validation_status'] } : v
                                    ))
                                  } catch (err) { console.error('Revert error:', err) }
                                }}>
                                Undo
                              </Button>
                            </div>
                          )}

                          {vuln.references?.length > 0 && (
                            <div>
                              <p className="text-sm font-medium text-dark-300 mb-1">References</p>
                              <div className="flex flex-wrap gap-2">
                                {vuln.references.map((ref, i) => (
                                  <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                                    className="text-xs text-primary-400 hover:underline flex items-center gap-1">
                                    {(() => { try { return new URL(ref).hostname } catch { return ref } })()}
                                    <ExternalLink className="w-3 h-3" />
                                  </a>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
            </div>
          )}
        </div>
      )}

      {/* ═══ Endpoints Tab ═══ */}
      {activeTab === 'endpoints' && (
        <Card title="Discovered Endpoints" subtitle={`${endpoints.length} endpoints found`}>
          <div className="space-y-2 max-h-[500px] overflow-auto">
            {endpoints.length === 0 ? (
              <p className="text-dark-400 text-center py-8">No endpoints discovered yet</p>
            ) : (
              endpoints.map((endpoint, idx) => (
                <div key={endpoint.id || `endpoint-${idx}`}
                  className="flex items-center gap-3 p-3 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors">
                  <Globe className="w-4 h-4 text-dark-400 flex-shrink-0" />
                  <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                    endpoint.method === 'GET' ? 'bg-green-500/20 text-green-400' :
                    endpoint.method === 'POST' ? 'bg-blue-500/20 text-blue-400' :
                    endpoint.method === 'PUT' ? 'bg-yellow-500/20 text-yellow-400' :
                    endpoint.method === 'DELETE' ? 'bg-red-500/20 text-red-400' :
                    'bg-dark-700 text-dark-300'
                  }`}>{endpoint.method}</span>
                  <span className="text-sm text-dark-200 truncate flex-1 font-mono">{endpoint.path || endpoint.url}</span>
                  {endpoint.parameters?.length > 0 && <span className="text-xs text-dark-500">{endpoint.parameters.length} params</span>}
                  {endpoint.content_type && <span className="text-xs text-dark-500 hidden sm:inline">{endpoint.content_type}</span>}
                  {endpoint.response_status && (
                    <span className={`text-xs font-medium tabular-nums ${
                      endpoint.response_status < 300 ? 'text-green-400' :
                      endpoint.response_status < 400 ? 'text-yellow-400' : 'text-red-400'
                    }`}>{endpoint.response_status}</span>
                  )}
                </div>
              ))
            )}
          </div>
        </Card>
      )}

      {/* ═══ Agent Tasks Tab ═══ */}
      {activeTab === 'tasks' && (
        <Card title="Agent Tasks" subtitle={`${agentTasks.length} tasks executed`}>
          <div className="space-y-3 max-h-[500px] overflow-auto">
            {agentTasks.length === 0 ? (
              <p className="text-dark-400 text-center py-8">
                {currentScan.status === 'running' ? 'Agent tasks will appear here...' : 'No agent tasks recorded'}
              </p>
            ) : (
              agentTasks.map((task, idx) => (
                <div key={task.id || `task-${idx}`} className="p-4 bg-dark-900/50 rounded-lg border border-dark-700">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <div className={`mt-0.5 flex-shrink-0 ${
                        task.status === 'completed' ? 'text-green-400' :
                        task.status === 'running' ? 'text-blue-400' :
                        task.status === 'failed' ? 'text-red-400' : 'text-dark-400'
                      }`}>
                        {task.status === 'completed' ? <CheckCircle className="w-5 h-5" /> :
                         task.status === 'running' ? <RefreshCw className="w-5 h-5 animate-spin" /> :
                         task.status === 'failed' ? <XCircle className="w-5 h-5" /> :
                         <Clock className="w-5 h-5" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-white">{task.task_name}</p>
                        {task.description && <p className="text-sm text-dark-400 mt-1">{task.description}</p>}
                        <div className="flex flex-wrap items-center gap-3 mt-2 text-xs">
                          {task.tool_name && <span className="bg-dark-700 px-2 py-1 rounded text-dark-300">{task.tool_name}</span>}
                          <span className={`px-2 py-1 rounded ${
                            task.task_type === 'recon' ? 'bg-blue-500/20 text-blue-400' :
                            task.task_type === 'analysis' ? 'bg-purple-500/20 text-purple-400' :
                            task.task_type === 'testing' ? 'bg-orange-500/20 text-orange-400' :
                            'bg-green-500/20 text-green-400'
                          }`}>{task.task_type}</span>
                          {task.duration_ms !== null && (
                            <span className="text-dark-500 tabular-nums">
                              {task.duration_ms < 1000 ? `${task.duration_ms}ms` : `${(task.duration_ms / 1000).toFixed(1)}s`}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <span className={`text-xs px-2 py-1 rounded font-medium ${
                        task.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                        task.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                        task.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                        'bg-dark-700 text-dark-300'
                      }`}>{task.status}</span>
                      {(task.items_processed > 0 || task.items_found > 0) && (
                        <p className="text-xs text-dark-500 mt-2 tabular-nums">
                          {task.items_processed > 0 && `${task.items_processed} processed`}
                          {task.items_processed > 0 && task.items_found > 0 && ' / '}
                          {task.items_found > 0 && `${task.items_found} found`}
                        </p>
                      )}
                    </div>
                  </div>
                  {task.result_summary && (
                    <p className="text-xs text-dark-400 mt-3 border-t border-dark-700 pt-3">{task.result_summary}</p>
                  )}
                  {task.error_message && (
                    <p className="text-xs text-red-400 mt-3 border-t border-dark-700 pt-3">Error: {task.error_message}</p>
                  )}
                </div>
              ))
            )}
          </div>
        </Card>
      )}

      {/* ═══ Activity Log Tab ═══ */}
      {activeTab === 'logs' && (
        <LogViewer
          logs={displayLogs}
          logFilter={logFilter}
          setLogFilter={setLogFilter}
          logSearch={logSearch}
          setLogSearch={setLogSearch}
          logsEndRef={logsEndRef}
        />
      )}

      {/* Feedback Modal */}
      {feedbackVulnId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setFeedbackVulnId(null)}>
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 w-full max-w-md mx-4" onClick={e => e.stopPropagation()} style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
            <h3 className="text-lg font-bold text-white mb-4">
              {feedbackIsTp ? 'Confirm True Positive' : 'Report False Positive'}
            </h3>
            <p className="text-sm text-dark-400 mb-4">
              {feedbackIsTp
                ? 'Confirm this finding is a real vulnerability. Optionally explain why.'
                : 'Explain why this is a false positive so the agent can learn and improve.'}
            </p>
            <textarea
              value={feedbackText}
              onChange={e => setFeedbackText(e.target.value)}
              rows={4}
              placeholder={feedbackIsTp
                ? 'Optional: explain why this is a true positive...'
                : 'Required: explain why this is a false positive (min 3 chars)...'}
              className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-dark-500 focus:outline-none focus:border-primary-500 mb-4 transition-colors"
            />
            {learningPatternCount !== null && (
              <div className="mb-4 p-2 bg-primary-500/10 border border-primary-500/30 rounded-lg">
                <p className="text-xs text-primary-400">
                  Agent has learned {learningPatternCount} pattern{learningPatternCount !== 1 ? 's' : ''} from user feedback.
                </p>
              </div>
            )}
            <div className="flex gap-3 justify-end">
              <Button variant="secondary" onClick={() => setFeedbackVulnId(null)}>Cancel</Button>
              <Button
                variant={feedbackIsTp ? 'primary' : 'danger'}
                isLoading={feedbackSubmitting}
                onClick={async () => {
                  if (!feedbackIsTp && feedbackText.length < 3) return
                  setFeedbackSubmitting(true)
                  try {
                    const result = await vulnerabilitiesApi.submitFeedback(feedbackVulnId, feedbackIsTp, feedbackText)
                    setLearningPatternCount(result.pattern_count)
                    const newStatus = feedbackIsTp ? 'validated' : 'false_positive'
                    setVulnerabilities(vulnerabilities.map(v =>
                      v.id === feedbackVulnId ? { ...v, validation_status: newStatus as Vulnerability['validation_status'] } : v
                    ))
                    addToast(feedbackIsTp ? 'True positive confirmed' : 'False positive reported', 'completed')
                    setTimeout(() => setFeedbackVulnId(null), 1500)
                  } catch (err) { console.error('Feedback error:', err) }
                  finally { setFeedbackSubmitting(false) }
                }}
                disabled={!feedbackIsTp && feedbackText.length < 3}
              >
                {feedbackIsTp ? 'Confirm True Positive' : 'Submit False Positive'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
