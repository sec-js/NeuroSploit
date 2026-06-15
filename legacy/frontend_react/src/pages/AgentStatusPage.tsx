import { useEffect, useMemo, useState, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Bot, RefreshCw, FileText, CheckCircle,
  XCircle, Clock, Target, Shield, ChevronDown, ChevronRight, ExternalLink,
  Copy, Download, StopCircle, Terminal, Brain, Send, Code, Globe, AlertTriangle,
  SkipForward, MinusCircle, Pause, Play, Sparkles, X, WifiOff
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { SeverityBadge } from '../components/common/Badge'
import { agentApi, reportsApi } from '../services/api'
import type { AgentStatus, AgentLog, AgentFinding } from '../types'

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const PHASE_ICONS: Record<string, React.ReactNode> = {
  initializing: <Clock className="w-4 h-4" />,
  reconnaissance: <Target className="w-4 h-4" />,
  'reconnaissance complete': <Target className="w-4 h-4" />,
  recon: <Target className="w-4 h-4" />,
  'starting reconnaissance': <Target className="w-4 h-4" />,
  scanning: <Shield className="w-4 h-4" />,
  analysis: <Bot className="w-4 h-4" />,
  'attack surface analyzed': <Bot className="w-4 h-4" />,
  testing: <Shield className="w-4 h-4" />,
  'vulnerability testing complete': <Shield className="w-4 h-4" />,
  enhancement: <Brain className="w-4 h-4" />,
  'findings enhanced': <Brain className="w-4 h-4" />,
  reporting: <FileText className="w-4 h-4" />,
  'assessment complete': <CheckCircle className="w-4 h-4" />,
  completed: <CheckCircle className="w-4 h-4" />,
  stopped: <StopCircle className="w-4 h-4" />,
  error: <XCircle className="w-4 h-4" />,
}

const SCAN_PHASES = [
  { key: 'recon', label: 'Reconnaissance', progress: 20 },
  { key: 'analysis', label: 'Analysis', progress: 30 },
  { key: 'testing', label: 'Testing', progress: 70 },
  { key: 'enhancement', label: 'Enhancement', progress: 90 },
  { key: 'completed', label: 'Completed', progress: 100 },
]

const MODE_LABELS: Record<string, string> = {
  full_auto: 'Full Auto',
  recon_only: 'Recon Only',
  prompt_only: 'AI Prompt Mode',
  analyze_only: 'Analyze Only',
}

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function getPhaseIndex(phase: string): number {
  const p = phase.toLowerCase()
  if (p.includes('recon') || p.includes('initializing')) return 0
  if (p.includes('analysis') || p.includes('attack surface')) return 1
  if (p.includes('test') || p.includes('vuln')) return 2
  if (p.includes('enhance') || p.includes('finding')) return 3
  if (p.includes('complete') || p.includes('report')) return 4
  return 0
}

function relativeTime(dateStr: string): string {
  const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (diff < 0) return 'just now'
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

/* ------------------------------------------------------------------ */
/*  Toast System                                                       */
/* ------------------------------------------------------------------ */

interface Toast {
  id: number
  message: string
  type: 'success' | 'error' | 'info'
}

let _toastSeq = 0

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null
  const borderColor: Record<string, string> = {
    success: 'border-green-500',
    error: 'border-red-500',
    info: 'border-blue-500',
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

/* ================================================================== */
/*  Main Component                                                     */
/* ================================================================== */

export default function AgentStatusPage() {
  const { agentId } = useParams<{ agentId: string }>()
  const navigate = useNavigate()
  const scriptLogsEndRef = useRef<HTMLDivElement>(null)
  const llmLogsEndRef = useRef<HTMLDivElement>(null)
  const consecutiveErrorsRef = useRef(0)

  const [status, setStatus] = useState<AgentStatus | null>(null)
  const [logs, setLogs] = useState<AgentLog[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())
  const [isGeneratingReport, setIsGeneratingReport] = useState(false)
  const [isStopping, setIsStopping] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // Toast state
  const [toasts, setToasts] = useState<Toast[]>([])
  const [connectionLost, setConnectionLost] = useState(false)

  // Custom prompt state
  const [customPrompt, setCustomPrompt] = useState('')
  const [isSubmittingPrompt, setIsSubmittingPrompt] = useState(false)

  // Phase skip state
  const [skipConfirm, setSkipConfirm] = useState<string | null>(null)
  const [isSkipping, setIsSkipping] = useState(false)
  const [skippedPhases, setSkippedPhases] = useState<Set<string>>(new Set())

  // AI report state
  const [isGeneratingAiReport, setIsGeneratingAiReport] = useState(false)

  /* ── Toast helpers ──────────────────────────────────────────── */

  const addToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = ++_toastSeq
    setToasts(prev => [...prev.slice(-4), { id, message, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  /* ── Derived log streams (memoized) ────────────────────────── */

  const scriptLogs = useMemo(
    () => logs.filter(l => l.source === 'script' || (!l.source && !l.message.includes('[LLM]') && !l.message.includes('[AI]'))),
    [logs]
  )

  const llmLogs = useMemo(
    () => logs.filter(l => l.source === 'llm' || l.message.includes('[LLM]') || l.message.includes('[AI]')),
    [logs]
  )

  /* ── Severity counts (memoized) ────────────────────────────── */

  const severityCounts = useMemo(() => {
    if (!status) return { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of status.findings) {
      if (f.severity in counts) counts[f.severity]++
    }
    return counts
  }, [status])

  /* ── Data fetch ────────────────────────────────────────────── */

  const fetchStatus = useCallback(async () => {
    if (!agentId) return
    try {
      const [statusData, logsData] = await Promise.all([
        agentApi.getStatus(agentId),
        agentApi.getLogs(agentId, 500),
      ])
      setStatus(statusData)
      setLogs(logsData.logs)
      setError(null)

      if (consecutiveErrorsRef.current >= 3) {
        setConnectionLost(false)
        addToast('Connection restored', 'success')
      }
      consecutiveErrorsRef.current = 0
    } catch (err: unknown) {
      const apiErr = err as { response?: { status?: number } }
      if (apiErr.response?.status === 404) {
        setError('Agent not found')
      } else {
        console.error('Failed to fetch agent status:', err)
        consecutiveErrorsRef.current++
        if (consecutiveErrorsRef.current >= 3) setConnectionLost(true)
      }
    } finally {
      setIsLoading(false)
    }
  }, [agentId, addToast])

  // Poll for status updates
  useEffect(() => {
    if (!agentId) return

    fetchStatus()

    const interval = setInterval(() => {
      if (status?.status === 'running' || status?.status === 'paused') {
        fetchStatus()
      }
    }, 5000)

    return () => clearInterval(interval)
  }, [agentId, status?.status, fetchStatus])

  // Auto-scroll logs
  useEffect(() => {
    if (autoScroll) {
      scriptLogsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
      llmLogsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, autoScroll])

  // Track skipped phases from status updates
  useEffect(() => {
    if (!status) return
    const phase = status.phase.toLowerCase()
    if (phase.includes('_skipped')) {
      const skippedKey = phase.replace('_skipped', '')
      setSkippedPhases(prev => new Set(prev).add(skippedKey))
    }
  }, [status?.phase])

  /* ── Handlers ──────────────────────────────────────────────── */

  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    await fetchStatus()
    setRefreshing(false)
    addToast('Status refreshed', 'info')
  }, [fetchStatus, addToast])

  const toggleFinding = useCallback((id: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text)
    addToast('Copied to clipboard', 'success')
  }, [addToast])

  /* ── Report generation ──────────────────────────────────────── */

  const generateReportData = useCallback(() => {
    if (!status) return null

    const severityBreakdown: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of status.findings) {
      if (f.severity in severityBreakdown) severityBreakdown[f.severity]++
    }

    return {
      report_info: {
        agent_id: agentId,
        target: status.target,
        mode: status.mode,
        status: status.status,
        started_at: status.started_at,
        completed_at: status.completed_at || new Date().toISOString(),
        total_findings: status.findings.length,
        severity_breakdown: severityBreakdown,
      },
      findings: status.findings.map(f => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        type: f.vulnerability_type,
        cvss_score: f.cvss_score,
        cvss_vector: f.cvss_vector,
        cwe_id: f.cwe_id,
        affected_endpoint: f.affected_endpoint,
        parameter: f.parameter,
        payload: f.payload,
        evidence: f.evidence,
        request: f.request,
        response: f.response,
        description: f.description,
        impact: f.impact,
        poc_code: f.poc_code,
        remediation: f.remediation,
        references: f.references,
        ai_verified: f.ai_verified,
        confidence: f.confidence,
      })),
      logs: logs.slice(-100),
    }
  }, [status, agentId, logs])

  const generateHTMLReport = useCallback(() => {
    if (!status) return ''

    const esc = (s: string | undefined | null): string =>
      (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')

    const sevColors: Record<string, string> = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280' }
    const sevBg: Record<string, string> = { critical:'rgba(239,68,68,.08)', high:'rgba(249,115,22,.08)', medium:'rgba(234,179,8,.08)', low:'rgba(59,130,246,.08)', info:'rgba(107,114,128,.08)' }

    const owaspMap: Record<string, string> = {
      sqli:'A03:2021 Injection', 'sql_injection':'A03:2021 Injection', xss:'A03:2021 Injection', 'xss_reflected':'A03:2021 Injection', 'xss_stored':'A03:2021 Injection',
      'command_injection':'A03:2021 Injection', ssrf:'A10:2021 SSRF', idor:'A01:2021 Broken Access Control', bola:'A01:2021 Broken Access Control',
      csrf:'A01:2021 Broken Access Control', 'auth_bypass':'A07:2021 Auth Failures', 'open_redirect':'A01:2021 Broken Access Control',
      lfi:'A01:2021 Broken Access Control', 'path_traversal':'A01:2021 Broken Access Control', ssti:'A03:2021 Injection',
      xxe:'A05:2021 Misconfiguration', cors:'A05:2021 Misconfiguration', 'security_headers':'A05:2021 Misconfiguration',
      'deserialization':'A08:2021 Integrity Failures', 'cryptographic_failures':'A02:2021 Crypto Failures',
    }
    const getOwasp = (type: string): string => owaspMap[type] || owaspMap[type.split('_')[0]] || ''

    // Sort findings by severity order
    const sevOrder = ['critical','high','medium','low','info']
    const sorted = [...status.findings].sort((a,b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity))

    const sc: Record<string,number> = { critical:0, high:0, medium:0, low:0, info:0 }
    for (const f of sorted) { if (f.severity in sc) sc[f.severity]++ }
    const total = sorted.length

    const riskScore = Math.min(100, sc.critical*25 + sc.high*15 + sc.medium*8 + sc.low*3)
    const riskLevel = riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW'
    const riskColor = riskScore >= 75 ? '#ef4444' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#eab308' : '#22c55e'

    // Severity distribution bar widths
    const barPcts = sevOrder.map(s => total > 0 ? Math.round((sc[s]/total)*100) : 0)

    // Table of contents
    const tocHtml = sorted.map((f, i) =>
      `<tr>
        <td style="padding:6px 12px;border-bottom:1px solid #1e293b;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${sevColors[f.severity]};margin-right:8px;"></span>${f.severity.toUpperCase()}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #1e293b;"><a href="#finding-${i+1}" style="color:#93c5fd;text-decoration:none;">${esc(f.title)}</a></td>
        <td style="padding:6px 12px;border-bottom:1px solid #1e293b;color:#94a3b8;font-family:monospace;font-size:12px;">${esc(f.vulnerability_type)}</td>
      </tr>`
    ).join('')

    // Build each finding card
    const findingsHtml = sorted.map((f, idx) => {
      const color = sevColors[f.severity]
      const bg = sevBg[f.severity]
      const owasp = getOwasp(f.vulnerability_type)
      const cweLink = f.cwe_id ? `https://cwe.mitre.org/data/definitions/${f.cwe_id.replace('CWE-','')}.html` : ''
      const confScore = f.confidence_score || 0
      const confColor = confScore >= 80 ? '#22c55e' : confScore >= 50 ? '#eab308' : '#ef4444'
      const confLabel = confScore >= 80 ? 'Confirmed' : confScore >= 50 ? 'Likely' : 'Unconfirmed'

      const section = (title: string, content: string, icon: string = '') =>
        `<div style="margin-bottom:20px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
            ${icon ? `<span style="font-size:14px;">${icon}</span>` : ''}
            <h4 style="margin:0;color:#e2e8f0;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:1px;">${title}</h4>
          </div>
          ${content}
        </div>`

      const codeBlock = (text: string, maxLen = 3000) =>
        `<pre style="background:#020617;border:1px solid #1e293b;border-radius:6px;padding:14px;margin:0;overflow-x:auto;font-family:'SF Mono',Monaco,monospace;font-size:12px;line-height:1.6;color:#e2e8f0;white-space:pre-wrap;word-break:break-all;">${esc(text.slice(0,maxLen))}</pre>`

      return `
      <div id="finding-${idx+1}" style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;margin-bottom:28px;overflow:hidden;page-break-inside:avoid;">
        <!-- Finding Header -->
        <div style="padding:24px;background:${bg};border-bottom:1px solid #1e293b;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
            <span style="background:${color};color:#fff;padding:4px 14px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;">${f.severity}</span>
            <span style="color:#475569;font-size:12px;font-weight:500;">FINDING #${idx+1} of ${total}</span>
            ${owasp ? `<span style="background:rgba(251,191,36,.1);color:#fbbf24;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:500;">${owasp}</span>` : ''}
            ${confScore > 0 ? `<span style="background:rgba(0,0,0,.3);color:${confColor};padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600;">${confScore}% ${confLabel}</span>` : ''}
          </div>
          <h3 style="margin:0 0 8px;color:#f8fafc;font-size:20px;font-weight:600;line-height:1.3;">${esc(f.title)}</h3>
          <div style="font-family:'SF Mono',Monaco,monospace;font-size:13px;color:#64748b;word-break:break-all;">${esc(f.affected_endpoint)}</div>
        </div>

        <div style="padding:24px;">
          <!-- Metrics Row -->
          <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px;">
            ${f.cvss_score ? `
            <div style="background:#020617;border:1px solid #1e293b;border-radius:8px;padding:12px 18px;min-width:120px;">
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">CVSS 3.1</div>
              <div style="font-size:26px;font-weight:700;color:${color};">${f.cvss_score}</div>
              ${f.cvss_vector ? `<div style="font-size:9px;color:#475569;font-family:monospace;margin-top:2px;">${esc(f.cvss_vector)}</div>` : ''}
            </div>` : ''}
            ${f.cwe_id ? `
            <div style="background:#020617;border:1px solid #1e293b;border-radius:8px;padding:12px 18px;min-width:120px;">
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">CWE</div>
              <a href="${cweLink}" target="_blank" style="color:#60a5fa;text-decoration:none;font-size:15px;font-weight:600;">${esc(f.cwe_id)}</a>
            </div>` : ''}
            <div style="background:#020617;border:1px solid #1e293b;border-radius:8px;padding:12px 18px;min-width:120px;">
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">TYPE</div>
              <div style="color:#e2e8f0;font-size:14px;font-weight:500;">${esc(f.vulnerability_type)}</div>
            </div>
            ${f.parameter ? `
            <div style="background:#020617;border:1px solid #1e293b;border-radius:8px;padding:12px 18px;min-width:120px;">
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">PARAMETER</div>
              <div style="color:#38bdf8;font-size:14px;font-family:monospace;">${esc(f.parameter)}</div>
            </div>` : ''}
          </div>

          ${f.description ? section('Description', `<p style="color:#cbd5e1;margin:0;line-height:1.8;font-size:14px;">${esc(f.description)}</p>`, '📋') : ''}
          ${f.evidence ? section('Evidence', codeBlock(f.evidence), '🔍') : ''}
          ${f.payload ? section('Payload', codeBlock(f.payload, 1000), '💉') : ''}

          ${f.request ? section('HTTP Request', codeBlock(f.request, 2000), '📤') : ''}
          ${f.response ? section('HTTP Response (excerpt)', codeBlock(f.response, 2000), '📥') : ''}

          ${f.poc_code ? section('Proof of Concept Code', codeBlock(f.poc_code, 4000), '⚡') : ''}
          ${f.proof_of_execution ? section('Proof of Execution', `<p style="color:#22c55e;margin:0;font-size:14px;line-height:1.7;padding:12px;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.15);border-radius:6px;">${esc(f.proof_of_execution)}</p>`, '✅') : ''}

          ${f.impact ? section('Impact', `<p style="color:#fbbf24;margin:0;line-height:1.7;font-size:14px;padding:12px;background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.12);border-radius:6px;">${esc(f.impact)}</p>`, '⚠️') : ''}

          ${f.remediation ? `
          <div style="margin-bottom:20px;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.15);border-radius:8px;padding:16px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
              <span style="font-size:14px;">🛡️</span>
              <h4 style="margin:0;color:#4ade80;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:1px;">Remediation</h4>
            </div>
            <p style="color:#cbd5e1;margin:0;line-height:1.8;font-size:14px;">${esc(f.remediation)}</p>
          </div>` : ''}

          ${f.references && f.references.length > 0 ? section('References',
            `<ul style="margin:0;padding-left:20px;color:#94a3b8;font-size:13px;line-height:2;">
              ${f.references.map(ref => `<li><a href="${esc(ref)}" target="_blank" style="color:#60a5fa;text-decoration:none;">${esc(ref)}</a></li>`).join('')}
            </ul>`, '📚') : ''}
        </div>
      </div>`
    }).join('')

    // Unique affected endpoints
    const uniqueEndpoints = [...new Set(sorted.map(f => f.affected_endpoint).filter(Boolean))]
    const uniqueTypes = [...new Set(sorted.map(f => f.vulnerability_type).filter(Boolean))]

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report - ${esc(status.target)}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#020617;color:#e2e8f0;line-height:1.6}
  .page{max-width:1100px;margin:0 auto;padding:40px 32px}
  a{color:#60a5fa}
  @media print{
    body{background:#fff;color:#1e293b;font-size:11pt}
    .page{padding:20px}
    .no-print{display:none!important}
    pre{border:1px solid #e2e8f0!important;background:#f8fafc!important;color:#1e293b!important}
    h1,h2,h3{color:#0f172a!important}
  }
  @page{margin:1.5cm;size:A4}
</style>
</head>
<body>
<div class="page">

  <!-- ═══ Cover / Header ═══ -->
  <div style="text-align:center;padding:48px 0 40px;border-bottom:2px solid #1e293b;margin-bottom:40px;">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:4px;color:#64748b;margin-bottom:16px;">Confidential Security Report</div>
    <h1 style="color:#f8fafc;font-size:32px;font-weight:700;margin-bottom:12px;">Penetration Test Report</h1>
    <div style="color:#94a3b8;font-size:15px;margin-bottom:8px;">Target: <span style="color:#38bdf8;font-family:monospace;">${esc(status.target)}</span></div>
    <div style="color:#64748b;font-size:13px;">
      ${new Date().toLocaleDateString('en-US', { weekday:'long', year:'numeric', month:'long', day:'numeric' })}
      &nbsp;&bull;&nbsp; Agent: ${esc(agentId || '')}
      &nbsp;&bull;&nbsp; Mode: ${esc(MODE_LABELS[status.mode] || status.mode)}
    </div>
  </div>

  <!-- ═══ Risk Overview ═══ -->
  <div style="display:grid;grid-template-columns:240px 1fr;gap:32px;margin-bottom:40px;align-items:start;">
    <!-- Risk Gauge -->
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:28px;text-align:center;">
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#64748b;margin-bottom:12px;">Risk Level</div>
      <div style="font-size:56px;font-weight:800;color:${riskColor};line-height:1;">${riskScore}</div>
      <div style="font-size:13px;color:${riskColor};font-weight:600;margin-top:4px;">${riskLevel}</div>
      <div style="height:6px;background:#1e293b;border-radius:3px;margin-top:16px;overflow:hidden;">
        <div style="height:100%;width:${riskScore}%;background:${riskColor};border-radius:3px;"></div>
      </div>
    </div>
    <!-- Severity Breakdown -->
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:28px;">
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#64748b;margin-bottom:16px;">Findings Breakdown</div>
      <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px;">
        <div style="text-align:center;"><div style="font-size:32px;font-weight:700;color:#f8fafc;">${total}</div><div style="font-size:11px;color:#64748b;text-transform:uppercase;">Total</div></div>
        ${sevOrder.map(s => `<div style="text-align:center;"><div style="font-size:32px;font-weight:700;color:${sevColors[s]};">${sc[s]}</div><div style="font-size:11px;color:#64748b;text-transform:uppercase;">${s}</div></div>`).join('')}
      </div>
      <!-- Distribution bar -->
      ${total > 0 ? `
      <div style="display:flex;height:10px;border-radius:5px;overflow:hidden;">
        ${sevOrder.map((s,i) => barPcts[i] > 0 ? `<div style="width:${barPcts[i]}%;background:${sevColors[s]};"></div>` : '').join('')}
      </div>` : ''}
    </div>
  </div>

  <!-- ═══ Executive Summary ═══ -->
  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:28px;margin-bottom:40px;">
    <h2 style="color:#f8fafc;font-size:18px;font-weight:600;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #1e293b;">Executive Summary</h2>
    <p style="color:#cbd5e1;line-height:1.9;font-size:14px;">
      A security assessment was performed against <strong style="color:#f8fafc;">${esc(status.target)}</strong>
      using NeuroSploit AI-powered penetration testing. The assessment identified
      <strong style="color:#f8fafc;">${total} security finding${total !== 1 ? 's' : ''}</strong>
      across <strong>${uniqueEndpoints.length}</strong> unique endpoint${uniqueEndpoints.length !== 1 ? 's' : ''}
      covering <strong>${uniqueTypes.length}</strong> distinct vulnerability type${uniqueTypes.length !== 1 ? 's' : ''}.
      ${sc.critical > 0 ? `<br/><br/><span style="color:#ef4444;font-weight:600;">&#9888; ${sc.critical} critical-severity finding${sc.critical > 1 ? 's' : ''} require${sc.critical === 1 ? 's' : ''} immediate remediation.</span>` : ''}
      ${sc.high > 0 ? ` <span style="color:#f97316;font-weight:500;">${sc.high} high-severity finding${sc.high > 1 ? 's' : ''} should be addressed promptly.</span>` : ''}
      ${sc.critical === 0 && sc.high === 0 && total > 0 ? ` No critical or high-severity vulnerabilities were identified.` : ''}
      ${total === 0 ? ` No vulnerabilities were identified during this assessment.` : ''}
    </p>
  </div>

  ${total > 0 ? `
  <!-- ═══ Table of Contents ═══ -->
  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:28px;margin-bottom:40px;">
    <h2 style="color:#f8fafc;font-size:18px;font-weight:600;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #1e293b;">Findings Index</h2>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead>
        <tr style="border-bottom:2px solid #1e293b;">
          <th style="text-align:left;padding:8px 12px;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:1px;width:100px;">Severity</th>
          <th style="text-align:left;padding:8px 12px;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:1px;">Finding</th>
          <th style="text-align:left;padding:8px 12px;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:1px;width:180px;">Type</th>
        </tr>
      </thead>
      <tbody>${tocHtml}</tbody>
    </table>
  </div>

  <!-- ═══ Detailed Findings ═══ -->
  <div style="margin-bottom:40px;">
    <h2 style="color:#f8fafc;font-size:20px;font-weight:600;margin-bottom:24px;padding-bottom:12px;border-bottom:2px solid #1e293b;">
      Detailed Findings <span style="color:#64748b;font-weight:400;font-size:14px;">(${total})</span>
    </h2>
    ${findingsHtml}
  </div>
  ` : ''}

  <!-- ═══ Scope & Methodology ═══ -->
  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:28px;margin-bottom:40px;">
    <h2 style="color:#f8fafc;font-size:18px;font-weight:600;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #1e293b;">Scope &amp; Methodology</h2>
    <table style="width:100%;font-size:13px;color:#cbd5e1;">
      <tr><td style="padding:6px 0;color:#64748b;width:180px;">Target URL</td><td style="padding:6px 0;font-family:monospace;">${esc(status.target)}</td></tr>
      <tr><td style="padding:6px 0;color:#64748b;">Assessment Mode</td><td style="padding:6px 0;">${esc(MODE_LABELS[status.mode] || status.mode)}</td></tr>
      <tr><td style="padding:6px 0;color:#64748b;">Agent ID</td><td style="padding:6px 0;font-family:monospace;">${esc(agentId || '')}</td></tr>
      <tr><td style="padding:6px 0;color:#64748b;">Start Time</td><td style="padding:6px 0;">${status.started_at ? new Date(status.started_at).toLocaleString() : 'N/A'}</td></tr>
      <tr><td style="padding:6px 0;color:#64748b;">End Time</td><td style="padding:6px 0;">${status.completed_at ? new Date(status.completed_at).toLocaleString() : 'N/A'}</td></tr>
      <tr><td style="padding:6px 0;color:#64748b;">Endpoints Tested</td><td style="padding:6px 0;">${uniqueEndpoints.length}</td></tr>
      <tr><td style="padding:6px 0;color:#64748b;">Vulnerability Types</td><td style="padding:6px 0;">${uniqueTypes.length}</td></tr>
    </table>
    <p style="color:#94a3b8;font-size:12px;margin-top:16px;line-height:1.7;">
      This assessment was conducted using NeuroSploit v3 AI-powered penetration testing platform with 100 vulnerability type coverage,
      automated payload generation, and AI-driven validation. Findings were validated through negative control testing,
      proof-of-execution verification, and confidence scoring.
    </p>
  </div>

  <!-- ═══ Footer ═══ -->
  <div style="text-align:center;padding:32px 0;border-top:1px solid #1e293b;color:#475569;font-size:12px;">
    <div style="margin-bottom:8px;"><strong style="color:#94a3b8;">Generated by NeuroSploit v3</strong> &mdash; AI-Powered Penetration Testing Platform</div>
    <div>${new Date().toISOString()}</div>
    <div style="margin-top:12px;font-size:11px;color:#334155;">CONFIDENTIAL &mdash; This document contains sensitive security information. Distribution is restricted to authorized personnel only.</div>
  </div>

</div>
</body>
</html>`
  }, [status, agentId])

  const handleGenerateReport = useCallback(async (format: 'json' | 'html' = 'json') => {
    if (!agentId || !status) return
    setIsGeneratingReport(true)
    try {
      if (format === 'html') {
        const htmlContent = generateHTMLReport()
        const blob = new Blob([htmlContent], { type: 'text/html' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `neurosploit-report-${agentId}-${new Date().toISOString().split('T')[0]}.html`
        a.click()
        URL.revokeObjectURL(url)
        addToast('HTML report downloaded', 'success')
      } else {
        const reportData = status.report || generateReportData()
        const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `neurosploit-report-${agentId}-${new Date().toISOString().split('T')[0]}.json`
        a.click()
        URL.revokeObjectURL(url)
        addToast('JSON report downloaded', 'success')
      }
    } finally {
      setIsGeneratingReport(false)
    }
  }, [agentId, status, generateHTMLReport, generateReportData, addToast])

  const handleGenerateAiReport = useCallback(async () => {
    if (!status?.scan_id) return
    setIsGeneratingAiReport(true)
    try {
      const report = await reportsApi.generateAiReport({
        scan_id: status.scan_id,
        title: `AI Report - ${status.target || 'Agent Scan'}`,
      })
      window.open(reportsApi.getViewUrl(report.id), '_blank')
      addToast('AI report generated successfully', 'success')
    } catch (err) {
      console.error('Failed to generate AI report:', err)
      addToast('Failed to generate AI report', 'error')
    } finally {
      setIsGeneratingAiReport(false)
    }
  }, [status, addToast])

  /* ── Scan controls ──────────────────────────────────────────── */

  const handleStopScan = useCallback(async () => {
    if (!agentId) return
    setIsStopping(true)
    try {
      await agentApi.stop(agentId)
      const statusData = await agentApi.getStatus(agentId)
      setStatus(statusData)
      addToast('Agent stopped', 'info')
    } catch (err) {
      console.error('Failed to stop agent:', err)
      addToast('Failed to stop agent', 'error')
    } finally {
      setIsStopping(false)
    }
  }, [agentId, addToast])

  const handlePauseScan = useCallback(async () => {
    if (!agentId) return
    try {
      await agentApi.pause(agentId)
      const statusData = await agentApi.getStatus(agentId)
      setStatus(statusData)
      addToast('Agent paused', 'info')
    } catch (err) {
      console.error('Failed to pause agent:', err)
      addToast('Failed to pause agent', 'error')
    }
  }, [agentId, addToast])

  const handleResumeScan = useCallback(async () => {
    if (!agentId) return
    try {
      await agentApi.resume(agentId)
      const statusData = await agentApi.getStatus(agentId)
      setStatus(statusData)
      addToast('Agent resumed', 'success')
    } catch (err) {
      console.error('Failed to resume agent:', err)
      addToast('Failed to resume agent', 'error')
    }
  }, [agentId, addToast])

  /* ── Custom prompt ──────────────────────────────────────────── */

  const handleSubmitPrompt = useCallback(async () => {
    if (!customPrompt.trim() || !agentId) return
    setIsSubmittingPrompt(true)
    const sentPrompt = customPrompt
    try {
      await agentApi.sendPrompt(agentId, customPrompt)
      setCustomPrompt('')
      addToast(`Prompt sent: "${sentPrompt.slice(0, 50)}${sentPrompt.length > 50 ? '...' : ''}"`, 'success')

      const [statusData, logsData] = await Promise.all([
        agentApi.getStatus(agentId),
        agentApi.getLogs(agentId, 200),
      ])
      setStatus(statusData)
      setLogs(logsData.logs || [])
    } catch (err) {
      console.error('Failed to send prompt:', err)
      addToast('Failed to send prompt', 'error')
    } finally {
      setIsSubmittingPrompt(false)
    }
  }, [customPrompt, agentId, addToast])

  /* ── Phase skip ─────────────────────────────────────────────── */

  const handleSkipToPhase = useCallback(async (targetPhase: string) => {
    if (!agentId) return
    setIsSkipping(true)
    try {
      await agentApi.skipToPhase(agentId, targetPhase)
      const currentIndex = status ? getPhaseIndex(status.phase) : 0
      const targetIndex = SCAN_PHASES.findIndex(p => p.key === targetPhase)
      const newSkipped = new Set(skippedPhases)
      for (let i = currentIndex; i < targetIndex; i++) {
        newSkipped.add(SCAN_PHASES[i].key)
      }
      setSkippedPhases(newSkipped)
      setSkipConfirm(null)
      addToast(`Skipped to ${targetPhase}`, 'info')
    } catch (err) {
      console.error('Failed to skip phase:', err)
      addToast('Failed to skip phase', 'error')
    } finally {
      setIsSkipping(false)
    }
  }, [agentId, status, skippedPhases, addToast])

  /* ── Sub-renderers ──────────────────────────────────────────── */

  const renderFindingDetails = useCallback((finding: AgentFinding) => (
    <div className="p-4 pt-0 space-y-4 border-t border-dark-700">
      {/* CVSS & Meta Info */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-sm text-dark-400">CVSS:</span>
          <span className={`font-bold ${
            finding.cvss_score >= 9 ? 'text-red-500' :
            finding.cvss_score >= 7 ? 'text-orange-500' :
            finding.cvss_score >= 4 ? 'text-yellow-500' :
            'text-blue-500'
          }`}>
            {finding.cvss_score?.toFixed(1) || 'N/A'}
          </span>
        </div>
        {finding.cwe_id && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-dark-400">CWE:</span>
            <a
              href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary-400 hover:underline flex items-center gap-1"
            >
              {finding.cwe_id}
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}
        <span className="text-xs bg-dark-700 px-2 py-1 rounded text-dark-300">
          {finding.vulnerability_type}
        </span>
        {finding.confidence && (
          <span className={`text-xs px-2 py-1 rounded ${
            finding.confidence === 'high' ? 'bg-green-500/20 text-green-400' :
            finding.confidence === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
            'bg-red-500/20 text-red-400'
          }`}>
            {finding.confidence} confidence
          </span>
        )}
        {typeof finding.confidence_score === 'number' && (
          <span className={`text-xs px-2 py-1 rounded border font-medium tabular-nums ${
            finding.confidence_score >= 90 ? 'bg-green-500/15 text-green-400 border-green-500/30' :
            finding.confidence_score >= 60 ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' :
            'bg-red-500/15 text-red-400 border-red-500/30'
          }`}>
            {finding.confidence_score}/100
          </span>
        )}
      </div>

      {/* CVSS Vector */}
      {finding.cvss_vector && (
        <div className="text-xs bg-dark-800 p-2 rounded font-mono text-dark-300">
          {finding.cvss_vector}
        </div>
      )}

      {/* Technical Details Section */}
      <div className="bg-dark-800/50 rounded-lg p-4 space-y-3">
        <h4 className="text-sm font-medium text-primary-400 flex items-center gap-2">
          <Code className="w-4 h-4" />
          Technical Details
        </h4>

        {/* Affected Endpoint */}
        <div>
          <span className="text-xs text-dark-500">Endpoint:</span>
          <div className="flex items-center gap-2 mt-1">
            <Globe className="w-4 h-4 text-dark-400 flex-shrink-0" />
            <code className="text-sm text-blue-400 bg-dark-900 px-2 py-1 rounded break-all">
              {finding.affected_endpoint}
            </code>
          </div>
        </div>

        {/* Parameter */}
        {finding.parameter && (
          <div>
            <span className="text-xs text-dark-500">Vulnerable Parameter:</span>
            <code className="block mt-1 text-sm text-yellow-400 bg-dark-900 px-2 py-1 rounded">
              {finding.parameter}
            </code>
          </div>
        )}

        {/* Payload */}
        {finding.payload && (
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-dark-500">Payload Used:</span>
              <Button variant="ghost" size="sm" onClick={() => copyToClipboard(finding.payload!)}>
                <Copy className="w-3 h-3" />
              </Button>
            </div>
            <code className="block mt-1 text-sm text-red-400 bg-dark-900 px-2 py-1 rounded break-all">
              {finding.payload}
            </code>
          </div>
        )}

        {/* HTTP Request */}
        {finding.request && (
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-dark-500">HTTP Request:</span>
              <Button variant="ghost" size="sm" onClick={() => copyToClipboard(finding.request!)}>
                <Copy className="w-3 h-3" />
              </Button>
            </div>
            <pre className="mt-1 text-xs text-green-400 bg-dark-900 p-2 rounded overflow-x-auto max-h-32">
              {finding.request}
            </pre>
          </div>
        )}

        {/* HTTP Response */}
        {finding.response && (
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-dark-500">HTTP Response (excerpt):</span>
              <Button variant="ghost" size="sm" onClick={() => copyToClipboard(finding.response!)}>
                <Copy className="w-3 h-3" />
              </Button>
            </div>
            <pre className="mt-1 text-xs text-orange-400 bg-dark-900 p-2 rounded overflow-x-auto max-h-32">
              {finding.response}
            </pre>
          </div>
        )}

        {/* Evidence */}
        {finding.evidence && (
          <div>
            <span className="text-xs text-dark-500">Evidence:</span>
            <p className="mt-1 text-sm text-dark-300 bg-dark-900 p-2 rounded">
              {finding.evidence}
            </p>
          </div>
        )}
      </div>

      {/* Description */}
      {finding.description && (
        <div>
          <p className="text-sm font-medium text-dark-300 mb-1">Description</p>
          <p className="text-sm text-dark-400">{finding.description}</p>
        </div>
      )}

      {/* Impact */}
      {finding.impact && (
        <div>
          <p className="text-sm font-medium text-dark-300 mb-1">Impact</p>
          <p className="text-sm text-dark-400">{finding.impact}</p>
        </div>
      )}

      {/* PoC Code */}
      {finding.poc_code && (
        <div>
          <div className="flex items-center justify-between mb-1">
            <p className="text-sm font-medium text-dark-300">Proof of Concept</p>
            <Button variant="ghost" size="sm" onClick={() => copyToClipboard(finding.poc_code)}>
              <Copy className="w-3 h-3 mr-1" />
              Copy
            </Button>
          </div>
          <pre className="text-xs bg-dark-800 p-3 rounded overflow-x-auto text-dark-300 font-mono">
            {finding.poc_code}
          </pre>
        </div>
      )}

      {/* Remediation */}
      {finding.remediation && (
        <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
          <p className="text-sm font-medium text-green-400 mb-1">Remediation</p>
          <p className="text-sm text-dark-400">{finding.remediation}</p>
        </div>
      )}

      {/* Confidence Breakdown */}
      {finding.confidence_breakdown && Object.keys(finding.confidence_breakdown).length > 0 && (
        <div className="bg-dark-800/50 rounded-lg p-3">
          <p className="text-sm font-medium text-dark-300 mb-2">Confidence Breakdown</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {Object.entries(finding.confidence_breakdown).map(([key, val]) => (
              <div key={key} className="flex items-center justify-between text-xs bg-dark-900 px-2 py-1.5 rounded">
                <span className="text-dark-400 truncate mr-2">{key.replace(/_/g, ' ')}</span>
                <span className={`font-medium tabular-nums ${
                  val > 0 ? 'text-green-400' : val < 0 ? 'text-red-400' : 'text-dark-500'
                }`}>
                  {val > 0 ? '+' : ''}{val}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Proof of Execution */}
      {finding.proof_of_execution && (
        <div className="bg-dark-800/50 rounded-lg p-3">
          <p className="text-sm font-medium text-dark-300 mb-1">Proof of Execution</p>
          <p className="text-xs text-dark-400 whitespace-pre-wrap">{finding.proof_of_execution}</p>
        </div>
      )}

      {/* References */}
      {finding.references && finding.references.length > 0 && (
        <div>
          <p className="text-sm font-medium text-dark-300 mb-1">References</p>
          <div className="flex flex-wrap gap-2">
            {finding.references.map((ref, i) => (
              <a
                key={i}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-primary-400 hover:underline flex items-center gap-1 bg-dark-800 px-2 py-1 rounded"
              >
                {(() => {
                  try {
                    return new URL(ref).hostname
                  } catch {
                    return ref
                  }
                })()}
                <ExternalLink className="w-3 h-3" />
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  ), [copyToClipboard])

  const renderLogViewer = useCallback((
    logsToShow: AgentLog[],
    endRef: React.RefObject<HTMLDivElement>,
    title: string,
    icon: React.ReactNode,
  ) => (
    <div className="space-y-1 max-h-[400px] overflow-auto font-mono text-xs">
      {logsToShow.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12">
          <Terminal className="w-8 h-8 text-dark-600 mb-2" />
          <p className="text-dark-400 text-center text-sm">No {title.toLowerCase()} activity yet...</p>
        </div>
      ) : (
        logsToShow.map((log, i) => {
          const isUserPrompt = log.message.includes('[USER PROMPT]')
          const isAIResponse = log.message.includes('[AI RESPONSE]') || log.message.includes('[AI]')

          return (
            <div
              key={i}
              className={`flex gap-2 py-1 px-1 rounded ${
                isUserPrompt ? 'bg-blue-500/10 border-l-2 border-blue-500' :
                isAIResponse && log.message.includes('[AI RESPONSE]') ? 'bg-purple-500/10 border-l-2 border-purple-500' :
                'hover:bg-dark-800/30'
              }`}
            >
              <span className="text-dark-500 flex-shrink-0 w-20">
                {new Date(log.time).toLocaleTimeString()}
              </span>
              <span className="flex-shrink-0">
                {isUserPrompt ? <Send className="w-3 h-3 text-blue-400" /> :
                 isAIResponse ? <Brain className="w-3 h-3 text-purple-400" /> :
                 icon}
              </span>
              <span className={`break-words ${
                isUserPrompt ? 'text-blue-300 font-medium' :
                isAIResponse && log.message.includes('[AI RESPONSE]') ? 'text-purple-300' :
                log.level === 'error' ? 'text-red-400' :
                log.level === 'warning' ? 'text-yellow-400' :
                log.level === 'success' ? 'text-green-400' :
                log.level === 'llm' ? 'text-purple-400' :
                'text-dark-300'
              }`}>
                {log.message}
              </span>
            </div>
          )
        })
      )}
      <div ref={endRef} />
    </div>
  ), [])

  /* ── Loading state ──────────────────────────────────────────── */

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-primary-500" />
      </div>
    )
  }

  /* ── Error state ────────────────────────────────────────────── */

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64">
        <XCircle className="w-12 h-12 text-red-500 mb-4" />
        <p className="text-xl text-white mb-2">{error}</p>
        <Button onClick={() => navigate('/scan/new')}>Start New Agent</Button>
      </div>
    )
  }

  if (!status) return null

  /* ── Main render ────────────────────────────────────────────── */

  return (
    <>
      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="space-y-6">
        {/* Connection Lost Banner */}
        {connectionLost && (
          <div
            className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg px-4 py-2.5 flex items-center gap-3"
            style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
          >
            <WifiOff className="w-4 h-4 text-yellow-400 flex-shrink-0" />
            <span className="text-sm text-yellow-300">Connection issues detected. Retrying...</span>
          </div>
        )}

        {/* Header */}
        <div
          className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <div className="min-w-0">
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              <Bot className="w-7 h-7 text-primary-500 flex-shrink-0" />
              <span className="truncate">Agent: {agentId}</span>
            </h2>
            <div className="flex items-center gap-3 mt-2 flex-wrap">
              <span className={`px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1 ${
                status.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                status.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                status.status === 'paused' ? 'bg-yellow-500/20 text-yellow-400' :
                status.status === 'stopped' ? 'bg-orange-500/20 text-orange-400' :
                'bg-red-500/20 text-red-400'
              }`}>
                {PHASE_ICONS[status.status]}
                {status.status.charAt(0).toUpperCase() + status.status.slice(1)}
              </span>
              <span className="text-dark-400 text-sm">Mode: {MODE_LABELS[status.mode] || status.mode}</span>
              {status.task && <span className="text-dark-400 text-sm truncate max-w-xs">Task: {status.task}</span>}
              {status.started_at && (
                <span className="text-dark-500 text-xs">Started {relativeTime(status.started_at)}</span>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {/* Refresh button */}
            <button
              onClick={handleRefresh}
              className="p-2 rounded-lg bg-dark-800 border border-dark-700 hover:border-dark-600 text-dark-400 hover:text-white transition-all"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
            {status.status === 'running' && (
              <>
                <Button variant="secondary" onClick={handlePauseScan}>
                  <Pause className="w-4 h-4 mr-2" />
                  Pause
                </Button>
                <Button variant="danger" onClick={handleStopScan} isLoading={isStopping}>
                  <StopCircle className="w-4 h-4 mr-2" />
                  Stop
                </Button>
              </>
            )}
            {status.status === 'paused' && (
              <>
                <Button variant="primary" onClick={handleResumeScan}>
                  <Play className="w-4 h-4 mr-2" />
                  Resume
                </Button>
                <Button variant="danger" onClick={handleStopScan} isLoading={isStopping}>
                  <StopCircle className="w-4 h-4 mr-2" />
                  Stop
                </Button>
              </>
            )}
            {status.scan_id && (
              <Button variant="secondary" onClick={() => navigate(`/scan/${status.scan_id}`)}>
                <Shield className="w-4 h-4 mr-2" />
                View in Dashboard
              </Button>
            )}
            {/* Always show export if there are findings */}
            {(status.findings.length > 0 || status.report) && (
              <>
                <Button onClick={() => handleGenerateReport('html')} isLoading={isGeneratingReport} variant="primary">
                  <FileText className="w-4 h-4 mr-2" />
                  HTML Report
                </Button>
                <Button onClick={() => handleGenerateReport('json')} isLoading={isGeneratingReport} variant="secondary">
                  <Download className="w-4 h-4 mr-2" />
                  JSON
                </Button>
                {status.scan_id && (
                  <Button onClick={handleGenerateAiReport} isLoading={isGeneratingAiReport} variant="secondary">
                    <Sparkles className="w-4 h-4 mr-2" />
                    AI Report
                  </Button>
                )}
              </>
            )}
          </div>
        </div>

        {/* Progress with Phase Steps */}
        {(status.status === 'running' || status.status === 'completed' || status.status === 'stopped' || status.status === 'paused') && (
          <Card>
            <div
              className="space-y-4"
              style={{ animation: 'fadeSlideIn 0.3s ease-out 0.05s both' }}
            >
              {/* Phase Steps with Skip */}
              <div className="flex items-center justify-between px-2">
                {SCAN_PHASES.map((phase, index) => {
                  const currentIndex = status.status === 'completed' ? 4 : getPhaseIndex(status.phase)
                  const isActive = index === currentIndex
                  const isCompleted = index < currentIndex || status.status === 'completed'
                  const isStopped = status.status === 'stopped' && index > currentIndex
                  const isSkipped = skippedPhases.has(phase.key)
                  const canSkipTo = (status.status === 'running' || status.status === 'paused') && index > currentIndex && phase.key !== 'completed'

                  return (
                    <div key={phase.key} className="flex flex-col items-center flex-1 relative group">
                      {/* Connector line */}
                      {index > 0 && (
                        <div className={`absolute top-4 right-1/2 w-full h-0.5 -translate-y-1/2 z-0 ${
                          isCompleted || isActive ? 'bg-green-500/50' :
                          isSkipped ? 'bg-yellow-500/30' :
                          'bg-dark-700'
                        }`} />
                      )}

                      {/* Phase node */}
                      <div
                        className={`relative z-10 w-8 h-8 rounded-full flex items-center justify-center mb-1 transition-all ${
                          isSkipped ? 'bg-yellow-500/20 text-yellow-500 ring-2 ring-yellow-500/30' :
                          isCompleted ? 'bg-green-500 text-white' :
                          isActive ? 'bg-primary-500 text-white animate-pulse ring-2 ring-primary-500/30' :
                          isStopped ? 'bg-yellow-500/20 text-yellow-500' :
                          canSkipTo ? 'bg-dark-700 text-dark-400 cursor-pointer hover:bg-primary-500/20 hover:text-primary-400 hover:ring-2 hover:ring-primary-500/30' :
                          'bg-dark-700 text-dark-400'
                        }`}
                        onClick={() => canSkipTo && setSkipConfirm(phase.key)}
                      >
                        {isSkipped ? <MinusCircle className="w-4 h-4" /> :
                         isCompleted ? <CheckCircle className="w-4 h-4" /> :
                         isActive ? (PHASE_ICONS[phase.key === 'recon' ? 'reconnaissance' : phase.key] || <span className="text-xs font-bold">{index + 1}</span>) :
                         isStopped ? <StopCircle className="w-4 h-4" /> :
                         canSkipTo ? <SkipForward className="w-3.5 h-3.5" /> :
                         <span className="text-xs font-bold">{index + 1}</span>}
                      </div>

                      <span className={`text-xs text-center ${
                        isSkipped ? 'text-yellow-500' :
                        isCompleted || isActive ? 'text-white' :
                        canSkipTo ? 'text-dark-400 group-hover:text-primary-400' :
                        'text-dark-500'
                      }`}>
                        {isSkipped ? `${phase.label} (skipped)` : phase.label}
                      </span>

                      {/* Skip tooltip on hover */}
                      {canSkipTo && (
                        <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-dark-800 text-primary-400 text-[10px] px-2 py-0.5 rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none border border-dark-600">
                          Skip to {phase.label}
                        </div>
                      )}

                      {/* Inline skip confirmation */}
                      {skipConfirm === phase.key && (
                        <div className="absolute top-10 left-1/2 -translate-x-1/2 z-20 bg-dark-800 border border-dark-600 rounded-lg p-3 shadow-xl whitespace-nowrap">
                          <p className="text-xs text-dark-300 mb-2">Skip to <span className="text-white font-medium">{phase.label}</span>?</p>
                          <div className="flex gap-2">
                            <button
                              onClick={() => handleSkipToPhase(phase.key)}
                              disabled={isSkipping}
                              className="px-3 py-1 bg-primary-500 text-white text-xs rounded hover:bg-primary-600 disabled:opacity-50"
                            >
                              {isSkipping ? 'Skipping...' : 'Confirm'}
                            </button>
                            <button
                              onClick={() => setSkipConfirm(null)}
                              className="px-3 py-1 bg-dark-700 text-dark-300 text-xs rounded hover:bg-dark-600"
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>

              {/* Progress Bar */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-dark-300">
                  {PHASE_ICONS[status.phase.toLowerCase()] || <Clock className="w-4 h-4" />}
                  <span className="capitalize">{status.phase.replace(/_/g, ' ')}</span>
                </div>
                <span className="text-white font-medium tabular-nums">{status.progress}%</span>
              </div>
              <div className="h-2 bg-dark-900 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    status.status === 'completed' ? 'bg-green-500' :
                    status.status === 'stopped' ? 'bg-yellow-500' :
                    'bg-primary-500'
                  }`}
                  style={{ width: `${status.progress}%` }}
                />
              </div>
            </div>
          </Card>
        )}

        {/* Stats */}
        <div
          className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3"
          style={{ animation: 'fadeSlideIn 0.3s ease-out 0.1s both' }}
        >
          {/* Total */}
          <div className="bg-dark-800 rounded-xl border border-primary-500/20 p-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-white tabular-nums">{status.findings_count}</p>
              <p className="text-[11px] text-dark-400 mt-1">Total Findings</p>
            </div>
          </div>
          {/* Per-severity cards */}
          {SEVERITY_ORDER.map((sev, idx) => {
            const colorClass: Record<Severity, string> = {
              critical: 'text-red-500',
              high: 'text-orange-500',
              medium: 'text-yellow-500',
              low: 'text-blue-500',
              info: 'text-gray-400',
            }
            const borderClass: Record<Severity, string> = {
              critical: 'border-red-500/20',
              high: 'border-orange-500/20',
              medium: 'border-yellow-500/20',
              low: 'border-blue-500/20',
              info: 'border-dark-700',
            }
            return (
              <div
                key={sev}
                className={`bg-dark-800 rounded-xl border ${borderClass[sev]} p-4`}
                style={{ animation: `fadeSlideIn 0.3s ease-out ${0.1 + (idx + 1) * 0.03}s both` }}
              >
                <div className="text-center">
                  <p className={`text-2xl font-bold tabular-nums ${colorClass[sev]}`}>{severityCounts[sev]}</p>
                  <p className="text-[11px] text-dark-400 mt-1 capitalize">{sev}</p>
                </div>
              </div>
            )
          })}
        </div>

        {/* Custom Prompt Input */}
        {status.status === 'running' && (
          <Card>
            <div
              className="space-y-3"
              style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}
            >
              <div className="flex items-center gap-2 text-primary-400">
                <Brain className="w-5 h-5" />
                <h3 className="font-medium">Custom AI Prompt</h3>
              </div>
              <p className="text-sm text-dark-400">
                Send a custom instruction to the AI agent. Example: &quot;Test for IDOR on /api/users/[id]&quot; or &quot;Check for XXE in XML endpoints&quot;
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={customPrompt}
                  onChange={(e) => setCustomPrompt(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSubmitPrompt()}
                  placeholder="Enter custom vulnerability test prompt..."
                  className="flex-1 bg-dark-800 border border-dark-600 rounded-lg px-4 py-2 text-white placeholder-dark-400 focus:outline-none focus:border-primary-500 transition-colors"
                />
                <Button
                  onClick={handleSubmitPrompt}
                  isLoading={isSubmittingPrompt}
                  disabled={!customPrompt.trim()}
                >
                  <Send className="w-4 h-4 mr-2" />
                  Send
                </Button>
              </div>
            </div>
          </Card>
        )}

        {/* Findings */}
        <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}>
          <Card title="Vulnerabilities Found" subtitle={`${status.findings_count} findings`}>
            <div className="space-y-3 max-h-[600px] overflow-auto">
              {status.findings.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <AlertTriangle className="w-12 h-12 text-dark-600 mb-3" />
                  <p className="text-dark-400 text-sm">
                    {status.status === 'running' ? 'Scanning for vulnerabilities...' : 'No vulnerabilities found'}
                  </p>
                  {status.status === 'running' && (
                    <p className="text-dark-500 text-xs mt-1">Findings will appear here as they are discovered</p>
                  )}
                </div>
              ) : (
                status.findings.map((finding) => (
                  <div
                    key={finding.id}
                    className="bg-dark-900/50 rounded-lg border border-dark-700 overflow-hidden"
                  >
                    {/* Finding Header */}
                    <div
                      className="p-4 cursor-pointer hover:bg-dark-800/50 transition-colors"
                      onClick={() => toggleFinding(finding.id)}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-start gap-2 flex-1 min-w-0">
                          {expandedFindings.has(finding.id) ? (
                            <ChevronDown className="w-4 h-4 mt-1 text-dark-400 flex-shrink-0" />
                          ) : (
                            <ChevronRight className="w-4 h-4 mt-1 text-dark-400 flex-shrink-0" />
                          )}
                          <div className="flex-1 min-w-0">
                            <p className="font-medium text-white">{finding.title}</p>
                            <p className="text-sm text-dark-400 truncate">{finding.affected_endpoint}</p>
                            {finding.parameter && (
                              <p className="text-xs text-yellow-400 mt-1">
                                Parameter: <code className="bg-dark-800 px-1 rounded">{finding.parameter}</code>
                              </p>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <SeverityBadge severity={finding.severity} />
                          {finding.ai_verified && (
                            <span className="text-xs bg-purple-500/20 text-purple-400 px-2 py-0.5 rounded flex items-center gap-1">
                              <Brain className="w-3 h-3" />
                              AI Verified
                            </span>
                          )}
                          {typeof finding.confidence_score === 'number' && (
                            <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium tabular-nums ${
                              finding.confidence_score >= 90 ? 'bg-green-500/15 text-green-400 border-green-500/30' :
                              finding.confidence_score >= 60 ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' :
                              'bg-red-500/15 text-red-400 border-red-500/30'
                            }`}>
                              {finding.confidence_score}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Finding Details */}
                    {expandedFindings.has(finding.id) && renderFindingDetails(finding)}
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>

        {/* Split Log Viewers */}
        <div
          className="grid grid-cols-1 lg:grid-cols-2 gap-6"
          style={{ animation: 'fadeSlideIn 0.3s ease-out 0.2s both' }}
        >
          {/* Script Activity Log */}
          <Card
            title={
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-green-400" />
                <span>Script Activity</span>
                <span className="text-xs bg-dark-700 px-2 py-0.5 rounded text-dark-400 tabular-nums">
                  {scriptLogs.length}
                </span>
              </div>
            }
            subtitle="Tool executions, HTTP requests, scanning progress"
          >
            {renderLogViewer(scriptLogs, scriptLogsEndRef, 'Script', <Terminal className="w-3 h-3 text-green-400" />)}
          </Card>

          {/* LLM Activity Log */}
          <Card
            title={
              <div className="flex items-center gap-2">
                <Brain className="w-4 h-4 text-purple-400" />
                <span>AI Analysis</span>
                <span className="text-xs bg-dark-700 px-2 py-0.5 rounded text-dark-400 tabular-nums">
                  {llmLogs.length}
                </span>
              </div>
            }
            subtitle="LLM reasoning, vulnerability analysis, decisions"
          >
            {renderLogViewer(llmLogs, llmLogsEndRef, 'AI', <Brain className="w-3 h-3 text-purple-400" />)}
          </Card>
        </div>

        {/* Auto-scroll toggle */}
        <div className="flex justify-end">
          <label className="flex items-center gap-2 text-sm text-dark-400 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="w-4 h-4 rounded border-dark-600 bg-dark-800 text-primary-500 focus:ring-primary-500"
            />
            Auto-scroll logs
          </label>
        </div>

        {/* Report Summary */}
        {(status.status === 'completed' || status.status === 'stopped') && (status.report || status.findings.length > 0) && (() => {
          const reportData = status.report || {
            summary: {
              target: status.target,
              mode: status.mode,
              duration: status.started_at
                ? `${Math.round((new Date(status.completed_at || new Date().toISOString()).getTime() - new Date(status.started_at).getTime()) / 60000)} min`
                : 'N/A',
              total_findings: status.findings.length,
              severity_breakdown: {
                critical: status.findings.filter(f => f.severity === 'critical').length,
                high: status.findings.filter(f => f.severity === 'high').length,
                medium: status.findings.filter(f => f.severity === 'medium').length,
                low: status.findings.filter(f => f.severity === 'low').length,
                info: status.findings.filter(f => f.severity === 'info').length,
              },
            },
            executive_summary: status.status === 'stopped'
              ? `Scan was stopped by user. ${status.findings.length} finding(s) discovered before stopping.`
              : undefined,
            recommendations: [] as string[],
          }

          return (
            <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.25s both' }}>
              <Card title={status.status === 'stopped' ? 'Partial Report Summary' : 'Report Summary'}>
                <div className="space-y-4">
                  {status.status === 'stopped' && (
                    <div className="flex items-center gap-2 text-yellow-500 bg-yellow-500/10 border border-yellow-500/30 rounded-lg px-3 py-2">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                      <span className="text-sm">Scan was stopped - showing partial results</span>
                    </div>
                  )}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <p className="text-sm text-dark-400">Target</p>
                      <p className="text-white font-medium truncate" title={reportData.summary.target}>{reportData.summary.target}</p>
                    </div>
                    <div>
                      <p className="text-sm text-dark-400">Mode</p>
                      <p className="text-white font-medium">{MODE_LABELS[reportData.summary.mode] || reportData.summary.mode}</p>
                    </div>
                    <div>
                      <p className="text-sm text-dark-400">Duration</p>
                      <p className="text-white font-medium">{reportData.summary.duration}</p>
                    </div>
                    <div>
                      <p className="text-sm text-dark-400">Total Findings</p>
                      <p className="text-white font-medium tabular-nums">{reportData.summary.total_findings}</p>
                    </div>
                  </div>

                  {reportData.executive_summary && (
                    <div>
                      <p className="text-sm font-medium text-dark-300 mb-2">Executive Summary</p>
                      <p className="text-dark-400 whitespace-pre-wrap">{reportData.executive_summary}</p>
                    </div>
                  )}

                  {reportData.recommendations && reportData.recommendations.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-dark-300 mb-2">Recommendations</p>
                      <ul className="space-y-2">
                        {reportData.recommendations.map((rec: string, i: number) => (
                          <li key={i} className="flex items-start gap-2 text-dark-400">
                            <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
                            {rec}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </Card>
            </div>
          )
        })()}

        {/* Error Display */}
        {status.error && (
          <div
            className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-start gap-3"
            style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
          >
            <XCircle className="w-6 h-6 text-red-500 flex-shrink-0" />
            <div>
              <p className="font-medium text-red-400">Agent Error</p>
              <p className="text-sm text-red-300/80 mt-1">{status.error}</p>
            </div>
          </div>
        )}
      </div>
    </>
  )
}
