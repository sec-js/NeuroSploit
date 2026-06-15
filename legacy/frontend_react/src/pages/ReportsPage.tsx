import { useEffect, useMemo, useState, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  FileText, Download, Eye, Trash2, Calendar, Sparkles, Search,
  RefreshCw, X, WifiOff, Filter, ArrowUpDown, Plus, AlertTriangle,
  ExternalLink, Archive, Package
} from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { reportsApi, scansApi } from '../services/api'
import type { Report, Scan } from '../types'

/* ─── Constants ──────────────────────────────────────────────── */

const FORMAT_STYLE: Record<string, { bg: string; text: string; chart: string }> = {
  html: { bg: 'bg-blue-500/10', text: 'text-blue-400', chart: '#3b82f6' },
  json: { bg: 'bg-green-500/10', text: 'text-green-400', chart: '#22c55e' },
  pdf:  { bg: 'bg-red-500/10',   text: 'text-red-400',   chart: '#ef4444' },
}

/* ─── Helpers ────────────────────────────────────────────────── */

function relativeTime(ts: string): string {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

/* ─── Toast System ───────────────────────────────────────────── */

interface Toast { id: number; message: string; severity: 'info' | 'success' | 'warning' | 'error' }
let _toastId = 0

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null
  const border: Record<string, string> = {
    info: 'border-blue-500', success: 'border-green-500',
    warning: 'border-yellow-500', error: 'border-red-500',
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

/* ─── Format Mini Chart ──────────────────────────────────────── */

function FormatChart({ reports }: { reports: Report[] }) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {}
    reports.forEach(r => { counts[r.format] = (counts[r.format] || 0) + 1 })
    return Object.entries(counts).map(([name, value]) => ({
      name: name.toUpperCase(),
      value,
      color: FORMAT_STYLE[name]?.chart || '#6b7280',
    }))
  }, [reports])

  if (data.length === 0) return null

  return (
    <ResponsiveContainer width={80} height={80}>
      <PieChart>
        <Pie data={data} dataKey="value" cx="50%" cy="50%" innerRadius={20} outerRadius={35} paddingAngle={2} strokeWidth={0}>
          {data.map((d, i) => <Cell key={i} fill={d.color} />)}
        </Pie>
        <RechartsTooltip
          contentStyle={{ background: '#1a1a2e', border: '1px solid #2a2a3e', borderRadius: 8, fontSize: 11 }}
          itemStyle={{ color: '#e2e8f0' }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

/* ─── Delete Confirmation Modal ──────────────────────────────── */

function DeleteModal({ title, onConfirm, onCancel }: {
  title: string
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
          <h3 className="text-lg font-semibold text-white">Delete Report</h3>
        </div>
        <p className="text-sm text-dark-300 mb-6">
          Are you sure you want to delete <span className="text-white font-medium">&quot;{title}&quot;</span>?
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

/* ═══════════════════════════════════════════════════════════════
   Main Component
   ═══════════════════════════════════════════════════════════════ */

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([])
  const [scans, setScans] = useState<Map<string, Scan>>(new Map())
  const [isLoading, setIsLoading] = useState(true)
  const [toasts, setToasts] = useState<Toast[]>([])
  const [connectionLost, setConnectionLost] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [regeneratingId, setRegeneratingId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; title: string } | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [formatFilter, setFormatFilter] = useState<string>('all')
  const [sortBy, setSortBy] = useState<'date' | 'name' | 'vulns'>('date')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const consecutiveErrorsRef = useRef(0)

  /* ── Toast helpers ──────────────────────────────────────────── */

  const addToast = useCallback((message: string, severity: Toast['severity'] = 'info') => {
    const id = ++_toastId
    setToasts(prev => [...prev.slice(-4), { id, message, severity }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  /* ── Data fetch ─────────────────────────────────────────────── */

  const fetchData = useCallback(async () => {
    try {
      const [reportsData, scansData] = await Promise.all([
        reportsApi.list(),
        scansApi.list(1, 100),
      ])
      setReports(reportsData.reports)
      const scansMap = new Map<string, Scan>()
      scansData.scans.forEach((scan: Scan) => scansMap.set(scan.id, scan))
      setScans(scansMap)

      if (consecutiveErrorsRef.current >= 3) {
        setConnectionLost(false)
        addToast('Connection restored', 'success')
      }
      consecutiveErrorsRef.current = 0
    } catch (error) {
      console.error('Failed to fetch reports:', error)
      consecutiveErrorsRef.current++
      if (consecutiveErrorsRef.current >= 3) setConnectionLost(true)
    }
  }, [addToast])

  useEffect(() => {
    setIsLoading(true)
    fetchData().finally(() => setIsLoading(false))
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [fetchData])

  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    await fetchData()
    setRefreshing(false)
    addToast('Reports refreshed', 'info')
  }, [fetchData, addToast])

  /* ── Actions ────────────────────────────────────────────────── */

  const handleDelete = useCallback(async () => {
    if (!deleteTarget) return
    try {
      await reportsApi.delete(deleteTarget.id)
      setReports(prev => prev.filter(r => r.id !== deleteTarget.id))
      addToast(`Report deleted`, 'success')
    } catch (error) {
      console.error('Failed to delete report:', error)
      addToast('Failed to delete report', 'error')
    } finally {
      setDeleteTarget(null)
    }
  }, [deleteTarget, addToast])

  const handleDownload = useCallback((reportId: string, format: string) => {
    window.open(reportsApi.getDownloadUrl(reportId, format), '_blank')
    addToast(`Downloading ${format.toUpperCase()} report`, 'info')
  }, [addToast])

  const handleDownloadZip = useCallback((reportId: string) => {
    window.open(reportsApi.getDownloadZipUrl(reportId), '_blank')
    addToast('Downloading ZIP package', 'info')
  }, [addToast])

  const handleAiRegenerate = useCallback(async (scanId: string, reportTitle: string) => {
    setRegeneratingId(scanId)
    try {
      const report = await reportsApi.generateAiReport({
        scan_id: scanId,
        title: `AI Report - ${reportTitle}`,
      })
      window.open(reportsApi.getViewUrl(report.id), '_blank')
      const reportsData = await reportsApi.list()
      setReports(reportsData.reports)
      addToast('AI report generated successfully', 'success')
    } catch (error) {
      console.error('Failed to generate AI report:', error)
      addToast('Failed to generate AI report', 'error')
    } finally {
      setRegeneratingId(null)
    }
  }, [addToast])

  /* ── Derived data ───────────────────────────────────────────── */

  const filteredReports = useMemo(() => {
    let result = [...reports]

    if (formatFilter !== 'all') {
      result = result.filter(r => r.format === formatFilter)
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      result = result.filter(r => {
        const scan = scans.get(r.scan_id)
        const title = (r.title || scan?.name || '').toLowerCase()
        return title.includes(q) || r.format.includes(q)
      })
    }

    result.sort((a, b) => {
      let cmp = 0
      if (sortBy === 'date') {
        cmp = new Date(a.generated_at).getTime() - new Date(b.generated_at).getTime()
      } else if (sortBy === 'name') {
        const na = (a.title || scans.get(a.scan_id)?.name || '').toLowerCase()
        const nb = (b.title || scans.get(b.scan_id)?.name || '').toLowerCase()
        cmp = na.localeCompare(nb)
      } else if (sortBy === 'vulns') {
        cmp = (scans.get(a.scan_id)?.total_vulnerabilities || 0) - (scans.get(b.scan_id)?.total_vulnerabilities || 0)
      }
      return sortDir === 'desc' ? -cmp : cmp
    })

    return result
  }, [reports, formatFilter, searchQuery, sortBy, sortDir, scans])

  const statsData = useMemo(() => {
    const totalVulns = reports.reduce((sum, r) => sum + (scans.get(r.scan_id)?.total_vulnerabilities || 0), 0)
    const formats: Record<string, number> = {}
    reports.forEach(r => { formats[r.format] = (formats[r.format] || 0) + 1 })
    const autoCount = reports.filter(r => r.auto_generated).length
    return { totalVulns, formats, autoCount }
  }, [reports, scans])

  /* ── Render ─────────────────────────────────────────────────── */

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {deleteTarget && (
        <DeleteModal
          title={deleteTarget.title}
          onConfirm={handleDelete}
          onCancel={() => setDeleteTarget(null)}
        />
      )}

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

      {/* ── Header ────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-primary-500" />
            Reports
          </h2>
          <p className="text-dark-400 mt-1">View and download security assessment reports</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            className="p-2 rounded-lg bg-dark-800 border border-dark-700 hover:border-dark-600 text-dark-400 hover:text-white transition-all"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
          <Link to="/scan/new">
            <Button>
              <Plus className="w-4 h-4 mr-2" />
              New Scan
            </Button>
          </Link>
        </div>
      </div>

      {/* ── Stats Row ─────────────────────────────────────────── */}
      {reports.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {/* Total Reports */}
          <div
            className="bg-dark-800 rounded-xl border border-primary-500/20 p-4"
            style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary-500/10">
                <FileText className="w-5 h-5 text-primary-500" />
              </div>
              <div>
                <p className="text-xl font-bold text-white tabular-nums">{reports.length}</p>
                <p className="text-[11px] text-dark-400">Total Reports</p>
              </div>
            </div>
          </div>

          {/* Total Vulns */}
          <div
            className="bg-dark-800 rounded-xl border border-red-500/20 p-4"
            style={{ animation: 'fadeSlideIn 0.3s ease-out 0.05s both' }}
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="text-xl font-bold text-white tabular-nums">{statsData.totalVulns}</p>
                <p className="text-[11px] text-dark-400">Total Vulns</p>
              </div>
            </div>
          </div>

          {/* AI Generated */}
          <div
            className="bg-dark-800 rounded-xl border border-yellow-500/20 p-4"
            style={{ animation: 'fadeSlideIn 0.3s ease-out 0.1s both' }}
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-500/10">
                <Sparkles className="w-5 h-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-xl font-bold text-white tabular-nums">{statsData.autoCount}</p>
                <p className="text-[11px] text-dark-400">AI Generated</p>
              </div>
            </div>
          </div>

          {/* Format Distribution */}
          <div
            className="bg-dark-800 rounded-xl border border-dark-700 p-4 flex items-center justify-between"
            style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}
          >
            <div className="flex flex-col gap-1">
              {Object.entries(statsData.formats).map(([fmt, count]) => {
                const fs = FORMAT_STYLE[fmt] || { bg: 'bg-dark-700', text: 'text-dark-300' }
                return (
                  <div key={fmt} className="flex items-center gap-2">
                    <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${fs.bg} ${fs.text}`}>
                      {fmt}
                    </span>
                    <span className="text-sm text-white font-semibold tabular-nums">{count}</span>
                  </div>
                )
              })}
            </div>
            <FormatChart reports={reports} />
          </div>
        </div>
      )}

      {/* ── Search + Filters ──────────────────────────────────── */}
      {reports.length > 0 && (
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
            <input
              type="text"
              placeholder="Search reports..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-white placeholder-dark-500 focus:outline-none focus:border-primary-500/50 transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Format Filter */}
          <div className="flex items-center gap-1">
            <Filter className="w-3.5 h-3.5 text-dark-500 mr-1" />
            {(['all', 'html', 'json', 'pdf'] as const).map(f => (
              <button
                key={f}
                onClick={() => setFormatFilter(f)}
                className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  formatFilter === f
                    ? 'bg-primary-500/20 text-primary-400'
                    : 'text-dark-400 hover:text-dark-200 hover:bg-dark-700'
                }`}
              >
                {f === 'all' ? 'All' : f.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Sort */}
          <div className="flex items-center gap-1 ml-auto">
            <ArrowUpDown className="w-3.5 h-3.5 text-dark-500 mr-1" />
            {(['date', 'name', 'vulns'] as const).map(s => (
              <button
                key={s}
                onClick={() => {
                  if (sortBy === s) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
                  else { setSortBy(s); setSortDir('desc') }
                }}
                className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  sortBy === s
                    ? 'bg-primary-500/20 text-primary-400'
                    : 'text-dark-400 hover:text-dark-200 hover:bg-dark-700'
                }`}
              >
                {s === 'date' ? 'Date' : s === 'name' ? 'Name' : 'Vulns'}
                {sortBy === s && <span className="ml-1">{sortDir === 'desc' ? '\u2193' : '\u2191'}</span>}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Report List ───────────────────────────────────────── */}
      {reports.length === 0 ? (
        <Card>
          <div className="text-center py-12">
            <FileText className="w-16 h-16 mx-auto text-dark-500 mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Reports Yet</h3>
            <p className="text-dark-400 mb-4">Reports are generated after completing a security scan.</p>
            <Link to="/scan/new">
              <Button>Start a New Scan</Button>
            </Link>
          </div>
        </Card>
      ) : filteredReports.length === 0 ? (
        <Card>
          <div className="text-center py-8">
            <Search className="w-10 h-10 mx-auto text-dark-500 mb-3" />
            <p className="text-dark-400 text-sm">No reports match your filters</p>
            <button
              onClick={() => { setSearchQuery(''); setFormatFilter('all') }}
              className="text-primary-500 text-sm hover:underline mt-1"
            >
              Clear filters
            </button>
          </div>
        </Card>
      ) : (
        <div className="grid gap-3">
          <p className="text-xs text-dark-500">
            {filteredReports.length} report{filteredReports.length !== 1 ? 's' : ''}
            {filteredReports.length !== reports.length && ` of ${reports.length}`}
          </p>

          {filteredReports.map((report, idx) => {
            const scan = scans.get(report.scan_id)
            const title = report.title || scan?.name || 'Security Report'
            const fs = FORMAT_STYLE[report.format] || { bg: 'bg-dark-700', text: 'text-dark-300' }

            return (
              <div
                key={report.id}
                className="bg-dark-800 rounded-xl border border-dark-900/50 hover:border-dark-700 transition-all group"
                style={{ animation: `fadeSlideIn 0.3s ease-out ${Math.min(idx * 0.04, 0.4)}s both` }}
              >
                <div className="p-4">
                  {/* Top row */}
                  <div className="flex items-start gap-4">
                    <div className={`p-2.5 rounded-lg ${fs.bg} flex-shrink-0`}>
                      <FileText className={`w-5 h-5 ${fs.text}`} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="font-medium text-white truncate max-w-[300px] sm:max-w-none">
                          {title}
                        </h3>
                        <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${fs.bg} ${fs.text}`}>
                          {report.format}
                        </span>
                        {report.auto_generated && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 flex items-center gap-0.5">
                            <Sparkles className="w-2.5 h-2.5" /> Auto
                          </span>
                        )}
                        {report.is_partial && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400">
                            Partial
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                        <span className="text-xs text-dark-500 flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {relativeTime(report.generated_at)}
                        </span>

                        {scan && scan.total_vulnerabilities > 0 && (
                          <div className="flex items-center gap-1">
                            {scan.critical_count > 0 && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 font-bold tabular-nums">
                                {scan.critical_count}C
                              </span>
                            )}
                            {scan.high_count > 0 && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-500/20 text-orange-400 font-bold tabular-nums">
                                {scan.high_count}H
                              </span>
                            )}
                            {scan.medium_count > 0 && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-yellow-500/20 text-yellow-400 font-bold tabular-nums">
                                {scan.medium_count}M
                              </span>
                            )}
                            {scan.low_count > 0 && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-500/20 text-blue-400 font-bold tabular-nums">
                                {scan.low_count}L
                              </span>
                            )}
                          </div>
                        )}

                        {scan && (
                          <Link
                            to={`/scan/${scan.id}`}
                            className="text-xs text-primary-500 hover:text-primary-400 flex items-center gap-0.5"
                            onClick={e => e.stopPropagation()}
                          >
                            View Scan <ExternalLink className="w-2.5 h-2.5" />
                          </Link>
                        )}
                      </div>
                    </div>

                    {/* Actions — Desktop */}
                    <div className="hidden sm:flex items-center gap-1.5 flex-shrink-0">
                      <button
                        onClick={() => window.open(reportsApi.getViewUrl(report.id), '_blank')}
                        className="p-2 rounded-lg text-dark-400 hover:text-white hover:bg-dark-700 transition-colors"
                        title="View in browser"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDownload(report.id, 'html')}
                        className="p-2 rounded-lg text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 transition-colors"
                        title="Download HTML"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDownload(report.id, 'json')}
                        className="p-2 rounded-lg text-green-400 hover:text-green-300 hover:bg-green-500/10 transition-colors"
                        title="Download JSON"
                      >
                        <Package className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDownloadZip(report.id)}
                        className="p-2 rounded-lg text-purple-400 hover:text-purple-300 hover:bg-purple-500/10 transition-colors"
                        title="Download ZIP"
                      >
                        <Archive className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleAiRegenerate(report.scan_id, title)}
                        disabled={regeneratingId === report.scan_id}
                        className="p-2 rounded-lg text-yellow-400 hover:text-yellow-300 hover:bg-yellow-500/10 transition-colors disabled:opacity-40"
                        title="Generate AI Report"
                      >
                        <Sparkles className={`w-4 h-4 ${regeneratingId === report.scan_id ? 'animate-spin' : ''}`} />
                      </button>
                      <button
                        onClick={() => setDeleteTarget({ id: report.id, title })}
                        className="p-2 rounded-lg text-dark-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Actions — Mobile */}
                  <div className="flex sm:hidden items-center gap-1.5 mt-3 pt-3 border-t border-dark-900/50 flex-wrap">
                    <button
                      onClick={() => window.open(reportsApi.getViewUrl(report.id), '_blank')}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-dark-700 text-dark-300 hover:text-white text-xs font-medium transition-colors"
                    >
                      <Eye className="w-3.5 h-3.5" /> View
                    </button>
                    <button
                      onClick={() => handleDownload(report.id, 'html')}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-dark-700 text-blue-400 hover:bg-blue-500/10 text-xs font-medium transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" /> HTML
                    </button>
                    <button
                      onClick={() => handleDownloadZip(report.id)}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-dark-700 text-purple-400 hover:bg-purple-500/10 text-xs font-medium transition-colors"
                    >
                      <Archive className="w-3.5 h-3.5" /> ZIP
                    </button>
                    <button
                      onClick={() => handleAiRegenerate(report.scan_id, title)}
                      disabled={regeneratingId === report.scan_id}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-dark-700 text-yellow-400 hover:bg-yellow-500/10 text-xs font-medium transition-colors disabled:opacity-40"
                    >
                      <Sparkles className={`w-3.5 h-3.5 ${regeneratingId === report.scan_id ? 'animate-spin' : ''}`} /> AI
                    </button>
                    <button
                      onClick={() => setDeleteTarget({ id: report.id, title })}
                      className="px-3 py-2 rounded-lg bg-dark-700 text-dark-500 hover:text-red-400 hover:bg-red-500/10 text-xs transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
