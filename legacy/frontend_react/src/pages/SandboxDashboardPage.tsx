import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Box, RefreshCw, Trash2, Heart, Clock, Cpu,
  HardDrive, Timer, CheckCircle2,
  XCircle, Wrench, Container, X, WifiOff
} from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { sandboxApi } from '../services/api'
import type { SandboxPoolStatus, SandboxContainer } from '../types'

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60)
    const s = Math.floor(seconds % 60)
    return `${m}m ${s}s`
  }
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

function relativeTime(isoDate: string | null): string {
  if (!isoDate) return 'Unknown'
  const now = Date.now()
  const then = new Date(isoDate).getTime()
  const diffMs = now - then
  const diffS = Math.floor(diffMs / 1000)
  if (diffS < 5) return 'just now'
  if (diffS < 60) return `${diffS}s ago`
  const diffM = Math.floor(diffS / 60)
  if (diffM < 60) return `${diffM}m ago`
  const diffH = Math.floor(diffM / 60)
  if (diffH < 24) return `${diffH}h ${diffM % 60}m ago`
  const diffD = Math.floor(diffH / 24)
  return `${diffD}d ${diffH % 24}h ago`
}

/* ------------------------------------------------------------------ */
/*  Toast System                                                      */
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
/*  Donut Chart Colors                                                */
/* ------------------------------------------------------------------ */

const DONUT_COLORS = ['#3b82f6', '#1e293b']

/* ------------------------------------------------------------------ */
/*  Page Component                                                    */
/* ------------------------------------------------------------------ */

export default function SandboxDashboardPage() {
  const [data, setData] = useState<SandboxPoolStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [toasts, setToasts] = useState<Toast[]>([])
  const [destroyConfirm, setDestroyConfirm] = useState<string | null>(null)
  const [healthResults, setHealthResults] = useState<Record<string, { status: string; tools: string[] } | null>>({})
  const [healthLoading, setHealthLoading] = useState<Record<string, boolean>>({})
  const [actionLoading, setActionLoading] = useState(false)
  const [refreshSpinning, setRefreshSpinning] = useState(false)
  const [pollFailures, setPollFailures] = useState(0)
  const dataRef = useRef(data)
  dataRef.current = data

  /* Toast helpers */
  const addToast = useCallback((message: string, severity: Toast['severity'] = 'info') => {
    const id = ++_toastId
    setToasts(prev => [...prev, { id, message, severity }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 4000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const fetchData = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    try {
      const result = await sandboxApi.list()
      setData(result)
      setPollFailures(0)
    } catch (error) {
      console.error('Failed to fetch sandbox data:', error)
      setPollFailures(prev => prev + 1)
      if (!dataRef.current) {
        setData({
          pool: { active: 0, max_concurrent: 0, image: 'N/A', container_ttl_minutes: 0, docker_available: false },
          containers: [],
          error: 'Failed to connect to backend',
        })
      }
    } finally {
      setLoading(false)
    }
  }, [])

  /* Initial fetch + 15-second polling */
  useEffect(() => {
    fetchData(true)
    const interval = setInterval(() => fetchData(false), 15000)
    return () => clearInterval(interval)
  }, [fetchData])

  const handleRefreshClick = useCallback(() => {
    setRefreshSpinning(true)
    fetchData(false)
    setTimeout(() => setRefreshSpinning(false), 800)
  }, [fetchData])

  const handleDestroy = async (scanId: string) => {
    if (destroyConfirm !== scanId) {
      setDestroyConfirm(scanId)
      setTimeout(() => setDestroyConfirm(null), 5000)
      return
    }
    setDestroyConfirm(null)
    setActionLoading(true)
    try {
      await sandboxApi.destroy(scanId)
      addToast(`Container for scan ${scanId.slice(0, 8)}... destroyed`, 'success')
      fetchData(false)
    } catch (error: any) {
      addToast(error?.response?.data?.detail || 'Failed to destroy container', 'error')
    } finally {
      setActionLoading(false)
    }
  }

  const handleHealthCheck = async (scanId: string) => {
    setHealthLoading(prev => ({ ...prev, [scanId]: true }))
    try {
      const result = await sandboxApi.healthCheck(scanId)
      setHealthResults(prev => ({ ...prev, [scanId]: result }))
      setTimeout(() => {
        setHealthResults(prev => ({ ...prev, [scanId]: null }))
      }, 8000)
    } catch {
      setHealthResults(prev => ({ ...prev, [scanId]: { status: 'error', tools: [] } }))
    } finally {
      setHealthLoading(prev => ({ ...prev, [scanId]: false }))
    }
  }

  const handleCleanup = async (type: 'expired' | 'orphans') => {
    setActionLoading(true)
    try {
      if (type === 'expired') {
        await sandboxApi.cleanup()
      } else {
        await sandboxApi.cleanupOrphans()
      }
      addToast(`${type === 'expired' ? 'Expired' : 'Orphan'} containers cleaned up`, 'success')
      fetchData(false)
    } catch (error: any) {
      addToast(error?.response?.data?.detail || 'Cleanup failed', 'error')
    } finally {
      setActionLoading(false)
    }
  }

  const pool = data?.pool
  const containers = data?.containers || []
  const utilizationPct = pool ? (pool.max_concurrent > 0 ? (pool.active / pool.max_concurrent) * 100 : 0) : 0

  const donutData = useMemo(() => {
    if (!pool || pool.max_concurrent === 0) return []
    return [
      { name: 'Active', value: pool.active },
      { name: 'Available', value: Math.max(0, pool.max_concurrent - pool.active) },
    ]
  }, [pool])

  const connectionLost = pollFailures >= 3

  if (loading && !data) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 bg-dark-800 rounded w-64" />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="h-24 bg-dark-800 rounded-lg" />
          ))}
        </div>
        <div className="space-y-4">
          {[1, 2].map(i => (
            <div key={i} className="h-40 bg-dark-800 rounded-lg" />
          ))}
        </div>
      </div>
    )
  }

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

      {/* Connection Lost Banner */}
      {connectionLost && (
        <div
          className="flex items-center gap-3 px-4 py-3 rounded-lg bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 text-sm"
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <WifiOff className="w-4 h-4 flex-shrink-0" />
          <span>Connection lost -- data may be stale. Retrying automatically...</span>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
              <Container className="w-6 h-6 text-blue-400" />
            </div>
            <Box className="w-5 h-5 text-dark-400 -ml-1" />
            Sandbox Containers
          </h1>
          <p className="text-dark-400 mt-1">Real-time monitoring of per-scan Kali Linux containers</p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleCleanup('expired')}
            isLoading={actionLoading}
          >
            <Timer className="w-4 h-4 mr-1" />
            Cleanup Expired
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleCleanup('orphans')}
            isLoading={actionLoading}
          >
            <Trash2 className="w-4 h-4 mr-1" />
            Cleanup Orphans
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleRefreshClick}
          >
            <RefreshCw
              className="w-4 h-4 mr-1"
              style={refreshSpinning ? { animation: 'spinOnce 0.6s ease-in-out' } : undefined}
            />
            Refresh
          </Button>
        </div>
      </div>

      {/* Pool Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {/* Active Containers */}
        <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.05s both' }}>
          <Card>
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                utilizationPct >= 100 ? 'bg-red-500/20' :
                utilizationPct >= 80 ? 'bg-yellow-500/20' :
                'bg-green-500/20'
              }`}>
                <Box className={`w-5 h-5 ${
                  utilizationPct >= 100 ? 'text-red-400' :
                  utilizationPct >= 80 ? 'text-yellow-400' :
                  'text-green-400'
                }`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">
                  {pool?.active || 0}<span className="text-dark-400 text-lg">/{pool?.max_concurrent || 0}</span>
                </p>
                <p className="text-xs text-dark-400">Active Containers</p>
              </div>
            </div>
          </Card>
        </div>

        {/* Docker Status */}
        <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.1s both' }}>
          <Card>
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                pool?.docker_available ? 'bg-green-500/20' : 'bg-red-500/20'
              }`}>
                <HardDrive className={`w-5 h-5 ${
                  pool?.docker_available ? 'text-green-400' : 'text-red-400'
                }`} />
              </div>
              <div>
                <p className="text-lg font-bold text-white">
                  {pool?.docker_available ? 'Online' : 'Offline'}
                </p>
                <p className="text-xs text-dark-400">Docker Engine</p>
              </div>
            </div>
          </Card>
        </div>

        {/* Container Image */}
        <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}>
          <Card>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
                <Cpu className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <p className="text-sm font-bold text-white truncate max-w-[140px]" title={pool?.image}>
                  {pool?.image?.split(':')[0]?.split('/').pop() || 'N/A'}
                </p>
                <p className="text-xs text-dark-400">
                  {pool?.image?.includes(':') ? pool.image.split(':')[1] : 'latest'}
                </p>
              </div>
            </div>
          </Card>
        </div>

        {/* TTL */}
        <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.2s both' }}>
          <Card>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center">
                <Clock className="w-5 h-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">
                  {pool?.container_ttl_minutes || 0}<span className="text-dark-400 text-lg"> min</span>
                </p>
                <p className="text-xs text-dark-400">Container TTL</p>
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* Capacity Bar + Donut Chart */}
      {pool && pool.max_concurrent > 0 && (
        <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
            {/* Bar section */}
            <div className="flex-1 w-full">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-dark-300">Pool Capacity</span>
                <span className={`text-sm font-medium ${
                  utilizationPct >= 100 ? 'text-red-400' :
                  utilizationPct >= 80 ? 'text-yellow-400' :
                  'text-green-400'
                }`}>
                  {Math.round(utilizationPct)}%
                </span>
              </div>
              <div className="w-full bg-dark-900 rounded-full h-2.5">
                <div
                  className={`h-2.5 rounded-full transition-all duration-500 ${
                    utilizationPct >= 100 ? 'bg-red-500' :
                    utilizationPct >= 80 ? 'bg-yellow-500' :
                    'bg-green-500'
                  }`}
                  style={{ width: `${Math.min(utilizationPct, 100)}%` }}
                />
              </div>
            </div>

            {/* Donut chart */}
            {donutData.length > 0 && (
              <div className="w-24 h-24 flex-shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={donutData}
                      cx="50%"
                      cy="50%"
                      innerRadius={25}
                      outerRadius={38}
                      paddingAngle={2}
                      dataKey="value"
                      stroke="none"
                    >
                      {donutData.map((_entry, index) => (
                        <Cell key={`cell-${index}`} fill={DONUT_COLORS[index % DONUT_COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }}
                      itemStyle={{ color: '#e2e8f0' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Container List */}
      {containers.length === 0 ? (
        <div className="bg-dark-800 rounded-lg border border-dark-700 p-12 text-center">
          <Box className="w-16 h-16 text-dark-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-dark-300 mb-2">No Sandbox Containers Running</h3>
          <p className="text-dark-400 text-sm max-w-md mx-auto">
            Containers are automatically created when scans start and destroyed when they complete.
            Start a scan to see containers here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <h2 className="text-lg font-semibold text-white">
            Running Containers ({containers.length})
          </h2>

          {containers.map((container: SandboxContainer, idx: number) => {
            const health = healthResults[container.scan_id]
            const isHealthLoading = healthLoading[container.scan_id]
            const isConfirming = destroyConfirm === container.scan_id

            return (
              <div
                key={container.scan_id}
                className="bg-dark-800 rounded-lg border border-dark-700 p-5 hover:border-dark-600 transition-colors"
                style={{ animation: `fadeSlideIn 0.3s ease-out ${0.05 * (idx + 1)}s both` }}
              >
                {/* Container Header */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full ${
                      container.available ? 'bg-green-500 animate-pulse' : 'bg-red-500'
                    }`} />
                    <div>
                      <h3 className="text-white font-medium font-mono text-sm">
                        {container.container_name}
                      </h3>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs text-dark-400">Scan:</span>
                        <Link
                          to={`/scan/${container.scan_id}`}
                          className="text-xs text-primary-400 hover:text-primary-300 font-mono"
                        >
                          {container.scan_id.slice(0, 12)}...
                        </Link>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Status badge */}
                    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${
                      container.available
                        ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                        : 'bg-red-500/10 text-red-400 border border-red-500/30'
                    }`}>
                      {container.available ? (
                        <><CheckCircle2 className="w-3 h-3" /> Running</>
                      ) : (
                        <><XCircle className="w-3 h-3" /> Stopped</>
                      )}
                    </span>
                  </div>
                </div>

                {/* Container Info Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 mb-4">
                  {/* Uptime */}
                  <div>
                    <p className="text-xs text-dark-400 mb-1">Uptime</p>
                    <p className="text-sm text-white font-medium">
                      {formatUptime(container.uptime_seconds)}
                    </p>
                  </div>

                  {/* Created */}
                  <div>
                    <p className="text-xs text-dark-400 mb-1">Created</p>
                    <p className="text-sm text-dark-300" title={container.created_at || undefined}>
                      {relativeTime(container.created_at)}
                    </p>
                  </div>

                  {/* Tools count */}
                  <div>
                    <p className="text-xs text-dark-400 mb-1">Installed Tools</p>
                    <p className="text-sm text-white font-medium">
                      {container.installed_tools.length}
                    </p>
                  </div>
                </div>

                {/* Installed Tools */}
                {container.installed_tools.length > 0 && (
                  <div className="mb-4">
                    <p className="text-xs text-dark-400 mb-2">Tools</p>
                    <div className="flex flex-wrap gap-1.5">
                      {container.installed_tools.map(tool => (
                        <span
                          key={tool}
                          className="inline-flex items-center gap-1 px-2 py-0.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-300"
                        >
                          <Wrench className="w-3 h-3 text-dark-500" />
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Health Check Result */}
                {health && (
                  <div className={`mb-4 px-3 py-2 rounded-lg text-xs ${
                    health.status === 'healthy'
                      ? 'bg-green-500/10 border border-green-500/20 text-green-400'
                      : health.status === 'degraded'
                      ? 'bg-yellow-500/10 border border-yellow-500/20 text-yellow-400'
                      : 'bg-red-500/10 border border-red-500/20 text-red-400'
                  }`} style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
                    <span className="font-medium">Health: {health.status}</span>
                    {health.tools.length > 0 && (
                      <span className="ml-2">
                        -- Verified: {health.tools.join(', ')}
                      </span>
                    )}
                  </div>
                )}

                {/* Actions */}
                <div className="flex items-center gap-2 pt-3 border-t border-dark-700 flex-wrap">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleHealthCheck(container.scan_id)}
                    isLoading={isHealthLoading}
                  >
                    <Heart className="w-4 h-4 mr-1" />
                    Health Check
                  </Button>

                  <Button
                    variant={isConfirming ? 'danger' : 'ghost'}
                    size="sm"
                    onClick={() => handleDestroy(container.scan_id)}
                    isLoading={actionLoading}
                  >
                    <Trash2 className="w-4 h-4 mr-1" />
                    {isConfirming ? 'Confirm Destroy' : 'Destroy'}
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Auto-refresh indicator */}
      <div className="text-center text-xs text-dark-500">
        Auto-refreshing every 15 seconds
      </div>
    </div>
  )
}
