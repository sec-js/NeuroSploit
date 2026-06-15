import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Download, ExternalLink, FileText, RefreshCw, Maximize2 } from 'lucide-react'
import Button from '../components/common/Button'
import { reportsApi } from '../services/api'

export default function ReportViewPage() {
  const { reportId } = useParams<{ reportId: string }>()
  const navigate = useNavigate()
  const [isLoading, setIsLoading] = useState(true)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [iframeKey, setIframeKey] = useState(0)

  useEffect(() => {
    if (!reportId) {
      navigate('/reports')
      return
    }
    setIsLoading(false)
  }, [reportId, navigate])

  const handleRefresh = useCallback(() => {
    setIframeKey(k => k + 1)
  }, [])

  const toggleFullscreen = useCallback(() => {
    setIsFullscreen(f => !f)
  }, [])

  if (isLoading || !reportId) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <div className="animate-spin w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full" />
        <p className="text-dark-400 text-sm">Loading report...</p>
      </div>
    )
  }

  return (
    <>
      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <div
        className={`space-y-4 ${isFullscreen ? 'fixed inset-0 z-50 bg-dark-950 p-4' : ''}`}
        style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <Button variant="ghost" onClick={() => navigate('/reports')}>
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Reports
            </Button>
            <div className="hidden sm:flex items-center gap-2 text-dark-400">
              <FileText className="w-4 h-4" />
              <span className="text-sm font-mono truncate max-w-[200px]">{reportId}</span>
            </div>
          </div>

          <div className="flex gap-2 flex-wrap">
            <Button variant="ghost" size="sm" onClick={handleRefresh} title="Refresh report">
              <RefreshCw className="w-4 h-4" />
            </Button>
            <Button variant="ghost" size="sm" onClick={toggleFullscreen} title="Toggle fullscreen">
              <Maximize2 className="w-4 h-4" />
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => window.open(reportsApi.getDownloadUrl(reportId, 'html'), '_blank')}
            >
              <Download className="w-4 h-4 mr-1.5" />
              <span className="hidden sm:inline">HTML</span>
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => window.open(reportsApi.getDownloadUrl(reportId, 'json'), '_blank')}
            >
              <Download className="w-4 h-4 mr-1.5" />
              <span className="hidden sm:inline">JSON</span>
            </Button>
            <Button
              size="sm"
              onClick={() => window.open(reportsApi.getViewUrl(reportId), '_blank')}
            >
              <ExternalLink className="w-4 h-4 mr-1.5" />
              <span className="hidden sm:inline">New Tab</span>
            </Button>
          </div>
        </div>

        {/* Report iframe */}
        <div className="bg-dark-800 rounded-xl overflow-hidden border border-dark-900/50">
          <iframe
            key={iframeKey}
            src={reportsApi.getViewUrl(reportId)}
            className={`w-full ${isFullscreen ? 'h-[calc(100vh-80px)]' : 'h-[calc(100vh-200px)]'}`}
            title="Report"
          />
        </div>
      </div>
    </>
  )
}
