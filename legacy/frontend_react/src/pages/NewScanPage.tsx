import { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Upload, Link as LinkIcon, FileText, Play, AlertTriangle,
  Bot, Search, Target, Brain, BookOpen, ChevronDown, Key, Settings, X
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'
import Textarea from '../components/common/Textarea'
import { agentApi, targetsApi } from '../services/api'
import type { AgentTask, AgentMode, AgentRequest } from '../types'

type TargetInputMode = 'single' | 'multiple' | 'file'

type AuthTypeOption = 'none' | 'cookie' | 'bearer' | 'basic' | 'header'

interface OperationModeInfo {
  id: AgentMode
  name: string
  icon: React.ReactNode
  description: string
  warning?: string
  color: string
}

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
    error: 'border-red-500'
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

const OPERATION_MODES: OperationModeInfo[] = [
  {
    id: 'full_auto',
    name: 'Full Auto',
    icon: <Bot className="w-5 h-5" />,
    description: 'Complete workflow: Recon -> Analyze -> Test -> Report',
    color: 'primary'
  },
  {
    id: 'recon_only',
    name: 'Recon Only',
    icon: <Search className="w-5 h-5" />,
    description: 'Reconnaissance and enumeration only, no vulnerability testing',
    color: 'blue'
  },
  {
    id: 'prompt_only',
    name: 'AI Prompt Mode',
    icon: <Brain className="w-5 h-5" />,
    description: 'AI decides everything based on your prompt - full autonomy',
    warning: 'HIGH TOKEN USAGE - The AI will use more API calls to decide what to do',
    color: 'purple'
  },
  {
    id: 'analyze_only',
    name: 'Analyze Only',
    icon: <Target className="w-5 h-5" />,
    description: 'Analyze provided data without active testing',
    color: 'green'
  }
]

const TASK_CATEGORIES = [
  { id: 'all', name: 'All Tasks' },
  { id: 'full_auto', name: 'Full Auto' },
  { id: 'recon', name: 'Reconnaissance' },
  { id: 'vulnerability', name: 'Vulnerability' },
  { id: 'custom', name: 'Custom' },
  { id: 'reporting', name: 'Reporting' }
]

const AUTH_TYPE_OPTIONS: { id: AuthTypeOption; label: string }[] = [
  { id: 'none', label: 'None' },
  { id: 'cookie', label: 'Cookie' },
  { id: 'bearer', label: 'Bearer Token' },
  { id: 'basic', label: 'Basic Auth' },
  { id: 'header', label: 'Custom Header' }
]

export default function NewScanPage() {
  const navigate = useNavigate()
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Target state
  const [targetMode, setTargetMode] = useState<TargetInputMode>('single')
  const [singleUrl, setSingleUrl] = useState('')
  const [multipleUrls, setMultipleUrls] = useState('')
  const [uploadedUrls, setUploadedUrls] = useState<string[]>([])
  const [urlError, setUrlError] = useState('')

  // Operation mode
  const [operationMode, setOperationMode] = useState<AgentMode>('full_auto')

  // Task library
  const [tasks, setTasks] = useState<AgentTask[]>([])
  const [selectedTask, setSelectedTask] = useState<AgentTask | null>(null)
  const [taskCategory, setTaskCategory] = useState('all')
  const [showTaskLibrary, setShowTaskLibrary] = useState(false)
  const [loadingTasks, setLoadingTasks] = useState(false)

  // Custom prompt
  const [useCustomPrompt, setUseCustomPrompt] = useState(false)
  const [customPrompt, setCustomPrompt] = useState('')

  // Auth options
  const [showAuthOptions, setShowAuthOptions] = useState(false)
  const [authType, setAuthType] = useState<AuthTypeOption>('none')
  const [authValue, setAuthValue] = useState('')

  // Advanced options
  const [maxDepth, setMaxDepth] = useState(5)

  // UI state
  const [isLoading, setIsLoading] = useState(false)

  // Toast state
  const [toasts, setToasts] = useState<Toast[]>([])

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

  // Load tasks on mount
  useEffect(() => {
    loadTasks()
  }, [])

  const loadTasks = async (category?: string) => {
    setLoadingTasks(true)
    try {
      const taskList = await agentApi.tasks.list(category === 'all' ? undefined : category)
      setTasks(taskList)
    } catch (error) {
      console.error('Failed to load tasks:', error)
    } finally {
      setLoadingTasks(false)
    }
  }

  const handleCategoryChange = useCallback((category: string) => {
    setTaskCategory(category)
    loadTasks(category)
  }, [])

  const handleFileUpload = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    try {
      const result = await targetsApi.upload(file)
      const validUrls = result.filter((r: { valid: boolean; normalized_url: string }) => r.valid).map((r: { valid: boolean; normalized_url: string }) => r.normalized_url)
      setUploadedUrls(validUrls)
      setUrlError('')
    } catch (error) {
      setUrlError('Failed to parse file')
    }
  }, [])

  const getTargetUrl = useCallback((): string => {
    switch (targetMode) {
      case 'single':
        return singleUrl.trim()
      case 'multiple':
        return multipleUrls.split(/[,\n]/)[0]?.trim() || ''
      case 'file':
        return uploadedUrls[0] || ''
      default:
        return ''
    }
  }, [targetMode, singleUrl, multipleUrls, uploadedUrls])

  const handleStartAgent = useCallback(async () => {
    const target = getTargetUrl()
    if (!target) {
      setUrlError('Please enter a target URL')
      addToast('Please enter a target URL before deploying', 'warning')
      return
    }

    setIsLoading(true)
    try {
      // Validate URL
      const validation = await targetsApi.validateBulk([target])
      if (!validation[0]?.valid) {
        setUrlError('Invalid URL format')
        addToast('Invalid URL format - please check and try again', 'error')
        setIsLoading(false)
        return
      }

      // Build request
      const request: AgentRequest = {
        target: validation[0].normalized_url,
        mode: operationMode,
        max_depth: maxDepth
      }

      // Add task or custom prompt
      if (selectedTask && !useCustomPrompt) {
        request.task_id = selectedTask.id
      } else if (useCustomPrompt && customPrompt.trim()) {
        request.prompt = customPrompt
      }

      // Add auth if specified
      if (authType !== 'none' && authValue.trim()) {
        request.auth_type = authType as AgentRequest['auth_type']
        request.auth_value = authValue
      }

      // Start agent
      const response = await agentApi.run(request)

      addToast('Agent deployed successfully - redirecting...', 'success')

      // Navigate to agent status page
      setTimeout(() => {
        navigate(`/agent/${response.agent_id}`)
      }, 300)
    } catch (error) {
      console.error('Failed to start agent:', error)
      setUrlError('Failed to start agent. Please try again.')
      addToast('Failed to start agent - please try again', 'error')
    } finally {
      setIsLoading(false)
    }
  }, [getTargetUrl, operationMode, maxDepth, selectedTask, useCustomPrompt, customPrompt, authType, authValue, addToast, navigate])

  const handleSelectTask = useCallback((task: AgentTask) => {
    setSelectedTask(task)
    addToast(`Task selected: ${task.name}`, 'info')
  }, [addToast])

  const handleClearTask = useCallback(() => {
    setSelectedTask(null)
  }, [])

  const handleSetAuthType = useCallback((id: AuthTypeOption) => {
    setAuthType(id)
  }, [])

  const handleToggleTaskLibrary = useCallback(() => {
    setShowTaskLibrary(prev => !prev)
  }, [])

  const handleToggleAuthOptions = useCallback(() => {
    setShowAuthOptions(prev => !prev)
  }, [])

  const handleToggleCustomPrompt = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setUseCustomPrompt(e.target.checked)
  }, [])

  const handleSingleUrlChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSingleUrl(e.target.value)
    setUrlError('')
  }, [])

  const handleMultipleUrlsChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setMultipleUrls(e.target.value)
    setUrlError('')
  }, [])

  const handleCustomPromptChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setCustomPrompt(e.target.value)
  }, [])

  const handleMaxDepthChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setMaxDepth(parseInt(e.target.value))
  }, [])

  const handleAuthValueChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setAuthValue(e.target.value)
  }, [])

  const handleNavigateHome = useCallback(() => {
    navigate('/')
  }, [navigate])

  // Memoized filtered task list
  const filteredTasks = useMemo(() => {
    if (showTaskLibrary) return tasks
    return tasks.slice(0, 4)
  }, [tasks, showTaskLibrary])

  const currentModeInfo = OPERATION_MODES.find(m => m.id === operationMode)!

  return (
    <div
      className="max-w-5xl mx-auto space-y-6"
      style={{ animation: 'fadeSlideIn 0.4s ease-out' }}
    >
      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Header */}
      <div
        className="flex items-center justify-between"
        style={{ animation: 'fadeSlideIn 0.3s ease-out 0s both' }}
      >
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Bot className="w-8 h-8 text-primary-500" />
            AI Security Agent
          </h1>
          <p className="text-dark-400 mt-1">Autonomous penetration testing powered by AI</p>
        </div>
      </div>

      {/* Operation Mode Selector */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.05s both' }}>
        <Card title="Operation Mode" subtitle="Select how the AI agent should operate">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {OPERATION_MODES.map((mode, idx) => (
              <div
                key={mode.id}
                onClick={() => setOperationMode(mode.id)}
                className={`p-4 rounded-xl border-2 cursor-pointer transition-all ${
                  operationMode === mode.id
                    ? `border-${mode.color}-500 bg-${mode.color}-500/10`
                    : 'border-dark-700 hover:border-dark-500 bg-dark-900/50'
                }`}
                style={{ animation: `fadeSlideIn 0.3s ease-out ${idx * 0.05}s both` }}
              >
                <div className={`flex items-center gap-2 mb-2 ${
                  operationMode === mode.id ? `text-${mode.color}-400` : 'text-dark-300'
                }`}>
                  {mode.icon}
                  <span className="font-semibold">{mode.name}</span>
                </div>
                <p className="text-sm text-dark-400">{mode.description}</p>
                {mode.warning && operationMode === mode.id && (
                  <div className="mt-2 flex items-start gap-2 text-yellow-400 text-xs">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                    <span>{mode.warning}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Target Input */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.1s both' }}>
        <Card title="Target" subtitle="Enter the URL to test">
          <div className="space-y-4">
            {/* Mode Selector */}
            <div className="flex gap-2 flex-wrap">
              <Button
                variant={targetMode === 'single' ? 'primary' : 'secondary'}
                onClick={() => setTargetMode('single')}
              >
                <LinkIcon className="w-4 h-4 mr-2" />
                Single URL
              </Button>
              <Button
                variant={targetMode === 'multiple' ? 'primary' : 'secondary'}
                onClick={() => setTargetMode('multiple')}
              >
                <FileText className="w-4 h-4 mr-2" />
                Multiple URLs
              </Button>
              <Button
                variant={targetMode === 'file' ? 'primary' : 'secondary'}
                onClick={() => setTargetMode('file')}
              >
                <Upload className="w-4 h-4 mr-2" />
                Upload File
              </Button>
            </div>

            {/* Input Fields */}
            {targetMode === 'single' && (
              <Input
                placeholder="https://example.com"
                value={singleUrl}
                onChange={handleSingleUrlChange}
                error={urlError}
              />
            )}

            {targetMode === 'multiple' && (
              <div>
                <Textarea
                  placeholder="Enter URLs separated by commas or new lines:&#10;https://example1.com&#10;https://example2.com"
                  rows={5}
                  value={multipleUrls}
                  onChange={handleMultipleUrlsChange}
                />
                <p className="text-xs text-dark-500 mt-1">Note: Agent will test the first URL. Multiple URL support coming soon.</p>
                {urlError && <p className="mt-1 text-sm text-red-400">{urlError}</p>}
              </div>
            )}

            {targetMode === 'file' && (
              <div>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  accept=".txt,.csv,.lst"
                  className="hidden"
                />
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-dark-700 rounded-lg p-8 text-center cursor-pointer hover:border-primary-500 transition-colors"
                >
                  <Upload className="w-10 h-10 mx-auto text-dark-400 mb-3" />
                  <p className="text-dark-300">Click to upload a file with URLs</p>
                  <p className="text-sm text-dark-500 mt-1">Supports .txt, .csv, .lst files</p>
                </div>
                {uploadedUrls.length > 0 && (
                  <p className="mt-2 text-sm text-green-400">
                    {uploadedUrls.length} valid URLs loaded - using first URL
                  </p>
                )}
                {urlError && <p className="mt-2 text-sm text-red-400">{urlError}</p>}
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Task Library */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.15s both' }}>
        <Card
          title={
            <div className="flex items-center justify-between w-full">
              <div className="flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-primary-500" />
                <span>Task Library</span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleToggleTaskLibrary}
              >
                <ChevronDown className={`w-4 h-4 transition-transform ${showTaskLibrary ? 'rotate-180' : ''}`} />
              </Button>
            </div>
          }
          subtitle="Select a preset task or create a custom prompt"
        >
          {/* Custom Prompt Toggle */}
          <div className="flex items-center justify-between mb-4 pb-4 border-b border-dark-700">
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="customPrompt"
                checked={useCustomPrompt}
                onChange={handleToggleCustomPrompt}
                className="w-4 h-4 rounded border-dark-600 bg-dark-800 text-primary-500 focus:ring-primary-500"
              />
              <label htmlFor="customPrompt" className="text-white">Use custom prompt instead of task</label>
            </div>
          </div>

          {useCustomPrompt ? (
            <Textarea
              placeholder="Enter your custom prompt for the AI agent...&#10;&#10;Example: Test for SQL injection on all form inputs, check for authentication bypass on the login endpoint, and look for IDOR vulnerabilities in user profile APIs."
              rows={6}
              value={customPrompt}
              onChange={handleCustomPromptChange}
            />
          ) : (
            <>
              {showTaskLibrary && (
                <>
                  {/* Category Filter */}
                  <div className="flex gap-2 mb-4 flex-wrap">
                    {TASK_CATEGORIES.map((cat) => (
                      <Button
                        key={cat.id}
                        variant={taskCategory === cat.id ? 'primary' : 'secondary'}
                        size="sm"
                        onClick={() => handleCategoryChange(cat.id)}
                      >
                        {cat.name}
                      </Button>
                    ))}
                  </div>
                </>
              )}

              {/* Tasks Grid */}
              <div className={`grid grid-cols-1 sm:grid-cols-2 gap-3 ${showTaskLibrary ? 'max-h-80 overflow-auto' : ''}`}>
                {loadingTasks ? (
                  <p className="text-dark-400 col-span-2 text-center py-4">Loading tasks...</p>
                ) : (
                  filteredTasks.map((task, idx) => (
                    <div
                      key={task.id}
                      onClick={() => handleSelectTask(task)}
                      className={`p-4 rounded-lg border cursor-pointer transition-all ${
                        selectedTask?.id === task.id
                          ? 'border-primary-500 bg-primary-500/10'
                          : 'border-dark-700 hover:border-dark-500 bg-dark-900/50'
                      }`}
                      style={{ animation: `fadeSlideIn 0.3s ease-out ${idx * 0.05}s both` }}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-white">{task.name}</span>
                        {task.is_preset && (
                          <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded">Preset</span>
                        )}
                      </div>
                      <p className="text-sm text-dark-400 line-clamp-2">{task.description}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <span className="text-xs text-dark-500">{task.category}</span>
                        {task.estimated_tokens > 0 && (
                          <span className="text-xs text-dark-500">~{task.estimated_tokens} tokens</span>
                        )}
                      </div>
                      {task.tags?.length > 0 && (
                        <div className="flex gap-1 mt-2 flex-wrap">
                          {task.tags.slice(0, 3).map((tag) => (
                            <span key={tag} className="text-xs bg-dark-700 text-dark-300 px-2 py-0.5 rounded">
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>

              {!showTaskLibrary && tasks.length > 4 && (
                <Button
                  variant="ghost"
                  className="w-full mt-3"
                  onClick={() => setShowTaskLibrary(true)}
                >
                  Show all {tasks.length} tasks
                </Button>
              )}
            </>
          )}

          {/* Selected Task Preview */}
          {selectedTask && !useCustomPrompt && (
            <div className="mt-4 p-4 bg-dark-800 rounded-lg border border-dark-700">
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-white">Selected: {selectedTask.name}</span>
                <Button variant="ghost" size="sm" onClick={handleClearTask}>
                  Clear
                </Button>
              </div>
              <p className="text-sm text-dark-400 whitespace-pre-wrap line-clamp-4">
                {selectedTask.prompt}
              </p>
            </div>
          )}
        </Card>
      </div>

      {/* Authentication Options */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.2s both' }}>
        <Card
          title={
            <div className="flex items-center gap-2">
              <Key className="w-5 h-5 text-primary-500" />
              <span>Authentication</span>
              <span className="text-xs text-dark-500">(Optional)</span>
            </div>
          }
        >
          <div className="space-y-4">
            <div className="flex gap-2 flex-wrap">
              {AUTH_TYPE_OPTIONS.map((type) => (
                <Button
                  key={type.id}
                  variant={authType === type.id ? 'primary' : 'secondary'}
                  size="sm"
                  onClick={() => handleSetAuthType(type.id)}
                >
                  {type.label}
                </Button>
              ))}
            </div>

            {authType !== 'none' && (
              <Input
                placeholder={
                  authType === 'cookie' ? 'session=abc123; token=xyz789' :
                  authType === 'bearer' ? 'eyJhbGciOiJIUzI1NiIs...' :
                  authType === 'basic' ? 'username:password' :
                  'X-API-Key: your-api-key'
                }
                value={authValue}
                onChange={handleAuthValueChange}
                label={
                  authType === 'cookie' ? 'Cookie String' :
                  authType === 'bearer' ? 'Bearer Token' :
                  authType === 'basic' ? 'Username:Password' :
                  'Header:Value'
                }
              />
            )}
          </div>
        </Card>
      </div>

      {/* Advanced Options */}
      <div style={{ animation: 'fadeSlideIn 0.3s ease-out 0.25s both' }}>
        <Card
          title={
            <div className="flex items-center gap-2 cursor-pointer" onClick={handleToggleAuthOptions}>
              <Settings className="w-5 h-5 text-primary-500" />
              <span>Advanced Options</span>
              <ChevronDown className={`w-4 h-4 transition-transform ${showAuthOptions ? 'rotate-180' : ''}`} />
            </div>
          }
        >
          {showAuthOptions && (
            <div className="space-y-4">
              <div>
                <label className="text-sm text-dark-300 mb-1 block">Max Crawl Depth</label>
                <div className="flex items-center gap-4">
                  <input
                    type="range"
                    min="1"
                    max="10"
                    value={maxDepth}
                    onChange={handleMaxDepthChange}
                    className="flex-1"
                  />
                  <span className="text-white font-medium w-8">{maxDepth}</span>
                </div>
              </div>
            </div>
          )}
          {!showAuthOptions && (
            <p className="text-dark-500 text-sm">Click to expand advanced options</p>
          )}
        </Card>
      </div>

      {/* Warning for Prompt Only Mode */}
      {operationMode === 'prompt_only' && (
        <div
          className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3"
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <AlertTriangle className="w-6 h-6 text-yellow-500 flex-shrink-0" />
          <div>
            <p className="font-medium text-yellow-400">High Token Usage Warning</p>
            <p className="text-sm text-yellow-300/80 mt-1">
              In AI Prompt Mode, the agent has full autonomy to decide what tools to use and what tests to run.
              This results in significantly higher API token consumption. Consider using Full Auto mode for most use cases.
            </p>
          </div>
        </div>
      )}

      {/* Start Button */}
      <div
        className="flex justify-end gap-3 sticky bottom-4 bg-dark-950/90 backdrop-blur p-4 -mx-4 rounded-lg"
        style={{ animation: 'fadeSlideIn 0.3s ease-out 0.3s both' }}
      >
        <Button variant="secondary" onClick={handleNavigateHome}>
          Cancel
        </Button>
        <Button onClick={handleStartAgent} isLoading={isLoading} size="lg">
          <Play className="w-5 h-5 mr-2" />
          Deploy Agent ({currentModeInfo.name})
        </Button>
      </div>
    </div>
  )
}
