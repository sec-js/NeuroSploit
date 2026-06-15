import { useState, useEffect, useRef } from 'react'
import { Shield, Loader2, CheckCircle2, XCircle, Clock, AlertTriangle } from 'lucide-react'
import { agentApi } from '../services/api'
import type { VulnAgentStatus, VulnAgentDashboard } from '../types'

// Category color mapping for vuln types
const VULN_CATEGORY_COLORS: Record<string, string> = {
  // XSS variants
  xss_reflected: 'border-yellow-500/60',
  xss_stored: 'border-yellow-500/60',
  xss_dom: 'border-yellow-500/60',
  blind_xss: 'border-yellow-500/60',
  mutation_xss: 'border-yellow-500/60',
  // SQL Injection
  sqli_error: 'border-red-500/60',
  sqli_union: 'border-red-500/60',
  sqli_blind: 'border-red-500/60',
  sqli_time: 'border-red-500/60',
  // SSRF
  ssrf: 'border-purple-500/60',
  ssrf_cloud: 'border-purple-500/60',
  // Auth/Access
  auth_bypass: 'border-blue-500/60',
  idor: 'border-blue-500/60',
  bola: 'border-blue-500/60',
  bfla: 'border-blue-500/60',
  privilege_escalation: 'border-blue-500/60',
  // Command/Template
  command_injection: 'border-red-600/60',
  ssti: 'border-red-600/60',
  // File access
  lfi: 'border-orange-500/60',
  rfi: 'border-orange-500/60',
  path_traversal: 'border-orange-500/60',
  xxe: 'border-orange-500/60',
}

function getCategoryColor(vulnType: string): string {
  return VULN_CATEGORY_COLORS[vulnType] || 'border-dark-600'
}

// Shortened display names for grid cells
function getShortName(vulnType: string): string {
  const names: Record<string, string> = {
    sqli_error: 'SQLi Err',
    sqli_union: 'SQLi Union',
    sqli_blind: 'SQLi Blind',
    sqli_time: 'SQLi Time',
    xss_reflected: 'XSS Refl',
    xss_stored: 'XSS Stored',
    xss_dom: 'XSS DOM',
    blind_xss: 'Blind XSS',
    mutation_xss: 'Mut XSS',
    command_injection: 'Cmd Inj',
    expression_language_injection: 'EL Inj',
    nosql_injection: 'NoSQLi',
    ldap_injection: 'LDAP Inj',
    xpath_injection: 'XPath Inj',
    orm_injection: 'ORM Inj',
    graphql_injection: 'GQL Inj',
    path_traversal: 'Path Trav',
    arbitrary_file_read: 'File Read',
    ssrf_cloud: 'SSRF Cloud',
    open_redirect: 'Open Redir',
    crlf_injection: 'CRLF',
    header_injection: 'Header Inj',
    host_header_injection: 'Host Hdr',
    http_smuggling: 'Smuggling',
    parameter_pollution: 'Param Poll',
    log_injection: 'Log Inj',
    html_injection: 'HTML Inj',
    csv_injection: 'CSV Inj',
    email_injection: 'Email Inj',
    prototype_pollution: 'Proto Poll',
    soap_injection: 'SOAP Inj',
    type_juggling: 'Type Jugg',
    cache_poisoning: 'Cache Poi',
    security_headers: 'Sec Hdrs',
    http_methods: 'HTTP Meth',
    ssl_issues: 'SSL/TLS',
    cors_misconfig: 'CORS',
    directory_listing: 'Dir List',
    debug_mode: 'Debug',
    exposed_admin_panel: 'Admin Exp',
    exposed_api_docs: 'API Docs',
    insecure_cookie_flags: 'Cookies',
    sensitive_data_exposure: 'Data Exp',
    information_disclosure: 'Info Disc',
    api_key_exposure: 'API Keys',
    version_disclosure: 'Version',
    cleartext_transmission: 'Cleartext',
    weak_encryption: 'Weak Enc',
    weak_hashing: 'Weak Hash',
    source_code_disclosure: 'Src Disc',
    backup_file_exposure: 'Backup Exp',
    graphql_introspection: 'GQL Intro',
    auth_bypass: 'Auth Byp',
    jwt_manipulation: 'JWT Manip',
    session_fixation: 'Sess Fix',
    weak_password: 'Weak Pass',
    default_credentials: 'Default Creds',
    brute_force: 'Brute Force',
    two_factor_bypass: '2FA Byp',
    oauth_misconfiguration: 'OAuth Misc',
    privilege_escalation: 'Priv Esc',
    mass_assignment: 'Mass Assign',
    forced_browsing: 'Forced Brw',
    race_condition: 'Race Cond',
    business_logic: 'Biz Logic',
    rate_limit_bypass: 'Rate Limit',
    timing_attack: 'Timing',
    insecure_deserialization: 'Deseiral',
    file_upload: 'File Upload',
    arbitrary_file_delete: 'File Del',
    zip_slip: 'Zip Slip',
    dom_clobbering: 'DOM Clob',
    postmessage_vulnerability: 'PostMsg',
    websocket_hijacking: 'WS Hijack',
    css_injection: 'CSS Inj',
    tabnabbing: 'Tabnab',
    subdomain_takeover: 'Subdomain',
    cloud_metadata_exposure: 'Cloud Meta',
    s3_bucket_misconfiguration: 'S3 Bucket',
    serverless_misconfiguration: 'Serverless',
    container_escape: 'Container',
    vulnerable_dependency: 'Vuln Dep',
    outdated_component: 'Outdated',
    insecure_cdn: 'CDN',
    weak_random: 'Weak Rand',
    graphql_dos: 'GQL DoS',
    rest_api_versioning: 'API Ver',
    api_rate_limiting: 'API Rate',
    excessive_data_exposure: 'Data Overexp',
    improper_error_handling: 'Error Hndl',
  }
  return names[vulnType] || vulnType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()).substring(0, 12)
}

const STATUS_ICONS: Record<string, React.ReactNode> = {
  idle: <Clock className="w-3 h-3 text-dark-500" />,
  running: <Loader2 className="w-3 h-3 text-blue-400 animate-spin" />,
  completed: <CheckCircle2 className="w-3 h-3 text-green-400" />,
  failed: <XCircle className="w-3 h-3 text-red-400" />,
  cancelled: <AlertTriangle className="w-3 h-3 text-yellow-500" />,
}

interface Props {
  agentId: string
  isRunning: boolean
}

export default function VulnAgentGrid({ agentId, isRunning }: Props) {
  const [data, setData] = useState<VulnAgentDashboard | null>(null)
  const [hoveredAgent, setHoveredAgent] = useState<string | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const result = await agentApi.getVulnAgents(agentId)
        setData(result)
      } catch {
        // Agent may not exist yet
      }
    }

    fetchData()

    if (isRunning) {
      pollRef.current = setInterval(fetchData, 2000)
    }

    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [agentId, isRunning])

  if (!data || !data.enabled) {
    return (
      <div className="bg-dark-800 border border-dark-700 rounded-2xl p-6 text-center">
        <Shield className="w-8 h-8 text-dark-500 mx-auto mb-2" />
        <p className="text-dark-400 text-sm">
          Per-vulnerability agent orchestration is not enabled for this scan.
        </p>
        <p className="text-dark-500 text-xs mt-1">
          Set ENABLE_VULN_AGENTS=true in .env to enable
        </p>
      </div>
    )
  }

  const { agents, stats } = data

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-primary-400" />
            <span className="text-white font-semibold">Vulnerability Agents</span>
            <span className="text-dark-400 text-sm">({stats.total} types)</span>
          </div>
          <div className="flex items-center gap-4 text-xs">
            {stats.completed > 0 && (
              <span className="text-green-400">
                <CheckCircle2 className="w-3 h-3 inline mr-1" />{stats.completed} done
              </span>
            )}
            {stats.running > 0 && (
              <span className="text-blue-400">
                <Loader2 className="w-3 h-3 inline mr-1 animate-spin" />{stats.running} running
              </span>
            )}
            {stats.failed > 0 && (
              <span className="text-red-400">
                <XCircle className="w-3 h-3 inline mr-1" />{stats.failed} failed
              </span>
            )}
            {(stats.total - stats.completed - stats.running - stats.failed - (stats.cancelled || 0)) > 0 && (
              <span className="text-dark-400">
                <Clock className="w-3 h-3 inline mr-1" />
                {stats.total - stats.completed - stats.running - stats.failed - (stats.cancelled || 0)} pending
              </span>
            )}
            {stats.findings_total > 0 && (
              <span className="text-red-400 font-bold">
                {stats.findings_total} findings
              </span>
            )}
            {stats.elapsed > 0 && (
              <span className="text-dark-500">
                {stats.elapsed < 60 ? `${Math.round(stats.elapsed)}s` : `${Math.round(stats.elapsed / 60)}m`}
              </span>
            )}
          </div>
        </div>

        {/* Progress bar */}
        {stats.total > 0 && (
          <div className="mt-3 h-1.5 bg-dark-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-primary-500 to-green-500 rounded-full transition-all duration-500"
              style={{ width: `${Math.round((stats.completed / stats.total) * 100)}%` }}
            />
          </div>
        )}
      </div>

      {/* Agent grid */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
        <div className="grid grid-cols-5 sm:grid-cols-8 md:grid-cols-10 lg:grid-cols-12 xl:grid-cols-14 gap-1.5">
          {agents.map((agent: VulnAgentStatus) => (
            <div
              key={agent.vuln_type}
              className={`relative border rounded-lg p-1.5 cursor-pointer transition-all hover:scale-105 ${
                getCategoryColor(agent.vuln_type)
              } ${
                agent.status === 'running' ? 'bg-blue-500/10' :
                agent.status === 'completed' ? 'bg-dark-900' :
                agent.status === 'failed' ? 'bg-red-500/5' :
                'bg-dark-900/50'
              } ${
                agent.findings_count > 0 ? 'ring-1 ring-red-500/50' : ''
              }`}
              onMouseEnter={() => setHoveredAgent(agent.vuln_type)}
              onMouseLeave={() => setHoveredAgent(null)}
            >
              {/* Status icon */}
              <div className="flex items-center justify-between mb-1">
                {STATUS_ICONS[agent.status] || STATUS_ICONS.idle}
                {agent.findings_count > 0 && (
                  <span className="bg-red-500 text-white text-[9px] font-bold rounded-full w-3.5 h-3.5 flex items-center justify-center">
                    {agent.findings_count}
                  </span>
                )}
              </div>

              {/* Label */}
              <div className="text-[9px] text-dark-300 leading-tight truncate">
                {getShortName(agent.vuln_type)}
              </div>

              {/* Micro progress bar */}
              {agent.status === 'running' && (
                <div className="mt-1 h-0.5 bg-dark-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-400 rounded-full transition-all"
                    style={{ width: `${agent.progress}%` }}
                  />
                </div>
              )}

              {/* Tooltip */}
              {hoveredAgent === agent.vuln_type && (
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-50 bg-dark-900 border border-dark-600 rounded-lg p-2 shadow-xl min-w-[180px] pointer-events-none">
                  <div className="text-xs text-white font-medium mb-1">
                    {agent.vuln_type.replace(/_/g, ' ')}
                  </div>
                  <div className="text-[10px] text-dark-400 space-y-0.5">
                    <div>Status: <span className={
                      agent.status === 'completed' ? 'text-green-400' :
                      agent.status === 'running' ? 'text-blue-400' :
                      agent.status === 'failed' ? 'text-red-400' :
                      'text-dark-300'
                    }>{agent.status}</span></div>
                    <div>Targets: {agent.targets_tested}/{agent.targets_total}</div>
                    {agent.findings_count > 0 && (
                      <div className="text-red-400 font-bold">{agent.findings_count} finding(s)</div>
                    )}
                    {agent.duration != null && agent.duration > 0 && (
                      <div>Duration: {agent.duration < 60 ? `${Math.round(agent.duration)}s` : `${(agent.duration / 60).toFixed(1)}m`}</div>
                    )}
                    {agent.error && (
                      <div className="text-red-400 truncate">Error: {agent.error}</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
