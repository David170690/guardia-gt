export interface User {
  id: number
  email: string
  full_name: string
  role: string
  is_active: boolean
  mfa_enabled: boolean
  created_at: string
}

export interface KPICard {
  label: string
  value: string
  change?: string
  trend?: 'up' | 'down' | 'stable'
}

export interface ThreatItem {
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
  description: string
}

export interface RiskCategory {
  category: string
  score: number
  color: string
}

export interface RecentIncident {
  id: number
  title: string
  severity: string
  status: string
  affected_asset: string | null
  detected_at: string | null
}

export interface DashboardData {
  organization: string | null
  risk_level: string
  risk_score: number
  vulnerabilities: KPICard
  compliance: KPICard
  assets: KPICard
  incidents: KPICard
  risk_categories: RiskCategory[]
  active_threats: ThreatItem[]
  recent_incidents: RecentIncident[]
}

export type FindingType = 'cve' | 'exposure' | 'ssl' | 'reachability'

export interface Vulnerability {
  id: number
  cve_id: string
  finding_type: FindingType | null
  title: string
  description: string
  cvss_score: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'open' | 'in_progress' | 'remediated' | 'accepted' | 'false_positive'
  asset_id: number | null
  affected_component: string
  solution: string
  discovered_at: string
  created_at: string
}

export interface VulnerabilityStats {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  remediated: number
}

export interface Asset {
  id: number
  name: string
  organization: string | null
  asset_type: string
  ip_address: string
  operating_system: string
  description: string
  criticality: string
  status: 'online' | 'offline' | 'maintenance' | 'decommissioned'
  cpu_usage: number
  ram_usage: number
  last_scan: string | null
  created_at: string
}

export interface AssetStats {
  total: number
  online: number
  offline: number
  servers: number
  endpoints: number
  web_apps: number
}

export interface Incident {
  id: number
  title: string
  organization: string | null
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'
  source_ip: string
  affected_asset: string
  response_action: string
  assigned_to: number | null
  detected_at: string
  created_at: string
}

export interface IncidentStats {
  total: number
  active: number
  critical: number
  high: number
  resolved_today: number
  /** `null` mientras no haya incidentes resueltos con marca de tiempo. */
  mttr_minutes: number | null
}

export interface ComplianceControl {
  id: number
  standard: string
  control_id: string
  control_name: string
  description: string
  status: 'compliant' | 'partial' | 'non_compliant' | 'not_applicable'
  score: number
  findings: string | null
  last_assessed: string | null
}

export interface ComplianceDashboard {
  overall_score: number
  standards: ComplianceStandardStats[]
  critical_findings: number
}

export interface ComplianceStandardStats {
  standard: string
  total_controls: number
  compliant: number
  partial: number
  non_compliant: number
  score: number
}

export interface Report {
  id: string
  name: string
  description: string
  records: number
  available: boolean
  format: string
}

export interface ReportsResponse {
  reports: Report[]
  summary: {
    open_vulnerabilities: number
    total_assets: number
    total_incidents: number
  }
  note: string
}

export interface TrendsResponse {
  months: string[]
  vulnerabilities: number[]
  remediated: number[]
  risk_scores: number[]
  note: string
}

export interface SystemConfig {
  app_version: string
  access_token_expire_minutes: number
  refresh_token_expire_days: number
  cors_origins: string[]
  scan_max_assets: number
  scan_port_timeout_seconds: number
  scan_host_budget_seconds: number
  scan_allow_private_targets: boolean
  seed_endpoint_enabled: boolean
  editable: boolean
  note: string
}

export interface DiagnosticFinding {
  id: number
  cve_id: string
  title: string
  cvss_score: number
  severity: string
  status: string
  finding_type: FindingType | null
  affected_component: string | null
  solution: string | null
  ssl_info?: {
    cn?: string
    issuer?: string
    not_before?: string
    not_after?: string
    days_left?: number
    expired?: boolean
  } | null
}

export interface DiagnosticResult {
  organization: string
  assets_created: number
  assets_scanned: number
  assets_unreachable: number
  vulnerabilities_found: number
  incidents_created: number
  compliance_score: number
  compliance_assessed: boolean
  risk_level: string
  summary: string
  notes: string[]
  assets_detail: Array<{
    id: number
    name: string
    asset_type: string
    ip_address: string | null
    operating_system: string | null
    criticality: string
    status: string
  }>
  vulns_detail: DiagnosticFinding[]
  incidents_detail: Array<{
    id: number
    title: string
    severity: string
    status: string
    affected_asset: string | null
    response_action: string | null
  }>
  compliance_detail: Array<{
    standard: string
    control_id: string
    control_name: string
    status: string
    score: number
    findings: string | null
  }>
}
