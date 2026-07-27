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

export interface DashboardData {
  risk_level: string
  risk_score: number
  vulnerabilities: KPICard
  compliance: KPICard
  assets: KPICard
  incidents: KPICard
  risk_categories: RiskCategory[]
  active_threats: ThreatItem[]
}

export interface Vulnerability {
  id: number
  cve_id: string
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
  mttr_minutes: number
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
  id: number
  name: string
  generated_at: string | null
  pages: number | null
  format: string | null
  status: 'ready' | 'generating'
}
