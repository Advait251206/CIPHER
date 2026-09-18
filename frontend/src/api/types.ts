/**
 * CIPHER Security API Types & Interfaces
 * Matches backend schemas from app/schemas, app/network/schemas, app/correlation/models,
 * app/rules/models, and app/threat_intel/models.
 */

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'BENIGN';
export type PreventionMode = 'detect_only' | 'enforce';
export type IncidentStatus = 'OPEN' | 'RESOLVED';
export type IOCType = 'IP' | 'DOMAIN' | 'URL' | 'HASH';
export type RuleType = 'HEURISTIC' | 'SIGNATURE';

// ----------------------
// Events
// ----------------------

export interface SecurityEventItem {
  event_id: string;
  timestamp: string;
  classification: string;
  risk_score: number;
  confidence: number;
  severity: Severity;
  ml_score: number;
  heuristic_score: number;
  domain: string;
  reasons: string[];
  recommendation: string;
  model_version: string;
  source: string;
  event_type?: string;
  attack_type?: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  detection_method?: string;
  action?: string;
  status?: string;
  metadata?: Record<string, any>;
}

export interface EventsListResponse {
  total_returned: number;
  events: SecurityEventItem[];
}

export interface SystemStatsResponse {
  total_scans: number;
  phishing_detected: number;
  suspicious_detected: number;
  legitimate_verified: number;
  average_risk_score: number;
}

// ----------------------
// Incidents & Correlation
// ----------------------

export interface IncidentItem {
  incident_id: string;
  created_at: string;
  updated_at: string;
  status: IncidentStatus;
  source_ip?: string;
  destination_ip?: string;
  event_count: number;
  attack_categories: string[];
  first_seen: string;
  last_seen: string;
  correlation_score: number;
  severity: Severity;
  confidence: number;
  escalation_detected: boolean;
  summary: string;
  recommended_action?: string;
  applied_action?: string;
  event_ids: string[];
  metadata: Record<string, any>;
}

export interface IncidentsListResponse {
  total_returned: number;
  incidents: IncidentItem[];
}

export interface IncidentDetailResponse {
  incident: IncidentItem;
  events: Record<string, any>[];
}

export interface CorrelationStatsResponse {
  total_incidents: number;
  open_incidents: number;
  resolved_incidents: number;
  escalations_detected: number;
  average_correlation_score: number;
  incidents_by_severity: Record<string, number>;
  top_attacking_sources: Array<{
    source_ip: string;
    count: number;
    max_severity: string;
  }>;
}

export interface IncidentResolveResponse {
  incident_id: string;
  status: string;
  message: string;
}

// ----------------------
// Network IDS & Sensor
// ----------------------

export interface NetworkHealthResponse {
  status: string;
  subsystem: string;
  model_loaded: boolean;
  model_version: string;
  feature_count: number;
  prevention_mode: PreventionMode;
  database_connected: boolean;
  timestamp: string;
}

export interface NetworkStatsResponse {
  total_flows: number;
  attack_flows: number;
  benign_flows: number;
  attack_percentage: number;
  attacks_by_category: Record<string, number>;
  top_attacking_ips: Array<{ ip: string; count: number }>;
  top_targeted_ports: Array<{ port: number; count: number }>;
}

export interface NetworkModelInfoResponse {
  model_name: string;
  model_architecture: string;
  dataset: string;
  feature_count: number;
  classes: string[];
  training_samples: number;
  validation_samples: number;
  test_samples: number;
  binary_metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1?: number;
    roc_auc?: number;
  };
  multiclass_metrics: {
    macro_f1?: number;
    weighted_f1?: number;
    per_class?: Record<string, any>;
  };
  top_features: Record<string, number>;
}

export interface NetworkRuleItem {
  rule_id: string;
  name: string;
  target_category: string;
  description: string;
  weight: number;
}

export interface NetworkRulesResponse {
  total_rules: number;
  rules: NetworkRuleItem[];
}

export interface BlocklistEntry {
  ip: string;
  reason: string;
  blocked_at: string;
  expires_at?: string;
  ttl_remaining_seconds?: number;
  status: 'ACTIVE' | 'EXPIRED';
}

export interface NetworkInterfaceItem {
  name: string;
  description: string;
  address?: string;
  ip_address?: string;
  mac_address?: string;
}

export interface NetworkInterfacesResponse {
  interfaces: NetworkInterfaceItem[];
}

export interface SensorStatusResponse {
  running?: boolean;
  interface?: string;
  bpf_filter?: string;
  started_at?: string;
  packets_captured: number;
  packets_dropped?: number;
  active_flows: number;
  completed_flows?: number;
  finalized_flows?: number;
  analyzed_flows?: number;
  detected_attacks?: number;
  errors?: number;
  prevention_mode?: string;
  flow_idle_timeout?: number;
  flow_active_timeout?: number;
  npcap_available?: boolean;
  scapy_available?: boolean;
}

export interface SensorStartRequest {
  interface: string;
  bpf_filter?: string;
  flow_idle_timeout?: number;
  flow_active_timeout?: number;
}

export interface NetworkFlowAnalyzeRequest {
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  flow_duration?: number;
  features?: Record<string, number>;
}

export interface NetworkDetectionResponse {
  flow_id: string;
  timestamp: string;
  is_attack: boolean;
  predicted_category: string;
  ml_confidence: number;
  ml_attack_prob: number;
  risk_score: number;
  severity: Severity;
  heuristic_score: number;
  heuristic_reasons: string[];
  rules_triggered: string[];
  prevention_action: string;
  recommendation: string;
  model_version: string;
}

// ----------------------
// Phishing
// ----------------------

export interface PhishingAnalyzeRequest {
  url: string;
  page_features?: Record<string, any>;
  source?: string;
}

export interface PhishingAnalyzeResponse {
  classification: 'LEGITIMATE' | 'SUSPICIOUS' | 'LIKELY_PHISHING';
  risk_score: number;
  severity: Severity;
  confidence: number;
  ml_score: number;
  heuristic_score: number;
  reasons: string[];
  recommendation: string;
  model_version: string;
  event_id?: string;
}

// ----------------------
// Detection Rules
// ----------------------

export interface RuleItem {
  rule_id: string;
  name: string;
  rule_type: RuleType;
  category: string;
  severity: Severity;
  confidence: number;
  scope: string;
  enabled: boolean;
  description: string;
}

export interface RulesListResponse {
  total_rules: number;
  enabled_count: number;
  rules: RuleItem[];
}

export interface RuleDetailResponse {
  rule: RuleItem;
  thresholds: Record<string, any>;
}

export interface RuleToggleResponse {
  rule_id: string;
  enabled: boolean;
  message: string;
}

export interface RuleEvaluateResponse {
  total_evaluated: number;
  total_matched: number;
  matches: Array<{
    rule_id: string;
    rule_name: string;
    rule_type: string;
    category: string;
    severity: string;
    confidence: number;
    evidence: string;
  }>;
}

// ----------------------
// Threat Intelligence / IOCs
// ----------------------

export interface IOCItem {
  ioc_id: string;
  ioc_type: IOCType;
  indicator: string;
  normalized_indicator: string;
  severity: Severity;
  confidence: number;
  category?: string;
  description?: string;
  source: string;
  first_seen: string;
  last_seen: string;
  expires_at?: string;
  enabled: boolean;
  tags: string[];
  match_count: number;
}

export interface IOCListResponse {
  total_returned: number;
  total_matching: number;
  iocs: IOCItem[];
}

export interface IOCDetailResponse {
  ioc: IOCItem;
}

export interface IOCCreateRequest {
  ioc_type: IOCType;
  indicator: string;
  severity?: Severity;
  confidence?: number;
  category?: string;
  description?: string;
  expires_at?: string;
  tags?: string[];
}

export interface IOCToggleResponse {
  ioc_id: string;
  enabled: boolean;
  message: string;
}

export interface IOCCheckRequest {
  indicator: string;
  ioc_type?: string;
}

export interface IOCCheckResponse {
  matched: boolean;
  matches: Array<{
    ioc_id: string;
    ioc_type: string;
    indicator: string;
    severity: string;
    confidence: number;
    category?: string;
    description?: string;
    source: string;
    explanation?: string;
  }>;
}

export interface IOCImportRequest {
  iocs: IOCCreateRequest[];
}

export interface IOCImportResponse {
  total_submitted: number;
  imported_count: number;
  rejected_count: number;
  errors: Array<{
    index?: number;
    row?: number;
    indicator?: string;
    error: string;
  }>;
}

// ----------------------
// Health & System
// ----------------------

export interface HealthResponse {
  status: string;
  version: string;
  local_only: boolean;
  model_loaded: boolean;
  database_connected: boolean;
  timestamp: string;
}

export interface SystemStatusResponse {
  system_name: string;
  environment: string;
  local_only: boolean;
  model_version: string;
  model_loaded: boolean;
  feature_count: number;
  feature_names: string[];
  database_path: string;
  uptime_seconds: number;
}

// ----------------------
// Email Phishing & Protection
// ----------------------

export interface EmailUrlAnalysisResult {
  url: string;
  classification: string;
  risk_score: number;
  severity: Severity;
  confidence: number;
  reasons: string[];
}

export interface EmailAnalyzeRequest {
  sender?: string;
  recipient?: string;
  subject?: string;
  body?: string;
  urls?: string[];
}

export interface EmailAnalyzeResponse {
  classification: string;
  risk_score: number;
  severity: Severity;
  confidence: number;
  evidence: string[];
  recommendation: string;
  urls_analyzed: EmailUrlAnalysisResult[];
  features: Record<string, number>;
  event_id?: string;
  model_version: string;
  timestamp: string;
}

export interface EmailModelInfoResponse {
  model_name: string;
  model_version: string;
  feature_count: number;
  feature_names: string[];
  test_metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1_score?: number;
    roc_auc?: number;
    pr_auc?: number;
    confusion_matrix?: {
      tn: number;
      fp: number;
      fn: number;
      tp: number;
    };
    inference_speed_samples_per_sec?: number;
  };
  training_timestamp: string;
}

export interface EmailHealthResponse {
  status: string;
  model_loaded: boolean;
  feature_count: number;
  version: string;
}

export interface ExtensionStatusResponse {
  available: boolean;
  path: string;
  manifest_name: string;
  version: string;
  browser_detected: boolean;
}

export interface ExtensionLaunchResponse {
  success: boolean;
  message: string;
  extension_path: string;
}

