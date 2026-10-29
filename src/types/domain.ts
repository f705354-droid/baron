/**
 * BARON NEXUS — Enterprise AI Cybersecurity Operations Platform
 * Core Domain Model & Type Definitions
 */

export enum Role {
  PLATFORM_ADMIN = 'Platform Administrator',
  SECURITY_MANAGER = 'Security Manager',
  SECURITY_ANALYST = 'Security Analyst',
  PENETRATION_TESTER = 'Penetration Tester',
  INCIDENT_RESPONDER = 'Incident Responder',
  AUDITOR = 'Auditor',
  READ_ONLY_VIEWER = 'Read-only Viewer',
}

export enum Permission {
  PROJECT_READ = 'project:read',
  PROJECT_WRITE = 'project:write',
  SCOPE_READ = 'scope:read',
  SCOPE_WRITE = 'scope:write',
  SCOPE_APPROVE = 'scope:approve',
  ASSET_READ = 'asset:read',
  ASSET_WRITE = 'asset:write',
  ASSESSMENT_READ = 'assessment:read',
  ASSESSMENT_CREATE = 'assessment:create',
  ASSESSMENT_APPROVE = 'assessment:approve',
  ASSESSMENT_CANCEL = 'assessment:cancel',
  KILL_SWITCH = 'kill_switch:trigger',
  FINDING_READ = 'finding:read',
  FINDING_WRITE = 'finding:write',
  FINDING_ACCEPT_RISK = 'finding:accept_risk',
  GRAPH_READ = 'graph:read',
  GRAPH_WRITE = 'graph:write',
  INTEL_READ = 'intel:read',
  INTEL_WRITE = 'intel:write',
  ALERT_READ = 'alert:read',
  ALERT_WRITE = 'alert:write',
  INCIDENT_READ = 'incident:read',
  INCIDENT_WRITE = 'incident:write',
  INCIDENT_APPROVE_CONTAINMENT = 'incident:approve_containment',
  LAB_READ = 'lab:read',
  LAB_EXECUTE = 'lab:execute',
  REPORT_READ = 'report:read',
  REPORT_GENERATE = 'report:generate',
  INTEGRATION_READ = 'integration:read',
  INTEGRATION_WRITE = 'integration:write',
  PLUGIN_READ = 'plugin:read',
  PLUGIN_MANAGE = 'plugin:manage',
  USER_READ = 'user:read',
  USER_MANAGE = 'user:manage',
  AUDIT_READ = 'audit:read',
  AI_USE = 'ai:use',
}

export enum EnvironmentType {
  PRODUCTION = 'Production',
  STAGING = 'Staging',
  DEVELOPMENT = 'Development',
  ISOLATED_LAB = 'Isolated Lab',
  CLOUD_VPC = 'Cloud VPC',
  CORPORATE_DMZ = 'Corporate DMZ',
}

export enum Criticality {
  MISSION_CRITICAL = 'Mission Critical',
  HIGH = 'High',
  MEDIUM = 'Medium',
  LOW = 'Low',
}

export enum Severity {
  CRITICAL = 'Critical',
  HIGH = 'High',
  MEDIUM = 'Medium',
  LOW = 'Low',
  INFORMATIONAL = 'Informational',
}

export enum FindingStatus {
  NEW = 'New',
  NEEDS_VALIDATION = 'Needs validation',
  CONFIRMED = 'Confirmed',
  REMEDIATION_PLANNED = 'Remediation planned',
  IN_PROGRESS = 'In progress',
  RETEST_REQUIRED = 'Retest required',
  RESOLVED = 'Resolved',
  ACCEPTED_RISK = 'Accepted risk',
  FALSE_POSITIVE = 'False positive',
}

export enum JobStatus {
  DRAFT = 'DRAFT',
  SCOPE_VALIDATION = 'SCOPE_VALIDATION',
  AWAITING_APPROVAL = 'AWAITING_APPROVAL',
  QUEUED = 'QUEUED',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
}

export enum AssetType {
  DOMAIN = 'Domain / Subdomain',
  IP_RANGE = 'IP Address / CIDR',
  HOST_SERVER = 'Host / Server',
  WEB_APP = 'Web Application',
  API_ENDPOINT = 'API Endpoint',
  CLOUD_RESOURCE = 'Cloud Resource',
  CONTAINER_K8S = 'Container / K8s',
  DATABASE = 'Database',
  DEVICE_INFRA = 'Network / OT Device',
  IDENTITY = 'Identity / IAM Role',
  THIRD_PARTY = 'Authorized 3rd-Party',
}

export interface User {
  id: string;
  username: string;
  email: string;
  displayName: string;
  role: Role;
  department: string;
  mfaEnabled: boolean;
  status: 'Active' | 'Suspended';
  lastLoginAt: string;
  projectIds: string[];
}

export interface Workspace {
  id: string;
  name: string;
  description: string;
  organization: string;
  createdAt: string;
}

export interface ScopeRule {
  id: string;
  projectId: string;
  name: string;
  authorizedTargets: string[]; // Domains, IPs, CIDRs
  excludedTargets: string[];   // Explicit exclusions
  allowedEnvironments: EnvironmentType[];
  windowStart: string;         // ISO timestamp
  windowEnd: string;           // ISO timestamp
  authorizedBy: string;
  authorizationTicketRef: string;
  acknowledgmentStatement: string;
  status: 'Active' | 'Expired' | 'Revoked' | 'Pending Approval';
  allowIntrusiveValidation: boolean;
  maxRatePerSecond: number;
  createdAt: string;
  updatedAt: string;
}

export interface Project {
  id: string;
  workspaceId: string;
  name: string;
  code: string;
  description: string;
  ownerId: string;
  memberIds: string[];
  environment: EnvironmentType;
  authorizationStatus: 'Authorized' | 'Pending Authorization' | 'Expired' | 'Suspended';
  startDate: string;
  endDate: string;
  scopeId: string;
  activePolicyProfile: 'Passive Only' | 'Safe Non-Destructive Validation' | 'Isolated Lab Emulation';
  archived: boolean;
  isSyntheticDemo: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface Asset {
  id: string;
  projectId: string;
  assetType: AssetType;
  displayName: string;
  address: string; // Hostname, IP, URL, ARN
  environment: EnvironmentType;
  owner: string;
  criticality: Criticality;
  exposure: 'External / Internet-Facing' | 'Internal / Private' | 'Isolated Lab' | 'Cloud VPC';
  tags: string[];
  discoverySource: string;
  firstSeenAt: string;
  lastSeenAt: string;
  verificationStatus: 'Verified In-Scope' | 'Unverified Candidate' | 'Excluded / Out-of-Scope';
  technologies: string[];
  openPortsOrServices: string[];
  notes: string;
  evidenceIds: string[];
  isSynthetic: boolean;
}

export type AssessmentProfileType =
  | 'DNS & Certificate Reconnaissance'
  | 'Authorized Service & TLS Audit'
  | 'Safe Web & API Header Validation'
  | 'Cloud & Kubernetes Posture Review'
  | 'Non-Destructive CVE Configuration Check'
  | 'Lab Adversary Telemetry Verification';

export interface AssessmentJob {
  id: string;
  workspaceId: string;
  projectId: string;
  name: string;
  profile: AssessmentProfileType;
  providerId: string;
  providerMode: 'Simulated Safe Provider' | 'Passive Inspector' | 'Configured External Adapter';
  requestedTargets: string[];
  scopeValidationResult: {
    passed: boolean;
    checkedAt: string;
    validTargets: string[];
    rejectedTargets: { target: string; reason: string }[];
    policyNotes: string;
  };
  requiresApproval: boolean;
  approvalState: 'Not Required' | 'Pending Approval' | 'Approved' | 'Rejected';
  approvedBy?: string;
  approvedAt?: string;
  status: JobStatus;
  progress: number;
  startedAt?: string;
  completedAt?: string;
  createdBy: string;
  createdAt: string;
  resourceLimits: {
    maxConcurrency: number;
    timeoutSeconds: number;
    rateLimitRps: number;
  };
  findingIds: string[];
  logs: { timestamp: string; level: 'INFO' | 'WARN' | 'ERROR'; message: string }[];
  errorClassification?: string;
  isSynthetic: boolean;
}

export interface Finding {
  id: string;
  projectId: string;
  assetId: string;
  assetName: string;
  jobId?: string;
  title: string;
  category: 'Web & API' | 'Cloud & IAM' | 'Container & K8s' | 'Network & TLS' | 'Identity & Auth' | 'Dependency & Supply Chain';
  severity: Severity;
  confidence: number; // 0 - 100
  status: FindingStatus;
  cveId?: string;
  cvssScore?: number;
  cweId?: string;
  description: string;
  evidenceSummary: string;
  reproductionSteps: string;
  remediationRecommendation: string;
  owner: string;
  remediationDeadline: string;
  riskAcceptanceJustification?: string;
  riskAcceptanceExpiresAt?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  verifiedByValidationCheck: boolean;
  sourceReference: string;
  isSynthetic: boolean;
}

export interface EvidenceRecord {
  id: string;
  projectId: string;
  title: string;
  type: 'HTTP Transcript' | 'TLS Certificate Chain' | 'DNS Zone Snapshot' | 'K8s Manifest Audit' | 'SIEM Log Extract' | 'SARIF Import' | 'Validation Output';
  linkedEntityType: 'Asset' | 'Assessment' | 'Finding' | 'Incident';
  linkedEntityId: string;
  capturedAt: string;
  capturedBy: string;
  sha256Hash: string;
  mimeType: string;
  sizeBytes: number;
  contentSnippet: string;
  classification: 'Confidential' | 'Restricted' | 'Internal';
  isSynthetic: boolean;
}

export interface GraphNode {
  id: string;
  projectId: string;
  label: string;
  nodeType: 'Asset' | 'Identity' | 'Service' | 'Permission' | 'Finding' | 'CloudResource' | 'SecurityControl';
  criticality: Criticality;
  exposure: 'External' | 'Internal' | 'Isolated';
  riskScore: number; // 0 - 100
  verified: boolean;
  metadata: Record<string, string | number | boolean>;
}

export interface GraphEdge {
  id: string;
  projectId: string;
  source: string;
  target: string;
  relationshipType:
    | 'EXPOSES_SERVICE'
    | 'HAS_VULNERABILITY'
    | 'CAN_ASSUME_ROLE'
    | 'NETWORK_REACHABLE'
    | 'TRUST_RELATIONSHIP'
    | 'MITIGATED_BY_CONTROL'
    | 'AI_INFERRED_PATH';
  provenance: 'Observed Telemetry' | 'Configuration Audit' | 'Verified Assessment' | 'AI Inferred Hypothesis';
  confidence: number; // 0 - 100
  isInferredHypothesis: boolean;
  evidenceRef: string;
  defensiveBreakRecommendation: string;
  timestamp: string;
}

export interface ThreatIndicator {
  id: string;
  projectId: string;
  indicatorType: 'IPv4' | 'Domain' | 'URL' | 'SHA-256' | 'TLS Fingerprint';
  value: string;
  threatLabels: string[];
  sourceAttribution: string;
  sourceVerified: boolean;
  confidence: number; // 0 - 100
  severity: Severity;
  firstObservedAt: string;
  lastObservedAt: string;
  expiresAt: string;
  matchedAssetIds: string[];
  matchedIncidentIds: string[];
  provenanceNotes: string;
  isSynthetic: boolean;
}

export interface DetectionRule {
  id: string;
  name: string;
  version: string;
  severity: Severity;
  mitreTechnique: string;
  description: string;
  queryExpression: string;
  enabled: boolean;
  testStatus: 'Passing' | 'Needs Review';
  lastUpdatedAt: string;
}

export interface SecurityAlert {
  id: string;
  projectId: string;
  title: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  confidence: number;
  status: 'New' | 'Investigating' | 'Escalated to Incident' | 'Benign / Tuned' | 'Closed';
  assetId: string;
  assetName: string;
  owner: string;
  normalizedSource: string;
  rawEvidenceSnippet: string;
  matchExplanation: string;
  timestamp: string;
  notes: string[];
  isSynthetic: boolean;
}

export interface IncidentPlaybookStep {
  id: string;
  phase: 'Triage' | 'Evidence Preservation' | 'Asset Isolation Recommendation' | 'Credential Rotation' | 'Patch Verification' | 'Recovery Verification';
  title: string;
  completed: boolean;
  requiresApproval: boolean;
  approvedBy?: string;
  completedAt?: string;
}

export interface Incident {
  id: string;
  projectId: string;
  title: string;
  description: string;
  severity: Severity;
  status: 'Open / Triage' | 'Investigation' | 'Containment Pending Approval' | 'Contained' | 'Recovery' | 'Closed';
  assignedResponder: string;
  affectedAssetIds: string[];
  relatedAlertIds: string[];
  evidenceIds: string[];
  timeline: { timestamp: string; actor: string; event: string }[];
  notes: { author: string; timestamp: string; text: string }[];
  playbookSteps: IncidentPlaybookStep[];
  containmentRecommendations: string[];
  closureSummary?: string;
  createdAt: string;
  updatedAt: string;
  isSynthetic: boolean;
}

export interface CloudContainerCheck {
  id: string;
  projectId: string;
  domain: 'Cloud Configuration' | 'Kubernetes Manifest' | 'Container Image' | 'IaC Review';
  resourceName: string;
  provider: 'AWS' | 'GCP' | 'Azure' | 'Kubernetes' | 'Docker / OCI' | 'Terraform';
  controlId: string;
  title: string;
  severity: Severity;
  status: 'Fail' | 'Pass' | 'Manual Review';
  evidence: string;
  remediation: string;
  lastCheckedAt: string;
  isSynthetic: boolean;
}

export interface WebApiCheck {
  id: string;
  projectId: string;
  assetId: string;
  endpointUrl: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'GRAPHQL';
  authScheme: 'OAuth2 / OIDC' | 'JWT Bearer' | 'mTLS' | 'API Key' | 'Unauthenticated Public';
  tlsVersion: 'TLS 1.3' | 'TLS 1.2' | 'Weak / Deprecated';
  securityHeadersScore: number; // 0 - 100
  missingHeaders: string[];
  passiveFindingsCount: number;
  rateLimitConfigured: boolean;
  lastValidatedAt: string;
  isSynthetic: boolean;
}

export interface LabScenario {
  id: string;
  projectId: string;
  name: string;
  mitreMapping: string[];
  labProfileName: string;
  environmentMetadata: string;
  executionMode: 'Simulated' | 'Locally Executed' | 'Remotely Executed' | 'Not Configured' | 'Failed';
  preconditions: string[];
  benignTestActions: string[];
  expectedEvents: string[];
  expectedDetections: string[];
  observedOutcomes: string[];
  detectionCoverageScore: number;
  cleanupStatus: 'Verified Clean' | 'Pending Cleanup' | 'Not Run';
  lastRunAt?: string;
  executionLogs: string[];
}

export interface SecurityReport {
  id: string;
  projectId: string;
  title: string;
  reportType:
    | 'Executive Security Summary'
    | 'Technical Assessment Report'
    | 'Vulnerability Register'
    | 'Asset Inventory'
    | 'Remediation Plan'
    | 'Incident Report'
    | 'Attack-Path Analysis'
    | 'Laboratory Exercise Report'
    | 'Audit Report';
  generatedBy: string;
  generatedAt: string;
  status: 'Ready' | 'Generating' | 'Failed';
  scopeSummary: string;
  methodology: string;
  executiveSummary: string;
  verifiedFindingsCount: number;
  unverifiedHypothesesCount: number;
  includesSyntheticData: boolean;
  limitations: string;
  remediationRoadmap: string[];
}

export interface IntegrationConfig {
  id: string;
  name: string;
  category: 'AI Engine' | 'Threat Intelligence' | 'Vulnerability Scanner' | 'SIEM & Logging' | 'Cloud Inventory' | 'Source Control' | 'Notifications';
  provider: string;
  status: 'Connected' | 'Safe Simulation Mode' | 'Not Configured' | 'Error';
  endpointUrl: string;
  requiresCredentials: boolean;
  credentialConfigured: boolean;
  lastSyncAt?: string;
  lastTestMessage: string;
  capabilities: string[];
}

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  supportedPlatformVersion: string;
  capabilities: string[];
  permissionsRequested: Permission[];
  configurationSchema: Record<string, string>;
  requiredSecrets: string[];
  installed: boolean;
  enabled: boolean;
  isolatedWorker: boolean;
  executionLimits: {
    maxMemoryMb: number;
    timeoutSeconds: number;
  };
  healthStatus: 'Healthy' | 'Disabled' | 'Degraded';
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actorId: string;
  actorName: string;
  actorRole: Role;
  projectId: string;
  action: string;
  targetType: string;
  targetId: string;
  outcome: 'SUCCESS' | 'DENIED_RBAC' | 'REJECTED_OUT_OF_SCOPE' | 'APPROVAL_REQUIRED' | 'EMERGENCY_STOP' | 'ERROR';
  details: Record<string, unknown>;
  prevHash: string;
  chainHash: string;
}

export interface AIConversationMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  citedFindingIds?: string[];
  citedAssetIds?: string[];
  confidenceNote?: string;
  toolExecuted?: string;
  modelUsed?: string;
}

export interface NotificationItem {
  id: string;
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'critical' | 'success';
  timestamp: string;
  read: boolean;
  linkSection?: NavigationSectionId;
}

export type NavigationSectionId =
  | 'overview'
  | 'ai-copilot'
  | 'assets'
  | 'assessments'
  | 'vulnerabilities'
  | 'attack-paths'
  | 'threat-intel'
  | 'secops'
  | 'incidents'
  | 'cloud-containers'
  | 'web-api'
  | 'lab-emulation'
  | 'reports'
  | 'integrations'
  | 'plugins'
  | 'team-rbac'
  | 'audit-log'
  | 'system-health'
  | 'settings';
