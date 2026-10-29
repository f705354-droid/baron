/**
 * BARON NEXUS — Security Engineering, RBAC, Scope Enforcement, SSRF Guard & Cryptographic Audit Engine
 */

import crypto from 'crypto';
import {
  AuditEvent,
  JobStatus,
  Permission,
  Role,
  ScopeRule,
} from '../types/domain.ts';

export const ROLE_PERMISSIONS: Record<Role, Set<Permission>> = {
  [Role.PLATFORM_ADMIN]: new Set(Object.values(Permission)),
  [Role.SECURITY_MANAGER]: new Set([
    Permission.PROJECT_READ,
    Permission.PROJECT_WRITE,
    Permission.SCOPE_READ,
    Permission.SCOPE_WRITE,
    Permission.SCOPE_APPROVE,
    Permission.ASSET_READ,
    Permission.ASSET_WRITE,
    Permission.ASSESSMENT_READ,
    Permission.ASSESSMENT_CREATE,
    Permission.ASSESSMENT_APPROVE,
    Permission.ASSESSMENT_CANCEL,
    Permission.KILL_SWITCH,
    Permission.FINDING_READ,
    Permission.FINDING_WRITE,
    Permission.FINDING_ACCEPT_RISK,
    Permission.GRAPH_READ,
    Permission.GRAPH_WRITE,
    Permission.INTEL_READ,
    Permission.INTEL_WRITE,
    Permission.ALERT_READ,
    Permission.ALERT_WRITE,
    Permission.INCIDENT_READ,
    Permission.INCIDENT_WRITE,
    Permission.INCIDENT_APPROVE_CONTAINMENT,
    Permission.LAB_READ,
    Permission.LAB_EXECUTE,
    Permission.REPORT_READ,
    Permission.REPORT_GENERATE,
    Permission.INTEGRATION_READ,
    Permission.PLUGIN_READ,
    Permission.USER_READ,
    Permission.AUDIT_READ,
    Permission.AI_USE,
  ]),
  [Role.SECURITY_ANALYST]: new Set([
    Permission.PROJECT_READ,
    Permission.SCOPE_READ,
    Permission.ASSET_READ,
    Permission.ASSET_WRITE,
    Permission.ASSESSMENT_READ,
    Permission.FINDING_READ,
    Permission.FINDING_WRITE,
    Permission.GRAPH_READ,
    Permission.GRAPH_WRITE,
    Permission.INTEL_READ,
    Permission.INTEL_WRITE,
    Permission.ALERT_READ,
    Permission.ALERT_WRITE,
    Permission.INCIDENT_READ,
    Permission.INCIDENT_WRITE,
    Permission.LAB_READ,
    Permission.REPORT_READ,
    Permission.REPORT_GENERATE,
    Permission.INTEGRATION_READ,
    Permission.PLUGIN_READ,
    Permission.AUDIT_READ,
    Permission.AI_USE,
  ]),
  [Role.PENETRATION_TESTER]: new Set([
    Permission.PROJECT_READ,
    Permission.SCOPE_READ,
    Permission.ASSET_READ,
    Permission.ASSET_WRITE,
    Permission.ASSESSMENT_READ,
    Permission.ASSESSMENT_CREATE,
    Permission.ASSESSMENT_CANCEL,
    Permission.FINDING_READ,
    Permission.FINDING_WRITE,
    Permission.GRAPH_READ,
    Permission.GRAPH_WRITE,
    Permission.INTEL_READ,
    Permission.LAB_READ,
    Permission.LAB_EXECUTE,
    Permission.REPORT_READ,
    Permission.REPORT_GENERATE,
    Permission.AI_USE,
  ]),
  [Role.INCIDENT_RESPONDER]: new Set([
    Permission.PROJECT_READ,
    Permission.SCOPE_READ,
    Permission.ASSET_READ,
    Permission.FINDING_READ,
    Permission.GRAPH_READ,
    Permission.INTEL_READ,
    Permission.INTEL_WRITE,
    Permission.ALERT_READ,
    Permission.ALERT_WRITE,
    Permission.INCIDENT_READ,
    Permission.INCIDENT_WRITE,
    Permission.LAB_READ,
    Permission.REPORT_READ,
    Permission.REPORT_GENERATE,
    Permission.AUDIT_READ,
    Permission.AI_USE,
  ]),
  [Role.AUDITOR]: new Set([
    Permission.PROJECT_READ,
    Permission.SCOPE_READ,
    Permission.ASSET_READ,
    Permission.ASSESSMENT_READ,
    Permission.FINDING_READ,
    Permission.GRAPH_READ,
    Permission.INTEL_READ,
    Permission.ALERT_READ,
    Permission.INCIDENT_READ,
    Permission.LAB_READ,
    Permission.REPORT_READ,
    Permission.REPORT_GENERATE,
    Permission.INTEGRATION_READ,
    Permission.PLUGIN_READ,
    Permission.USER_READ,
    Permission.AUDIT_READ,
  ]),
  [Role.READ_ONLY_VIEWER]: new Set([
    Permission.PROJECT_READ,
    Permission.SCOPE_READ,
    Permission.ASSET_READ,
    Permission.ASSESSMENT_READ,
    Permission.FINDING_READ,
    Permission.GRAPH_READ,
    Permission.INTEL_READ,
    Permission.ALERT_READ,
    Permission.INCIDENT_READ,
    Permission.LAB_READ,
    Permission.REPORT_READ,
  ]),
};

export function hasPermission(role: Role, permission: Permission): boolean {
  const perms = ROLE_PERMISSIONS[role];
  return perms ? perms.has(permission) : false;
}

/**
 * IPv4 & CIDR helper for deterministic server-side scope validation
 */
function ipToLong(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const val = parseInt(part, 10);
    if (val < 0 || val > 255) return null;
    num = (num << 8) + val;
  }
  return num >>> 0;
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const [netStr, prefixStr] = cidr.split('/');
  if (!netStr || !prefixStr) return false;
  const ipLong = ipToLong(ip);
  const netLong = ipToLong(netStr);
  const prefix = parseInt(prefixStr, 10);
  if (ipLong === null || netLong === null || isNaN(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  if (prefix === 0) return true;
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (ipLong & mask) === (netLong & mask);
}

/**
 * Extracts normalized hostname or IPv4 from a target string (URL, host:port, domain, or IP)
 */
export function normalizeTargetHost(rawTarget: string): string {
  const trimmed = rawTarget.trim().toLowerCase();
  if (!trimmed) return '';
  try {
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      const u = new URL(trimmed);
      return u.hostname.toLowerCase();
    }
  } catch {
    // Fall through
  }
  const withoutPath = trimmed.split('/')[0] || '';
  const withoutPort = withoutPath.split(':')[0] || '';
  return withoutPort;
}

export function matchesScopePattern(target: string, pattern: string): boolean {
  const normTarget = normalizeTargetHost(target);
  const normPattern = pattern.trim().toLowerCase();
  if (!normTarget || !normPattern) return false;

  if (normTarget === normPattern || target.trim().toLowerCase() === normPattern) {
    return true;
  }

  // CIDR match
  if (normPattern.includes('/')) {
    if (isIpInCidr(normTarget, normPattern)) return true;
  }

  // Wildcard subdomain match (*.example.com or .example.com)
  if (normPattern.startsWith('*.')) {
    const base = normPattern.slice(2);
    return normTarget === base || normTarget.endsWith(`.${base}`);
  }
  if (normPattern.startsWith('.')) {
    const base = normPattern.slice(1);
    return normTarget === base || normTarget.endsWith(normPattern);
  }

  return false;
}

export interface ScopeValidationSummary {
  passed: boolean;
  checkedAt: string;
  validTargets: string[];
  rejectedTargets: { target: string; reason: string }[];
  policyNotes: string;
}

/**
 * Mandatory server-side scope validation service.
 * Runs before every assessment operation.
 */
export function validateTargetsAgainstScope(
  requestedTargets: string[],
  scope: ScopeRule | undefined,
  projectAuthorizationStatus: string,
  now: Date = new Date()
): ScopeValidationSummary {
  const checkedAt = now.toISOString();

  if (!scope) {
    return {
      passed: false,
      checkedAt,
      validTargets: [],
      rejectedTargets: requestedTargets.map((t) => ({
        target: t,
        reason: 'No scope rule configured for this project.',
      })),
      policyNotes: 'Assessment blocked: missing scope registry definition.',
    };
  }

  if (projectAuthorizationStatus !== 'Authorized') {
    return {
      passed: false,
      checkedAt,
      validTargets: [],
      rejectedTargets: requestedTargets.map((t) => ({
        target: t,
        reason: `Project authorization status is '${projectAuthorizationStatus}' (must be 'Authorized').`,
      })),
      policyNotes: 'Assessment blocked: project is not explicitly authorized.',
    };
  }

  if (scope.status !== 'Active') {
    return {
      passed: false,
      checkedAt,
      validTargets: [],
      rejectedTargets: requestedTargets.map((t) => ({
        target: t,
        reason: `Scope status is '${scope.status}' (must be 'Active').`,
      })),
      policyNotes: 'Assessment blocked: scope is not active.',
    };
  }

  if (
    scope.acknowledgmentStatement !==
    'I confirm explicit written authorization exists for all scoped targets.'
  ) {
    return {
      passed: false,
      checkedAt,
      validTargets: [],
      rejectedTargets: requestedTargets.map((t) => ({
        target: t,
        reason: 'Scope is missing valid formal authorization acknowledgment.',
      })),
      policyNotes: 'Assessment blocked: invalid authorization acknowledgment.',
    };
  }

  const start = new Date(scope.windowStart);
  const end = new Date(scope.windowEnd);
  if (isNaN(start.getTime()) || isNaN(end.getTime()) || now < start || now > end) {
    return {
      passed: false,
      checkedAt,
      validTargets: [],
      rejectedTargets: requestedTargets.map((t) => ({
        target: t,
        reason: `Current time (${checkedAt}) is outside authorized testing window (${scope.windowStart} to ${scope.windowEnd}).`,
      })),
      policyNotes: 'Assessment blocked: outside authorized testing window.',
    };
  }

  if (!requestedTargets || requestedTargets.length === 0) {
    return {
      passed: false,
      checkedAt,
      validTargets: [],
      rejectedTargets: [],
      policyNotes: 'No targets specified for assessment.',
    };
  }

  const validTargets: string[] = [];
  const rejectedTargets: { target: string; reason: string }[] = [];

  for (const rawTarget of requestedTargets) {
    const target = rawTarget.trim();
    if (!target) continue;

    // 1. Check exclusions first (explicit deny overrides allow)
    const matchedExclusion = scope.excludedTargets.find((ex) =>
      matchesScopePattern(target, ex)
    );
    if (matchedExclusion) {
      rejectedTargets.push({
        target,
        reason: `Target matches explicit scope exclusion rule '${matchedExclusion}'.`,
      });
      continue;
    }

    // 2. Check authorized targets
    const matchedAllow = scope.authorizedTargets.find((allow) =>
      matchesScopePattern(target, allow)
    );
    if (!matchedAllow) {
      rejectedTargets.push({
        target,
        reason: 'Target is not listed in authorized scope patterns.',
      });
      continue;
    }

    validTargets.push(target);
  }

  const passed = rejectedTargets.length === 0 && validTargets.length > 0;
  return {
    passed,
    checkedAt,
    validTargets,
    rejectedTargets,
    policyNotes: passed
      ? `All ${validTargets.length} target(s) verified in scope (${scope.authorizationTicketRef}).`
      : `Rejected ${rejectedTargets.length} out-of-scope or excluded target(s).`,
  };
}

/**
 * Valid Assessment Job State Machine Transitions
 * DRAFT → SCOPE_VALIDATION → AWAITING_APPROVAL → QUEUED → RUNNING → COMPLETED / FAILED / CANCELLED
 */
const VALID_JOB_TRANSITIONS: Record<JobStatus, Set<JobStatus>> = {
  [JobStatus.DRAFT]: new Set([JobStatus.SCOPE_VALIDATION, JobStatus.CANCELLED]),
  [JobStatus.SCOPE_VALIDATION]: new Set([
    JobStatus.AWAITING_APPROVAL,
    JobStatus.QUEUED,
    JobStatus.FAILED,
    JobStatus.CANCELLED,
  ]),
  [JobStatus.AWAITING_APPROVAL]: new Set([
    JobStatus.QUEUED,
    JobStatus.FAILED,
    JobStatus.CANCELLED,
  ]),
  [JobStatus.QUEUED]: new Set([
    JobStatus.RUNNING,
    JobStatus.FAILED,
    JobStatus.CANCELLED,
  ]),
  [JobStatus.RUNNING]: new Set([
    JobStatus.COMPLETED,
    JobStatus.FAILED,
    JobStatus.CANCELLED,
  ]),
  [JobStatus.COMPLETED]: new Set([]),
  [JobStatus.FAILED]: new Set([]),
  [JobStatus.CANCELLED]: new Set([]),
};

export function canTransitionJobStatus(from: JobStatus, to: JobStatus): boolean {
  return VALID_JOB_TRANSITIONS[from]?.has(to) ?? false;
}

/**
 * SSRF Protection for external integration URLs.
 * Blocks loopback, link-local (169.254.0.0/16 cloud metadata), and RFC1918 private addresses
 * unless explicitly permitted for a narrow internal lab integration.
 */
export function validateExternalIntegrationUrl(
  rawUrl: string,
  allowScopedInternal = false
): { valid: boolean; reason?: string } {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return { valid: false, reason: 'Only HTTP/HTTPS protocols are permitted.' };
    }
    const host = parsed.hostname.toLowerCase();

    if (
      host === 'localhost' ||
      host === '0.0.0.0' ||
      host === '::1' ||
      host === '[::1]' ||
      host.endsWith('.localhost')
    ) {
      return { valid: false, reason: 'Loopback destinations are blocked (SSRF protection).' };
    }

    // Cloud metadata & link-local always blocked
    if (
      host === 'metadata.google.internal' ||
      isIpInCidr(host, '169.254.0.0/16') ||
      isIpInCidr(host, '127.0.0.0/8')
    ) {
      return {
        valid: false,
        reason: 'Link-local, cloud metadata, and loopback IP ranges are strictly blocked (SSRF protection).',
      };
    }

    if (!allowScopedInternal) {
      if (
        isIpInCidr(host, '10.0.0.0/8') ||
        isIpInCidr(host, '172.16.0.0/12') ||
        isIpInCidr(host, '192.168.0.0/16') ||
        host.endsWith('.internal') ||
        host.endsWith('.local')
      ) {
        return {
          valid: false,
          reason: 'Private RFC1918 / internal network addresses are blocked for external integrations.',
        };
      }
    }

    return { valid: true };
  } catch {
    return { valid: false, reason: 'Malformed URL.' };
  }
}

/**
 * Immutable-style Cryptographic Hash-Chained Audit Trail
 * Inspired by Al-Baron's AuditTrail (`entry_i.hash = sha256(entry_i.data + entry_{i-1}.hash)`)
 */
export function computeAuditHash(
  payload: Omit<AuditEvent, 'chainHash'>,
  prevHash: string
): string {
  const canonical = JSON.stringify({
    id: payload.id,
    timestamp: payload.timestamp,
    actorId: payload.actorId,
    actorName: payload.actorName,
    actorRole: payload.actorRole,
    projectId: payload.projectId,
    action: payload.action,
    targetType: payload.targetType,
    targetId: payload.targetId,
    outcome: payload.outcome,
    details: payload.details,
    prevHash,
  });
  return crypto.createHash('sha256').update(canonical + prevHash).digest('hex');
}

export function verifyAuditChainIntegrity(events: AuditEvent[]): {
  valid: boolean;
  totalChecked: number;
  tamperedIndices: number[];
} {
  // Events may be stored newest-first or oldest-first; sort oldest-first by sequence
  const chronological = [...events].reverse();
  let expectedPrev = 'GENESIS_BARON_NEXUS_0000000000000000';
  const tamperedIndices: number[] = [];

  for (let i = 0; i < chronological.length; i++) {
    const ev = chronological[i];
    if (ev.prevHash !== expectedPrev) {
      tamperedIndices.push(i);
    }
    const recomputed = computeAuditHash(ev, ev.prevHash);
    if (recomputed !== ev.chainHash) {
      tamperedIndices.push(i);
    }
    expectedPrev = ev.chainHash;
  }

  return {
    valid: tamperedIndices.length === 0,
    totalChecked: chronological.length,
    tamperedIndices,
  };
}

/**
 * Redacts sensitive tokens or secrets from structured log objects
 */
export function redactSecrets(input: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = /password|secret|token|apikey|api_key|authorization|credential/i;
  const output: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
    if (sensitiveKeys.test(k)) {
      output[k] = '[REDACTED]';
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      output[k] = redactSecrets(v as Record<string, unknown>);
    } else {
      output[k] = v;
    }
  }
  return output;
}
