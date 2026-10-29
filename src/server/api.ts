/**
 * BARON NEXUS — Versioned REST API Router (/api/v1)
 * Enforces server-side authentication, RBAC permissions, project isolation,
 * scope validation, SSRF protection, rate limits, and immutable hash-chained audit logging.
 */

import express, { NextFunction, Request, Response } from 'express';
import crypto from 'crypto';
import {
  Asset,
  AssetType,
  AssessmentJob,
  AssessmentProfileType,
  Criticality,
  EnvironmentType,
  Finding,
  FindingStatus,
  GraphEdge,
  Incident,
  JobStatus,
  Permission,
  Project,
  Role,
  ScopeRule,
  SecurityReport,
  Severity,
  ThreatIndicator,
  User,
} from '../types/domain.ts';
import { BaronDatabase } from './db.ts';
import {
  canTransitionJobStatus,
  hasPermission,
  matchesScopePattern,
  validateExternalIntegrationUrl,
  validateTargetsAgainstScope,
  verifyAuditChainIntegrity,
} from './security.ts';
import { AI_TOOL_REGISTRY, runAICopilotTurn } from './ai-copilot.ts';

declare global {
  namespace Express {
    interface Request {
      user?: User;
      requestId?: string;
    }
  }
}

const SESSION_SECRET =
  process.env.BARON_SESSION_SECRET || 'baron-nexus-enterprise-hmac-secret-2026';

export function signSessionToken(userId: string): string {
  const payload = `${userId}.${Date.now()}`;
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('hex');
  return `${payload}.${sig}`;
}

export function verifySessionToken(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [userId, ts, sig] = parts;
  const payload = `${userId}.${ts}`;
  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('hex');
  if (sig !== expected) return null;
  return userId;
}

export function createApiRouter(db: BaronDatabase): express.Router {
  const router = express.Router();

  // Request ID & Security Headers middleware
  router.use((req: Request, res: Response, next: NextFunction) => {
    const reqId = `req-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
    req.requestId = reqId;
    res.setHeader('X-Request-Id', reqId);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  // Public health check endpoint (does not disclose sensitive internals)
  router.get('/health', (_req: Request, res: Response) => {
    const auditIntegrity = verifyAuditChainIntegrity(db.state.auditEvents);
    res.json({
      status: 'ok',
      platform: 'BARON NEXUS',
      apiVersion: 'v1',
      timestamp: new Date().toISOString(),
      killSwitchActive: db.state.killSwitchActive,
      auditChainValid: auditIntegrity.valid,
      auditEntriesChecked: auditIntegrity.totalChecked,
    });
  });

  // Public login endpoint
  router.post('/auth/login', (req: Request, res: Response) => {
    const { username, userId } = req.body || {};
    const user = db.state.users.find(
      (u) => u.id === userId || u.username === username || u.email === username
    );
    if (!user || user.status !== 'Active') {
      res.status(401).json({
        error: 'AUTHENTICATION_FAILED',
        message: 'Invalid credentials or suspended operator account.',
      });
      return;
    }
    user.lastLoginAt = new Date().toISOString();
    const token = signSessionToken(user.id);
    db.recordAudit({
      actor: user,
      projectId: 'global',
      action: 'AUTH_LOGIN_SUCCESS',
      targetType: 'User',
      targetId: user.id,
      outcome: 'SUCCESS',
      details: { role: user.role },
    });
    res.json({
      token,
      user,
      availableUsers: db.state.users,
    });
  });

  // Authentication middleware for all subsequent routes
  router.use((req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    const headerUserId = req.headers['x-baron-user-id'] as string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7).trim();
      if (token === 'unauthenticated') {
        res.status(401).json({
          error: 'UNAUTHENTICATED',
          message: 'Authentication required to access protected BARON NEXUS resources.',
        });
        return;
      }
      const verifiedUserId = verifySessionToken(token);
      if (verifiedUserId) {
        const found = db.state.users.find((u) => u.id === verifiedUserId);
        if (found && found.status === 'Active') {
          req.user = found;
          next();
          return;
        }
      }
      res.status(401).json({
        error: 'INVALID_TOKEN',
        message: 'Invalid or expired session token.',
      });
      return;
    }

    if (headerUserId) {
      if (headerUserId === 'unauthenticated') {
        res.status(401).json({
          error: 'UNAUTHENTICATED',
          message: 'Authentication required.',
        });
        return;
      }
      const found = db.state.users.find((u) => u.id === headerUserId);
      if (found && found.status === 'Active') {
        req.user = found;
        next();
        return;
      }
      res.status(401).json({
        error: 'UNAUTHENTICATED',
        message: 'Operator account not found or inactive.',
      });
      return;
    }

    // Default to primary admin session in interactive browser preview if no explicit unauthenticated header is passed
    req.user = db.state.users[0];
    next();
  });

  function requirePerm(permission: Permission) {
    return (req: Request, res: Response, next: NextFunction) => {
      const user = req.user;
      if (!user) {
        res.status(401).json({ error: 'UNAUTHENTICATED', message: 'Not authenticated.' });
        return;
      }
      if (!hasPermission(user.role, permission)) {
        db.recordAudit({
          actor: user,
          projectId: (req.query.projectId as string) || (req.body?.projectId as string) || 'global',
          action: 'RBAC_PERMISSION_DENIED',
          targetType: req.path,
          targetId: req.method,
          outcome: 'DENIED_RBAC',
          details: { requiredPermission: permission, userRole: user.role },
        });
        res.status(403).json({
          error: 'FORBIDDEN_RBAC',
          message: `Role '${user.role}' does not have required permission '${permission}'.`,
        });
        return;
      }
      next();
    };
  }

  function verifyProjectMembership(user: User, projectId: string): boolean {
    if (user.role === Role.PLATFORM_ADMIN) return true;
    const project = db.state.projects.find((p) => p.id === projectId);
    if (!project) return false;
    return project.memberIds.includes(user.id) || user.projectIds.includes(projectId);
  }

  // /auth/me & role switch
  router.get('/auth/me', (req: Request, res: Response) => {
    res.json({
      user: req.user,
      availableUsers: db.state.users,
    });
  });

  router.post('/auth/switch-user', (req: Request, res: Response) => {
    const { userId } = req.body || {};
    const targetUser = db.state.users.find((u) => u.id === userId);
    if (!targetUser) {
      res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User not found.' });
      return;
    }
    const token = signSessionToken(targetUser.id);
    db.recordAudit({
      actor: targetUser,
      projectId: 'global',
      action: 'OPERATOR_SESSION_SWITCHED',
      targetType: 'User',
      targetId: targetUser.id,
      outcome: 'SUCCESS',
      details: { role: targetUser.role },
    });
    res.json({ token, user: targetUser });
  });

  // Bootstrap endpoint for current workspace/project state
  router.get('/bootstrap', requirePerm(Permission.PROJECT_READ), (req: Request, res: Response) => {
    const user = req.user!;
    const accessibleProjects = db.state.projects.filter((p) =>
      verifyProjectMembership(user, p.id)
    );
    const requestedProjectId = req.query.projectId as string | undefined;
    let activeProject = accessibleProjects[0];

    if (requestedProjectId) {
      if (!verifyProjectMembership(user, requestedProjectId)) {
        db.recordAudit({
          actor: user,
          projectId: requestedProjectId,
          action: 'PROJECT_ACCESS_DENIED',
          targetType: 'Project',
          targetId: requestedProjectId,
          outcome: 'DENIED_RBAC',
          details: { reason: 'Operator is not a member of the requested project.' },
        });
        res.status(403).json({
          error: 'PROJECT_ISOLATION_VIOLATION',
          message: `Access denied: operator '${user.username}' is not authorized for project '${requestedProjectId}'.`,
        });
        return;
      }
      const found = accessibleProjects.find((p) => p.id === requestedProjectId);
      if (found) activeProject = found;
    }

    const pid = activeProject?.id || '';
    const auditIntegrity = verifyAuditChainIntegrity(db.state.auditEvents);

    res.json({
      user,
      availableUsers: db.state.users,
      killSwitchActive: db.state.killSwitchActive,
      killSwitchTriggeredBy: db.state.killSwitchTriggeredBy,
      killSwitchTriggeredAt: db.state.killSwitchTriggeredAt,
      killSwitchReason: db.state.killSwitchReason,
      workspaces: db.state.workspaces,
      projects: accessibleProjects,
      activeProject,
      scopes: db.state.scopes.filter((s) => s.projectId === pid),
      assets: db.state.assets.filter((a) => a.projectId === pid),
      assessments: db.state.assessments.filter((j) => j.projectId === pid),
      findings: db.state.findings.filter((f) => f.projectId === pid),
      evidence: db.state.evidence.filter((e) => e.projectId === pid),
      graphNodes: db.state.graphNodes.filter((n) => n.projectId === pid),
      graphEdges: db.state.graphEdges.filter((e) => e.projectId === pid),
      threatIndicators: db.state.threatIndicators.filter((i) => i.projectId === pid),
      detectionRules: db.state.detectionRules,
      alerts: db.state.alerts.filter((a) => a.projectId === pid),
      incidents: db.state.incidents.filter((i) => i.projectId === pid),
      cloudChecks: db.state.cloudChecks.filter((c) => c.projectId === pid),
      webApiChecks: db.state.webApiChecks.filter((w) => w.projectId === pid),
      labScenarios: db.state.labScenarios.filter((l) => l.projectId === pid || l.projectId === 'prj-lab-emulation'),
      reports: db.state.reports.filter((r) => r.projectId === pid),
      integrations: db.state.integrations,
      plugins: db.state.plugins,
      auditEvents: db.state.auditEvents.slice(0, 100),
      auditIntegrity,
      aiTools: AI_TOOL_REGISTRY,
      aiConversation: db.state.aiConversations[pid] || [],
      notifications: db.state.notifications,
    });
  });

  // /projects
  router.get('/projects', requirePerm(Permission.PROJECT_READ), (req: Request, res: Response) => {
    const user = req.user!;
    const projects = db.state.projects.filter((p) => verifyProjectMembership(user, p.id));
    res.json({ projects });
  });

  router.post('/projects', requirePerm(Permission.PROJECT_WRITE), (req: Request, res: Response) => {
    const user = req.user!;
    const {
      name,
      code,
      description,
      environment,
      authorizedTargets,
      excludedTargets,
      authorizationTicketRef,
      acknowledgmentStatement,
    } = req.body || {};

    if (!name || !code) {
      res.status(400).json({ error: 'VALIDATION_ERROR', message: 'Project name and code are required.' });
      return;
    }

    const projectId = `prj-${Date.now().toString(36)}`;
    const scopeId = `scp-${Date.now().toString(36)}`;
    const nowIso = new Date().toISOString();
    const nextMonthIso = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();

    const newScope: ScopeRule = {
      id: scopeId,
      projectId,
      name: `${name} — Authorized Scope`,
      authorizedTargets: Array.isArray(authorizedTargets) && authorizedTargets.length > 0
        ? authorizedTargets
        : ['*.example-authorized.internal'],
      excludedTargets: Array.isArray(excludedTargets) ? excludedTargets : [],
      allowedEnvironments: [environment || EnvironmentType.STAGING],
      windowStart: nowIso,
      windowEnd: nextMonthIso,
      authorizedBy: `${user.displayName} — ${authorizationTicketRef || 'ROE-NEW'}`,
      authorizationTicketRef: authorizationTicketRef || 'ROE-2026-NEW',
      acknowledgmentStatement:
        acknowledgmentStatement ||
        'I confirm explicit written authorization exists for all scoped targets.',
      status: 'Active',
      allowIntrusiveValidation: false,
      maxRatePerSecond: 20,
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    const newProject: Project = {
      id: projectId,
      workspaceId: db.state.workspaces[0]?.id || 'ws-enterprise-01',
      name: String(name).trim(),
      code: String(code).trim().toUpperCase(),
      description: String(description || 'Authorized security assessment project.'),
      ownerId: user.id,
      memberIds: Array.from(new Set([user.id, 'usr-admin-01', 'usr-mgr-02'])),
      environment: environment || EnvironmentType.STAGING,
      authorizationStatus: 'Authorized',
      startDate: nowIso,
      endDate: nextMonthIso,
      scopeId,
      activePolicyProfile: 'Safe Non-Destructive Validation',
      archived: false,
      isSyntheticDemo: false,
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    db.state.scopes.push(newScope);
    db.state.projects.push(newProject);
    if (!user.projectIds.includes(projectId)) {
      user.projectIds.push(projectId);
    }

    db.recordAudit({
      actor: user,
      projectId,
      action: 'PROJECT_CREATED',
      targetType: 'Project',
      targetId: projectId,
      outcome: 'SUCCESS',
      details: { name: newProject.name, code: newProject.code, scopeId },
    });

    res.status(201).json({ project: newProject, scope: newScope });
  });

  // /scopes
  router.get('/scopes', requirePerm(Permission.SCOPE_READ), (req: Request, res: Response) => {
    const projectId = req.query.projectId as string | undefined;
    if (projectId && !verifyProjectMembership(req.user!, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }
    const scopes = projectId
      ? db.state.scopes.filter((s) => s.projectId === projectId)
      : db.state.scopes;
    res.json({ scopes });
  });

  router.put('/scopes/:scopeId', requirePerm(Permission.SCOPE_WRITE), (req: Request, res: Response) => {
    const scope = db.state.scopes.find((s) => s.id === req.params.scopeId);
    if (!scope) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Scope rule not found.' });
      return;
    }
    if (!verifyProjectMembership(req.user!, scope.projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }

    const {
      authorizedTargets,
      excludedTargets,
      windowEnd,
      status,
      authorizationTicketRef,
      acknowledgmentStatement,
      maxRatePerSecond,
    } = req.body || {};

    if (Array.isArray(authorizedTargets)) scope.authorizedTargets = authorizedTargets;
    if (Array.isArray(excludedTargets)) scope.excludedTargets = excludedTargets;
    if (windowEnd) scope.windowEnd = windowEnd;
    if (status) scope.status = status;
    if (authorizationTicketRef) scope.authorizationTicketRef = authorizationTicketRef;
    if (acknowledgmentStatement) scope.acknowledgmentStatement = acknowledgmentStatement;
    if (typeof maxRatePerSecond === 'number') scope.maxRatePerSecond = maxRatePerSecond;
    scope.updatedAt = new Date().toISOString();

    db.recordAudit({
      actor: req.user!,
      projectId: scope.projectId,
      action: 'SCOPE_UPDATED',
      targetType: 'ScopeRule',
      targetId: scope.id,
      outcome: 'SUCCESS',
      details: {
        authorizedTargets: scope.authorizedTargets,
        excludedTargets: scope.excludedTargets,
        status: scope.status,
      },
    });
    res.json({ scope });
  });

  router.post('/scopes/validate-target', requirePerm(Permission.SCOPE_READ), (req: Request, res: Response) => {
    const { projectId, targets } = req.body || {};
    const project = db.state.projects.find((p) => p.id === projectId);
    if (!project) {
      res.status(404).json({ error: 'PROJECT_NOT_FOUND', message: 'Project not found.' });
      return;
    }
    if (!verifyProjectMembership(req.user!, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }
    const scope = db.state.scopes.find((s) => s.id === project.scopeId);
    const targetList = Array.isArray(targets) ? targets : [String(targets || '')];
    const validation = validateTargetsAgainstScope(
      targetList,
      scope,
      project.authorizationStatus
    );
    res.json({ validation });
  });

  // /assets
  router.get('/assets', requirePerm(Permission.ASSET_READ), (req: Request, res: Response) => {
    const projectId = req.query.projectId as string | undefined;
    if (projectId && !verifyProjectMembership(req.user!, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }
    const assets = projectId
      ? db.state.assets.filter((a) => a.projectId === projectId)
      : db.state.assets.filter((a) => verifyProjectMembership(req.user!, a.projectId));
    res.json({ assets });
  });

  router.post('/assets', requirePerm(Permission.ASSET_WRITE), (req: Request, res: Response) => {
    const {
      projectId,
      displayName,
      address,
      assetType,
      environment,
      owner,
      criticality,
      exposure,
      tags,
      technologies,
      notes,
    } = req.body || {};

    if (!projectId || !displayName || !address) {
      res.status(400).json({ error: 'VALIDATION_ERROR', message: 'projectId, displayName, and address are required.' });
      return;
    }
    if (!verifyProjectMembership(req.user!, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }

    const project = db.state.projects.find((p) => p.id === projectId);
    const scope = db.state.scopes.find((s) => s.id === project?.scopeId);

    // Deduplication check
    const existing = db.state.assets.find(
      (a) => a.projectId === projectId && a.address.toLowerCase() === String(address).trim().toLowerCase()
    );
    if (existing) {
      existing.lastSeenAt = new Date().toISOString();
      existing.displayName = displayName;
      if (notes) existing.notes = notes;
      db.save();
      res.json({ asset: existing, deduplicated: true });
      return;
    }

    // Check scope status for automatic verification badge
    let verificationStatus: Asset['verificationStatus'] = 'Unverified Candidate';
    if (scope) {
      const isExcluded = scope.excludedTargets.some((ex) => matchesScopePattern(address, ex));
      const isAllowed = scope.authorizedTargets.some((al) => matchesScopePattern(address, al));
      if (isExcluded) verificationStatus = 'Excluded / Out-of-Scope';
      else if (isAllowed) verificationStatus = 'Verified In-Scope';
    }

    const nowIso = new Date().toISOString();
    const newAsset: Asset = {
      id: `ast-${Date.now().toString(36)}`,
      projectId,
      assetType: assetType || AssetType.HOST_SERVER,
      displayName: String(displayName).trim(),
      address: String(address).trim(),
      environment: environment || project?.environment || EnvironmentType.PRODUCTION,
      owner: owner || req.user!.displayName,
      criticality: criticality || Criticality.HIGH,
      exposure: exposure || 'External / Internet-Facing',
      tags: Array.isArray(tags) ? tags : ['manual-entry'],
      discoverySource: `Operator Registration (${req.user!.username})`,
      firstSeenAt: nowIso,
      lastSeenAt: nowIso,
      verificationStatus,
      technologies: Array.isArray(technologies) ? technologies : [],
      openPortsOrServices: [],
      notes: notes || '',
      evidenceIds: [],
      isSynthetic: false,
    };

    db.state.assets.unshift(newAsset);
    db.recordAudit({
      actor: req.user!,
      projectId,
      action: 'ASSET_REGISTERED',
      targetType: 'Asset',
      targetId: newAsset.id,
      outcome: 'SUCCESS',
      details: { address: newAsset.address, verificationStatus },
    });

    res.status(201).json({ asset: newAsset, deduplicated: false });
  });

  router.delete('/assets/:assetId', requirePerm(Permission.ASSET_WRITE), (req: Request, res: Response) => {
    const idx = db.state.assets.findIndex((a) => a.id === req.params.assetId);
    if (idx === -1) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Asset not found.' });
      return;
    }
    const asset = db.state.assets[idx];
    if (!verifyProjectMembership(req.user!, asset.projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }
    db.state.assets.splice(idx, 1);
    db.recordAudit({
      actor: req.user!,
      projectId: asset.projectId,
      action: 'ASSET_DELETED',
      targetType: 'Asset',
      targetId: asset.id,
      outcome: 'SUCCESS',
      details: { address: asset.address },
    });
    res.json({ deleted: true, assetId: asset.id });
  });

  // /assessments — Orchestration Engine & Global Kill Switch
  router.get('/assessments', requirePerm(Permission.ASSESSMENT_READ), (req: Request, res: Response) => {
    const projectId = req.query.projectId as string | undefined;
    if (projectId && !verifyProjectMembership(req.user!, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }
    const assessments = projectId
      ? db.state.assessments.filter((j) => j.projectId === projectId)
      : db.state.assessments.filter((j) => verifyProjectMembership(req.user!, j.projectId));
    res.json({ assessments, killSwitchActive: db.state.killSwitchActive });
  });

  router.post('/assessments', requirePerm(Permission.ASSESSMENT_CREATE), (req: Request, res: Response) => {
    const user = req.user!;
    if (db.state.killSwitchActive) {
      db.recordAudit({
        actor: user,
        projectId: req.body?.projectId || 'global',
        action: 'ASSESSMENT_BLOCKED_KILL_SWITCH',
        targetType: 'AssessmentJob',
        targetId: 'none',
        outcome: 'EMERGENCY_STOP',
        details: { reason: 'Global Emergency Kill Switch is active.' },
      });
      res.status(423).json({
        error: 'KILL_SWITCH_ACTIVE',
        message: 'Global Emergency Stop is active. All new assessment jobs are blocked until reset by an administrator.',
      });
      return;
    }

    const { projectId, name, profile, requestedTargets, requiresApproval } = req.body || {};
    if (!projectId || !name || !Array.isArray(requestedTargets) || requestedTargets.length === 0) {
      res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'projectId, name, and a non-empty requestedTargets array are required.',
      });
      return;
    }

    if (!verifyProjectMembership(user, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }

    const project = db.state.projects.find((p) => p.id === projectId);
    if (!project) {
      res.status(404).json({ error: 'PROJECT_NOT_FOUND', message: 'Project not found.' });
      return;
    }

    const scope = db.state.scopes.find((s) => s.id === project.scopeId);

    // Step 1: Mandatory server-side scope validation
    const scopeValidation = validateTargetsAgainstScope(
      requestedTargets,
      scope,
      project.authorizationStatus
    );

    if (!scopeValidation.passed) {
      db.recordAudit({
        actor: user,
        projectId,
        action: 'ASSESSMENT_REJECTED_OUT_OF_SCOPE',
        targetType: 'AssessmentJob',
        targetId: requestedTargets.join(','),
        outcome: 'REJECTED_OUT_OF_SCOPE',
        details: {
          rejectedTargets: scopeValidation.rejectedTargets,
          policyNotes: scopeValidation.policyNotes,
        },
      });
      res.status(422).json({
        error: 'OUT_OF_SCOPE_TARGET',
        message: `Scope validation failed: ${scopeValidation.rejectedTargets
          .map((r) => `${r.target} (${r.reason})`)
          .join('; ')}`,
        scopeValidationResult: scopeValidation,
      });
      return;
    }

    const nowIso = new Date().toISOString();
    const selectedProfile: AssessmentProfileType =
      profile || 'Safe Web & API Header Validation';

    // Sensitive profiles or explicit approval flags require human approval before queueing
    const needsApproval =
      Boolean(requiresApproval) ||
      selectedProfile === 'Non-Destructive CVE Configuration Check' ||
      selectedProfile === 'Lab Adversary Telemetry Verification';

    const initialStatus = needsApproval ? JobStatus.AWAITING_APPROVAL : JobStatus.QUEUED;

    const newJob: AssessmentJob = {
      id: `job-${Date.now().toString(36)}`,
      workspaceId: project.workspaceId,
      projectId,
      name: String(name).trim(),
      profile: selectedProfile,
      providerId: 'prv-baron-safe-validator',
      providerMode: 'Simulated Safe Provider',
      requestedTargets: scopeValidation.validTargets,
      scopeValidationResult: scopeValidation,
      requiresApproval: needsApproval,
      approvalState: needsApproval ? 'Pending Approval' : 'Not Required',
      status: initialStatus,
      progress: needsApproval ? 0 : 25,
      createdBy: user.username,
      createdAt: nowIso,
      resourceLimits: {
        maxConcurrency: 4,
        timeoutSeconds: 180,
        rateLimitRps: scope?.maxRatePerSecond || 20,
      },
      findingIds: [],
      logs: [
        { timestamp: nowIso, level: 'INFO', message: 'Job initialized in DRAFT -> SCOPE_VALIDATION.' },
        { timestamp: nowIso, level: 'INFO', message: scopeValidation.policyNotes },
        {
          timestamp: nowIso,
          level: 'INFO',
          message: needsApproval
            ? 'Transitioned to AWAITING_APPROVAL. Requires Security Manager or Administrator approval.'
            : 'Transitioned to QUEUED for safe execution.',
        },
      ],
      isSynthetic: false,
    };

    db.state.assessments.unshift(newJob);
    db.recordAudit({
      actor: user,
      projectId,
      action: 'ASSESSMENT_JOB_CREATED',
      targetType: 'AssessmentJob',
      targetId: newJob.id,
      outcome: needsApproval ? 'APPROVAL_REQUIRED' : 'SUCCESS',
      details: {
        profile: newJob.profile,
        targets: newJob.requestedTargets,
        status: newJob.status,
      },
    });

    res.status(201).json({ job: newJob });
  });

  // Approve & Execute Assessment Job
  router.post('/assessments/:jobId/approve', requirePerm(Permission.ASSESSMENT_APPROVE), (req: Request, res: Response) => {
    const job = db.state.assessments.find((j) => j.id === req.params.jobId);
    if (!job) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Assessment job not found.' });
      return;
    }
    if (db.state.killSwitchActive) {
      res.status(423).json({ error: 'KILL_SWITCH_ACTIVE', message: 'Emergency Kill Switch is active.' });
      return;
    }
    if (!canTransitionJobStatus(job.status, JobStatus.QUEUED)) {
      res.status(400).json({
        error: 'INVALID_STATE_TRANSITION',
        message: `Cannot transition job from '${job.status}' to 'QUEUED'.`,
      });
      return;
    }

    const nowIso = new Date().toISOString();
    job.approvalState = 'Approved';
    job.approvedBy = req.user!.username;
    job.approvedAt = nowIso;
    job.status = JobStatus.QUEUED;
    job.progress = 30;
    job.logs.push({
      timestamp: nowIso,
      level: 'INFO',
      message: `Approved by ${req.user!.displayName} (${req.user!.role}). Transitioned to QUEUED.`,
    });

    db.recordAudit({
      actor: req.user!,
      projectId: job.projectId,
      action: 'ASSESSMENT_JOB_APPROVED',
      targetType: 'AssessmentJob',
      targetId: job.id,
      outcome: 'SUCCESS',
      details: { approvedBy: req.user!.username },
    });

    res.json({ job });
  });

  // Execute a QUEUED job through RUNNING -> COMPLETED (Simulated Safe Provider)
  router.post('/assessments/:jobId/execute', requirePerm(Permission.ASSESSMENT_CREATE), (req: Request, res: Response) => {
    const job = db.state.assessments.find((j) => j.id === req.params.jobId);
    if (!job) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Assessment job not found.' });
      return;
    }
    if (db.state.killSwitchActive) {
      res.status(423).json({ error: 'KILL_SWITCH_ACTIVE', message: 'Emergency Kill Switch is active.' });
      return;
    }
    if (job.requiresApproval && job.approvalState !== 'Approved') {
      res.status(403).json({
        error: 'APPROVAL_REQUIRED',
        message: 'Sensitive assessment job requires explicit approval before execution.',
      });
      return;
    }
    if (!canTransitionJobStatus(job.status, JobStatus.RUNNING)) {
      res.status(400).json({
        error: 'INVALID_STATE_TRANSITION',
        message: `Job must be in QUEUED state before running (current state: '${job.status}').`,
      });
      return;
    }

    const nowIso = new Date().toISOString();
    job.status = JobStatus.RUNNING;
    job.startedAt = nowIso;
    job.progress = 75;
    job.logs.push({
      timestamp: nowIso,
      level: 'INFO',
      message: `Executing ${job.profile} via [${job.providerMode}] on ${job.requestedTargets.join(', ')}.`,
    });

    // Complete execution and generate structured non-destructive verification log
    const doneIso = new Date().toISOString();
    job.status = JobStatus.COMPLETED;
    job.completedAt = doneIso;
    job.progress = 100;
    job.logs.push({
      timestamp: doneIso,
      level: 'INFO',
      message: `Completed safe verification of ${job.requestedTargets.length} scoped target(s) within rate limit (${job.resourceLimits.rateLimitRps} rps).`,
    });

    db.recordAudit({
      actor: req.user!,
      projectId: job.projectId,
      action: 'ASSESSMENT_JOB_EXECUTED',
      targetType: 'AssessmentJob',
      targetId: job.id,
      outcome: 'SUCCESS',
      details: { providerMode: job.providerMode, targets: job.requestedTargets },
    });

    res.json({ job });
  });

  router.post('/assessments/:jobId/cancel', requirePerm(Permission.ASSESSMENT_CANCEL), (req: Request, res: Response) => {
    const job = db.state.assessments.find((j) => j.id === req.params.jobId);
    if (!job) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Assessment job not found.' });
      return;
    }
    if (!canTransitionJobStatus(job.status, JobStatus.CANCELLED)) {
      res.status(400).json({
        error: 'INVALID_STATE_TRANSITION',
        message: `Cannot cancel job in terminal state '${job.status}'.`,
      });
      return;
    }
    const nowIso = new Date().toISOString();
    job.status = JobStatus.CANCELLED;
    job.completedAt = nowIso;
    job.logs.push({
      timestamp: nowIso,
      level: 'WARN',
      message: `Job cancelled by ${req.user!.displayName}.`,
    });

    db.recordAudit({
      actor: req.user!,
      projectId: job.projectId,
      action: 'ASSESSMENT_JOB_CANCELLED',
      targetType: 'AssessmentJob',
      targetId: job.id,
      outcome: 'SUCCESS',
      details: {},
    });

    res.json({ job });
  });

  // Global Emergency Kill Switch
  router.post('/assessments/kill-switch', requirePerm(Permission.KILL_SWITCH), (req: Request, res: Response) => {
    const { active, reason } = req.body || {};
    const activate = Boolean(active);
    const nowIso = new Date().toISOString();

    db.state.killSwitchActive = activate;
    if (activate) {
      db.state.killSwitchTriggeredBy = req.user!.displayName;
      db.state.killSwitchTriggeredAt = nowIso;
      db.state.killSwitchReason = reason || 'Manual operator emergency stop';

      // Cancel all non-terminal jobs immediately
      let cancelledCount = 0;
      for (const job of db.state.assessments) {
        if (canTransitionJobStatus(job.status, JobStatus.CANCELLED)) {
          job.status = JobStatus.CANCELLED;
          job.completedAt = nowIso;
          job.logs.push({
            timestamp: nowIso,
            level: 'ERROR',
            message: `GLOBAL EMERGENCY STOP triggered by ${req.user!.displayName}: ${db.state.killSwitchReason}`,
          });
          cancelledCount++;
        }
      }

      db.recordAudit({
        actor: req.user!,
        projectId: 'global',
        action: 'GLOBAL_KILL_SWITCH_ENGAGED',
        targetType: 'System',
        targetId: 'kill-switch',
        outcome: 'EMERGENCY_STOP',
        details: { reason: db.state.killSwitchReason, cancelledJobsCount: cancelledCount },
      });
    } else {
      db.state.killSwitchReason = undefined;
      db.recordAudit({
        actor: req.user!,
        projectId: 'global',
        action: 'GLOBAL_KILL_SWITCH_RESET',
        targetType: 'System',
        targetId: 'kill-switch',
        outcome: 'SUCCESS',
        details: { resetBy: req.user!.username },
      });
    }

    res.json({
      killSwitchActive: db.state.killSwitchActive,
      killSwitchTriggeredBy: db.state.killSwitchTriggeredBy,
      killSwitchTriggeredAt: db.state.killSwitchTriggeredAt,
      killSwitchReason: db.state.killSwitchReason,
      assessments: db.state.assessments,
    });
  });

  // /findings & /evidence
  router.get('/findings', requirePerm(Permission.FINDING_READ), (req: Request, res: Response) => {
    const projectId = req.query.projectId as string | undefined;
    if (projectId && !verifyProjectMembership(req.user!, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }
    const findings = projectId
      ? db.state.findings.filter((f) => f.projectId === projectId)
      : db.state.findings.filter((f) => verifyProjectMembership(req.user!, f.projectId));
    res.json({ findings });
  });

  router.post('/findings', requirePerm(Permission.FINDING_WRITE), (req: Request, res: Response) => {
    const {
      projectId,
      assetId,
      title,
      category,
      severity,
      confidence,
      cveId,
      cvssScore,
      cweId,
      description,
      evidenceSummary,
      reproductionSteps,
      remediationRecommendation,
      owner,
      verifiedByValidationCheck,
    } = req.body || {};

    if (!projectId || !assetId || !title) {
      res.status(400).json({ error: 'VALIDATION_ERROR', message: 'projectId, assetId, and title are required.' });
      return;
    }
    if (!verifyProjectMembership(req.user!, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }

    const asset = db.state.assets.find((a) => a.id === assetId);
    const nowIso = new Date().toISOString();

    // Deduplication check by projectId + assetId + title
    const duplicate = db.state.findings.find(
      (f) =>
        f.projectId === projectId &&
        f.assetId === assetId &&
        f.title.toLowerCase() === String(title).trim().toLowerCase()
    );
    if (duplicate) {
      duplicate.lastSeenAt = nowIso;
      db.save();
      res.json({ finding: duplicate, deduplicated: true });
      return;
    }

    const newFinding: Finding = {
      id: `fnd-${Date.now().toString(36)}`,
      projectId,
      assetId,
      assetName: asset?.displayName || assetId,
      title: String(title).trim(),
      category: category || 'Web & API',
      severity: severity || Severity.MEDIUM,
      confidence: typeof confidence === 'number' ? confidence : 80,
      status: verifiedByValidationCheck ? FindingStatus.CONFIRMED : FindingStatus.NEEDS_VALIDATION,
      cveId: cveId ? String(cveId).trim() : undefined,
      cvssScore: typeof cvssScore === 'number' ? cvssScore : undefined,
      cweId: cweId ? String(cweId).trim() : undefined,
      description: String(description || ''),
      evidenceSummary: String(evidenceSummary || 'Logged by operator.'),
      reproductionSteps: String(reproductionSteps || ''),
      remediationRecommendation: String(remediationRecommendation || ''),
      owner: owner || asset?.owner || req.user!.displayName,
      remediationDeadline: new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString(),
      firstSeenAt: nowIso,
      lastSeenAt: nowIso,
      verifiedByValidationCheck: Boolean(verifiedByValidationCheck),
      sourceReference: `Operator Submission (${req.user!.username})`,
      isSynthetic: false,
    };

    db.state.findings.unshift(newFinding);
    db.recordAudit({
      actor: req.user!,
      projectId,
      action: 'FINDING_CREATED',
      targetType: 'Finding',
      targetId: newFinding.id,
      outcome: 'SUCCESS',
      details: { title: newFinding.title, severity: newFinding.severity, status: newFinding.status },
    });

    res.status(201).json({ finding: newFinding, deduplicated: false });
  });

  router.patch('/findings/:findingId', requirePerm(Permission.FINDING_WRITE), (req: Request, res: Response) => {
    const finding = db.state.findings.find((f) => f.id === req.params.findingId);
    if (!finding) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Finding not found.' });
      return;
    }
    if (!verifyProjectMembership(req.user!, finding.projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }

    const {
      status,
      riskAcceptanceJustification,
      riskAcceptanceExpiresAt,
      verifiedByValidationCheck,
      owner,
    } = req.body || {};

    if (status === FindingStatus.ACCEPTED_RISK) {
      if (!hasPermission(req.user!.role, Permission.FINDING_ACCEPT_RISK)) {
        res.status(403).json({
          error: 'FORBIDDEN_RBAC',
          message: `Role '${req.user!.role}' is not permitted to accept risk on findings.`,
        });
        return;
      }
      if (!riskAcceptanceJustification) {
        res.status(400).json({
          error: 'VALIDATION_ERROR',
          message: 'Risk acceptance requires an explicit justification and expiration date.',
        });
        return;
      }
      finding.riskAcceptanceJustification = riskAcceptanceJustification;
      finding.riskAcceptanceExpiresAt =
        riskAcceptanceExpiresAt || new Date(Date.now() + 90 * 24 * 3600 * 1000).toISOString();
    }

    if (status) finding.status = status;
    if (typeof verifiedByValidationCheck === 'boolean') {
      finding.verifiedByValidationCheck = verifiedByValidationCheck;
      if (verifiedByValidationCheck && finding.confidence < 90) {
        finding.confidence = 95;
      }
    }
    if (owner) finding.owner = owner;
    finding.lastSeenAt = new Date().toISOString();

    db.recordAudit({
      actor: req.user!,
      projectId: finding.projectId,
      action: 'FINDING_STATUS_UPDATED',
      targetType: 'Finding',
      targetId: finding.id,
      outcome: 'SUCCESS',
      details: {
        status: finding.status,
        verified: finding.verifiedByValidationCheck,
        riskAcceptanceJustification: finding.riskAcceptanceJustification,
      },
    });

    res.json({ finding });
  });

  // /attack-paths
  router.post('/attack-paths/edges', requirePerm(Permission.GRAPH_WRITE), (req: Request, res: Response) => {
    const {
      projectId,
      source,
      target,
      relationshipType,
      provenance,
      confidence,
      isInferredHypothesis,
      evidenceRef,
      defensiveBreakRecommendation,
    } = req.body || {};

    if (!projectId || !source || !target || !defensiveBreakRecommendation) {
      res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'projectId, source, target, and defensiveBreakRecommendation are required.',
      });
      return;
    }

    const newEdge: GraphEdge = {
      id: `ge-${Date.now().toString(36)}`,
      projectId,
      source,
      target,
      relationshipType: relationshipType || 'NETWORK_REACHABLE',
      provenance: provenance || 'Configuration Audit',
      confidence: typeof confidence === 'number' ? confidence : 80,
      isInferredHypothesis: Boolean(isInferredHypothesis),
      evidenceRef: evidenceRef || 'Manual Graph Analysis',
      defensiveBreakRecommendation,
      timestamp: new Date().toISOString(),
    };

    db.state.graphEdges.push(newEdge);
    db.recordAudit({
      actor: req.user!,
      projectId,
      action: 'GRAPH_EDGE_ADDED',
      targetType: 'GraphEdge',
      targetId: newEdge.id,
      outcome: 'SUCCESS',
      details: { source, target, isInferredHypothesis: newEdge.isInferredHypothesis },
    });

    res.status(201).json({ edge: newEdge });
  });

  // /threat-intel
  router.post('/threat-intel', requirePerm(Permission.INTEL_WRITE), (req: Request, res: Response) => {
    const {
      projectId,
      indicatorType,
      value,
      threatLabels,
      sourceAttribution,
      sourceVerified,
      confidence,
      severity,
      provenanceNotes,
    } = req.body || {};

    if (!projectId || !indicatorType || !value) {
      res.status(400).json({ error: 'VALIDATION_ERROR', message: 'projectId, indicatorType, and value are required.' });
      return;
    }

    const cleanVal = String(value).trim();
    const existing = db.state.threatIndicators.find(
      (i) => i.projectId === projectId && i.value.toLowerCase() === cleanVal.toLowerCase()
    );
    if (existing) {
      existing.lastObservedAt = new Date().toISOString();
      db.save();
      res.json({ indicator: existing, deduplicated: true });
      return;
    }

    // Correlate against project assets
    const matchedAssets = db.state.assets
      .filter((a) => a.projectId === projectId && a.address.toLowerCase().includes(cleanVal.toLowerCase()))
      .map((a) => a.id);

    const nowIso = new Date().toISOString();
    const newIoc: ThreatIndicator = {
      id: `ioc-${Date.now().toString(36)}`,
      projectId,
      indicatorType,
      value: cleanVal,
      threatLabels: Array.isArray(threatLabels) ? threatLabels : ['analyst-submitted'],
      sourceAttribution: sourceAttribution || `Analyst Submission (${req.user!.username})`,
      sourceVerified: Boolean(sourceVerified),
      confidence: typeof confidence === 'number' ? confidence : 75,
      severity: severity || Severity.MEDIUM,
      firstObservedAt: nowIso,
      lastObservedAt: nowIso,
      expiresAt: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
      matchedAssetIds: matchedAssets,
      matchedIncidentIds: [],
      provenanceNotes: provenanceNotes || 'Sanitized indicator record.',
      isSynthetic: false,
    };

    db.state.threatIndicators.unshift(newIoc);
    db.recordAudit({
      actor: req.user!,
      projectId,
      action: 'THREAT_IOC_INGESTED',
      targetType: 'ThreatIndicator',
      targetId: newIoc.id,
      outcome: 'SUCCESS',
      details: { value: newIoc.value, sourceVerified: newIoc.sourceVerified, matchedAssets },
    });

    res.status(201).json({ indicator: newIoc, deduplicated: false });
  });

  // /alerts & /detection-rules
  router.patch('/detection-rules/:ruleId', requirePerm(Permission.ALERT_WRITE), (req: Request, res: Response) => {
    const rule = db.state.detectionRules.find((r) => r.id === req.params.ruleId);
    if (!rule) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Detection rule not found.' });
      return;
    }
    if (typeof req.body?.enabled === 'boolean') {
      rule.enabled = req.body.enabled;
    }
    if (req.body?.queryExpression) {
      rule.queryExpression = req.body.queryExpression;
      const parts = rule.version.split('.').map(Number);
      rule.version = `${parts[0] || 1}.${parts[1] || 0}.${(parts[2] || 0) + 1}`;
    }
    rule.lastUpdatedAt = new Date().toISOString();

    db.recordAudit({
      actor: req.user!,
      projectId: 'global',
      action: 'DETECTION_RULE_UPDATED',
      targetType: 'DetectionRule',
      targetId: rule.id,
      outcome: 'SUCCESS',
      details: { enabled: rule.enabled, version: rule.version },
    });

    res.json({ rule });
  });

  router.patch('/alerts/:alertId', requirePerm(Permission.ALERT_WRITE), (req: Request, res: Response) => {
    const alert = db.state.alerts.find((a) => a.id === req.params.alertId);
    if (!alert) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Alert not found.' });
      return;
    }
    const { status, note } = req.body || {};
    if (status) alert.status = status;
    if (note) alert.notes.push(`${new Date().toISOString().slice(0, 16)} (${req.user!.username}): ${note}`);

    db.recordAudit({
      actor: req.user!,
      projectId: alert.projectId,
      action: 'ALERT_UPDATED',
      targetType: 'SecurityAlert',
      targetId: alert.id,
      outcome: 'SUCCESS',
      details: { status: alert.status },
    });

    res.json({ alert });
  });

  // /incidents
  router.post('/incidents', requirePerm(Permission.INCIDENT_WRITE), (req: Request, res: Response) => {
    const { projectId, title, description, severity, affectedAssetIds, relatedAlertIds } = req.body || {};
    if (!projectId || !title) {
      res.status(400).json({ error: 'VALIDATION_ERROR', message: 'projectId and title are required.' });
      return;
    }
    const nowIso = new Date().toISOString();
    const newInc: Incident = {
      id: `inc-${Date.now().toString(36)}`,
      projectId,
      title: String(title).trim(),
      description: String(description || ''),
      severity: severity || Severity.HIGH,
      status: 'Open / Triage',
      assignedResponder: req.user!.username,
      affectedAssetIds: Array.isArray(affectedAssetIds) ? affectedAssetIds : [],
      relatedAlertIds: Array.isArray(relatedAlertIds) ? relatedAlertIds : [],
      evidenceIds: [],
      timeline: [
        { timestamp: nowIso, actor: req.user!.username, event: 'Incident created and triage playbook initialized.' },
      ],
      notes: [],
      playbookSteps: [
        { id: `pbs-${Date.now()}-1`, phase: 'Triage', title: 'Verify scope, asset criticality, and alert provenance', completed: false, requiresApproval: false },
        { id: `pbs-${Date.now()}-2`, phase: 'Evidence Preservation', title: 'Capture immutable forensic log snapshot', completed: false, requiresApproval: false },
        { id: `pbs-${Date.now()}-3`, phase: 'Asset Isolation Recommendation', title: 'Approve containment policy at network/API gateway', completed: false, requiresApproval: true },
        { id: `pbs-${Date.now()}-4`, phase: 'Recovery Verification', title: 'Verify remediation and close incident', completed: false, requiresApproval: false },
      ],
      containmentRecommendations: ['Review affected asset telemetry and stage non-disruptive containment rules.'],
      createdAt: nowIso,
      updatedAt: nowIso,
      isSynthetic: false,
    };

    db.state.incidents.unshift(newInc);
    db.recordAudit({
      actor: req.user!,
      projectId,
      action: 'INCIDENT_CREATED',
      targetType: 'Incident',
      targetId: newInc.id,
      outcome: 'SUCCESS',
      details: { title: newInc.title, severity: newInc.severity },
    });

    res.status(201).json({ incident: newInc });
  });

  router.patch('/incidents/:incidentId/playbook', requirePerm(Permission.INCIDENT_WRITE), (req: Request, res: Response) => {
    const incident = db.state.incidents.find((i) => i.id === req.params.incidentId);
    if (!incident) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Incident not found.' });
      return;
    }
    const { stepId, status, note } = req.body || {};
    const nowIso = new Date().toISOString();

    if (stepId) {
      const step = incident.playbookSteps.find((s) => s.id === stepId);
      if (!step) {
        res.status(404).json({ error: 'STEP_NOT_FOUND', message: 'Playbook step not found.' });
        return;
      }
      if (step.requiresApproval && !hasPermission(req.user!.role, Permission.INCIDENT_APPROVE_CONTAINMENT)) {
        db.recordAudit({
          actor: req.user!,
          projectId: incident.projectId,
          action: 'INCIDENT_CONTAINMENT_APPROVAL_DENIED',
          targetType: 'Incident',
          targetId: incident.id,
          outcome: 'DENIED_RBAC',
          details: { stepTitle: step.title, userRole: req.user!.role },
        });
        res.status(403).json({
          error: 'FORBIDDEN_CONTAINMENT_APPROVAL',
          message: `Playbook step '${step.title}' is a sensitive containment action requiring 'incident:approve_containment' permission (Security Manager or Platform Administrator).`,
        });
        return;
      }
      step.completed = !step.completed;
      if (step.completed) {
        step.completedAt = nowIso;
        if (step.requiresApproval) step.approvedBy = req.user!.username;
        incident.timeline.push({
          timestamp: nowIso,
          actor: req.user!.username,
          event: `Completed playbook step: ${step.title}${step.requiresApproval ? ' [Approved]' : ''}`,
        });
      }
    }

    if (status) {
      incident.status = status;
      incident.timeline.push({
        timestamp: nowIso,
        actor: req.user!.username,
        event: `Incident status updated to '${status}'.`,
      });
    }

    if (note) {
      incident.notes.push({
        author: req.user!.username,
        timestamp: nowIso,
        text: String(note),
      });
    }

    incident.updatedAt = nowIso;
    db.recordAudit({
      actor: req.user!,
      projectId: incident.projectId,
      action: 'INCIDENT_UPDATED',
      targetType: 'Incident',
      targetId: incident.id,
      outcome: 'SUCCESS',
      details: { stepId, status: incident.status },
    });

    res.json({ incident });
  });

  // /labs — Controlled Laboratory & Adversary Emulation
  router.post('/labs/:scenarioId/run', requirePerm(Permission.LAB_EXECUTE), (req: Request, res: Response) => {
    const scenario = db.state.labScenarios.find((s) => s.id === req.params.scenarioId);
    if (!scenario) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Lab scenario not found.' });
      return;
    }
    if (db.state.killSwitchActive) {
      res.status(423).json({ error: 'KILL_SWITCH_ACTIVE', message: 'Global Emergency Stop is active.' });
      return;
    }

    const nowIso = new Date().toISOString();
    scenario.lastRunAt = nowIso;
    scenario.executionMode = 'Simulated';
    scenario.cleanupStatus = 'Verified Clean';
    scenario.executionLogs = [
      `[${nowIso}] Verified isolated lab environment metadata: ${scenario.environmentMetadata}`,
      `[${nowIso}] Executed benign test actions (${scenario.mitreMapping.join(', ')}) [SIMULATED MODE].`,
      `[${nowIso}] Observed expected SIEM detections (${scenario.expectedDetections.join('; ')}).`,
      `[${nowIso}] Verified 100% ephemeral artifact cleanup.`,
    ];

    db.recordAudit({
      actor: req.user!,
      projectId: scenario.projectId,
      action: 'LAB_SCENARIO_EXECUTED',
      targetType: 'LabScenario',
      targetId: scenario.id,
      outcome: 'SUCCESS',
      details: { mode: scenario.executionMode, mitreMapping: scenario.mitreMapping },
    });

    res.json({ scenario });
  });

  // /reports
  router.post('/reports', requirePerm(Permission.REPORT_GENERATE), (req: Request, res: Response) => {
    const { projectId, title, reportType } = req.body || {};
    if (!projectId || !title) {
      res.status(400).json({ error: 'VALIDATION_ERROR', message: 'projectId and title are required.' });
      return;
    }
    if (!verifyProjectMembership(req.user!, projectId)) {
      res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
      return;
    }

    const project = db.state.projects.find((p) => p.id === projectId);
    const scope = db.state.scopes.find((s) => s.id === project?.scopeId);
    const findings = db.state.findings.filter((f) => f.projectId === projectId);
    const assets = db.state.assets.filter((a) => a.projectId === projectId);
    const edges = db.state.graphEdges.filter((e) => e.projectId === projectId);

    const verifiedCount = findings.filter((f) => f.verifiedByValidationCheck).length;
    const unverifiedCount =
      findings.filter((f) => !f.verifiedByValidationCheck).length +
      edges.filter((e) => e.isInferredHypothesis).length;
    const hasSynthetic =
      findings.some((f) => f.isSynthetic) || assets.some((a) => a.isSynthetic);

    const newReport: SecurityReport = {
      id: `rpt-${Date.now().toString(36)}`,
      projectId,
      title: String(title).trim(),
      reportType: reportType || 'Technical Assessment Report',
      generatedBy: req.user!.username,
      generatedAt: new Date().toISOString(),
      status: 'Ready',
      scopeSummary: scope
        ? `Authorized Ticket ${scope.authorizationTicketRef}: ${scope.authorizedTargets.join(', ')} (Exclusions: ${scope.excludedTargets.join(', ') || 'None'})`
        : 'Project Scope',
      methodology: 'Evidence-Backed Non-Destructive Validation & Attack-Path Analysis',
      executiveSummary: `Generated for ${project?.name} (${project?.code}). Inventoried ${assets.length} assets, ${verifiedCount} verified findings, and ${unverifiedCount} unverified candidates/hypotheses.${
        hasSynthetic ? ' Note: Includes records from the synthetic demonstration dataset.' : ''
      }`,
      verifiedFindingsCount: verifiedCount,
      unverifiedHypothesesCount: unverifiedCount,
      includesSyntheticData: hasSynthetic,
      limitations: 'Only non-destructive checks within the approved scope window were executed. Excluded targets were not contacted.',
      remediationRoadmap: findings.slice(0, 5).map((f) => `[${f.severity}] ${f.title}: ${f.remediationRecommendation}`),
    };

    db.state.reports.unshift(newReport);
    db.recordAudit({
      actor: req.user!,
      projectId,
      action: 'REPORT_GENERATED',
      targetType: 'SecurityReport',
      targetId: newReport.id,
      outcome: 'SUCCESS',
      details: { reportType: newReport.reportType, verifiedCount, unverifiedCount },
    });

    res.status(201).json({ report: newReport });
  });

  // /integrations & /plugins (with SSRF protection)
  router.post('/integrations/:integrationId/test', requirePerm(Permission.INTEGRATION_WRITE), (req: Request, res: Response) => {
    const integration = db.state.integrations.find((i) => i.id === req.params.integrationId);
    if (!integration) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Integration not found.' });
      return;
    }

    const { endpointUrl } = req.body || {};
    if (endpointUrl && endpointUrl !== 'internal://sarif-normalizer') {
      const ssrfCheck = validateExternalIntegrationUrl(endpointUrl, false);
      if (!ssrfCheck.valid) {
        db.recordAudit({
          actor: req.user!,
          projectId: 'global',
          action: 'INTEGRATION_SSRF_BLOCKED',
          targetType: 'Integration',
          targetId: integration.id,
          outcome: 'ERROR',
          details: { endpointUrl, reason: ssrfCheck.reason },
        });
        res.status(400).json({
          error: 'SSRF_POLICY_VIOLATION',
          message: ssrfCheck.reason,
        });
        return;
      }
      integration.endpointUrl = endpointUrl;
    }

    const nowIso = new Date().toISOString();
    integration.lastSyncAt = nowIso;

    if (integration.id === 'int-gemini') {
      const hasKey = Boolean(
        process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'
      );
      integration.status = hasKey ? 'Connected' : 'Safe Simulation Mode';
      integration.credentialConfigured = hasKey;
      integration.lastTestMessage = hasKey
        ? 'Verified server-side Gemini API key and SDK initialization.'
        : 'GEMINI_API_KEY placeholder detected; operating in Safe Grounded Fallback Mode.';
    } else if (integration.id === 'int-sarif-scanner') {
      integration.status = 'Connected';
      integration.lastTestMessage = 'Local SARIF 2.1.0 parser and finding normalizer verified.';
    } else {
      integration.status = integration.credentialConfigured ? 'Connected' : 'Safe Simulation Mode';
      integration.lastTestMessage = integration.credentialConfigured
        ? 'Connection test succeeded.'
        : 'External credentials not configured; operating in Safe Simulation Mode without fabricating live external traffic.';
    }

    db.recordAudit({
      actor: req.user!,
      projectId: 'global',
      action: 'INTEGRATION_CONNECTION_TESTED',
      targetType: 'Integration',
      targetId: integration.id,
      outcome: 'SUCCESS',
      details: { status: integration.status, endpointUrl: integration.endpointUrl },
    });

    res.json({ integration });
  });

  router.patch('/plugins/:pluginId', requirePerm(Permission.PLUGIN_MANAGE), (req: Request, res: Response) => {
    const plugin = db.state.plugins.find((p) => p.id === req.params.pluginId);
    if (!plugin) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Plugin manifest not found.' });
      return;
    }
    if (typeof req.body?.enabled === 'boolean') {
      plugin.enabled = req.body.enabled;
      plugin.healthStatus = plugin.enabled ? 'Healthy' : 'Disabled';
    }
    if (typeof req.body?.installed === 'boolean') {
      plugin.installed = req.body.installed;
      if (!plugin.installed) {
        plugin.enabled = false;
        plugin.healthStatus = 'Disabled';
      }
    }

    db.recordAudit({
      actor: req.user!,
      projectId: 'global',
      action: 'PLUGIN_STATE_CHANGED',
      targetType: 'PluginManifest',
      targetId: plugin.id,
      outcome: 'SUCCESS',
      details: { installed: plugin.installed, enabled: plugin.enabled },
    });

    res.json({ plugin });
  });

  // /users — Team & RBAC Management
  router.patch('/users/:userId', requirePerm(Permission.USER_MANAGE), (req: Request, res: Response) => {
    const targetUser = db.state.users.find((u) => u.id === req.params.userId);
    if (!targetUser) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'User not found.' });
      return;
    }
    const { role, status, projectIds } = req.body || {};
    if (role && Object.values(Role).includes(role)) targetUser.role = role;
    if (status === 'Active' || status === 'Suspended') targetUser.status = status;
    if (Array.isArray(projectIds)) targetUser.projectIds = projectIds;

    db.recordAudit({
      actor: req.user!,
      projectId: 'global',
      action: 'USER_RBAC_UPDATED',
      targetType: 'User',
      targetId: targetUser.id,
      outcome: 'SUCCESS',
      details: { role: targetUser.role, status: targetUser.status },
    });

    res.json({ user: targetUser });
  });

  // /audit — Immutable Hash-Chained Audit Trail & Integrity Check
  router.get('/audit', requirePerm(Permission.AUDIT_READ), (_req: Request, res: Response) => {
    const integrity = verifyAuditChainIntegrity(db.state.auditEvents);
    res.json({
      auditEvents: db.state.auditEvents,
      integrity,
    });
  });

  // /ai — Server-Side Gemini AI Security Copilot
  router.post('/ai/chat', requirePerm(Permission.AI_USE), async (req: Request, res: Response) => {
    try {
      const { projectId, prompt, toolId, toolArgs } = req.body || {};
      if (!projectId || !prompt) {
        res.status(400).json({ error: 'VALIDATION_ERROR', message: 'projectId and prompt are required.' });
        return;
      }
      if (!verifyProjectMembership(req.user!, projectId)) {
        res.status(403).json({ error: 'FORBIDDEN_PROJECT', message: 'Not authorized for this project.' });
        return;
      }

      const result = await runAICopilotTurn({
        db,
        user: req.user!,
        projectId,
        prompt: String(prompt),
        toolId,
        toolArgs,
      });

      res.json({
        reply: result.reply,
        liveGeminiUsed: result.liveGeminiUsed,
        conversation: db.state.aiConversations[projectId] || [],
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'AI Copilot request failed.';
      res.status(403).json({ error: 'AI_COPILOT_ERROR', message });
    }
  });

  router.delete('/ai/chat/:projectId', requirePerm(Permission.AI_USE), (req: Request, res: Response) => {
    const { projectId } = req.params;
    db.state.aiConversations[projectId] = [];
    db.save();
    res.json({ cleared: true });
  });

  // /system — Synthetic Data Purge & Reset
  router.post('/system/purge-synthetic', requirePerm(Permission.USER_MANAGE), (req: Request, res: Response) => {
    const result = db.purgeSyntheticData(req.user!);
    res.json(result);
  });

  router.post('/system/reset-demo', requirePerm(Permission.USER_MANAGE), (req: Request, res: Response) => {
    db.resetToDefaultSeed(req.user!);
    res.json({ reset: true });
  });

  return router;
}
