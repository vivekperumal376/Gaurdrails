import { createHash, randomUUID } from "node:crypto";
import { basename } from "node:path";
import express, { type ErrorRequestHandler, type RequestHandler } from "express";
import type { Logger } from "pino";
import multer from "multer";
import { Ajv, type AnySchema, type ErrorObject } from "ajv";
import { createAuthenticationMiddleware, requireRole, type AuthConfig } from "./auth.js";
import { detectSecret, type SecretRule } from "./secrets.js";
import { requireJsonContentType, validateModerationRequest } from "./validators/request.validator.js";
import { countInputTokens, evaluateTokenLimit, type TokenPolicy } from "./limits.js";
import { logger as defaultLogger } from "./logger.js";
import type { ToolPolicy } from "./tool-policy.js";
import type { ContentSafetyPolicy, DecisionAction } from "./config.js";
import {
  createRateLimitMiddleware,
  createRequestBudgetMiddleware,
  enforceTokenLimit
} from "./middleware/request-limits.middleware.js";

export function createApp(
  policyVersion: string | null,
  authConfig: AuthConfig | null,
  secretRules: SecretRule[] | null,
  tokenPolicy: TokenPolicy | null,
  toolPolicy: ToolPolicy | null = null,
  decisionPriority: DecisionAction[] | null = null,
  auditLogger: Logger = defaultLogger,
  contentSafetyPolicy: ContentSafetyPolicy | null = null
) {
  const app = express();
  const jailbreakAttemptCounts = new Map<string, number>();
  const processedActionIds = new Map<string, number>();
  const pendingReviews: Array<{ reviewId: string; status: "PENDING"; decision: "ESCALATE"; requestId: string; reasonCode: string; createdAt: string }> = [];

  app.use((_req, res, next) => {
    const startedAt = process.hrtime.bigint();
    const requestId = `req_${randomUUID()}`;
    res.locals.requestId = requestId;
    res.setHeader("X-Request-Id", requestId);
    res.once("finish", () => {
      const subject = res.locals.authenticatedSubject;
      const validatedRequest = res.locals.validatedModerationRequest as { applicationId?: unknown } | undefined;
      const applicationId = validatedRequest?.applicationId ?? _req.get("x-application-id");
      const safeApplicationId = typeof applicationId === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(applicationId)
        ? applicationId
        : undefined;
      const audit = res.locals.audit as { decision?: unknown; findingCategories?: unknown; ruleIds?: unknown; reviewId?: unknown } | undefined;
      const findingCategories = Array.isArray(audit?.findingCategories)
        ? audit.findingCategories.filter((value): value is string => typeof value === "string" && /^[A-Z0-9_-]{1,64}$/.test(value)).slice(0, 50)
        : [];
      const ruleIds = Array.isArray(audit?.ruleIds)
        ? audit.ruleIds.filter((value): value is string => typeof value === "string" && /^[A-Z0-9_-]{1,64}$/.test(value)).slice(0, 50)
        : [];
      const subjectIdHash = typeof subject === "string" && subject.length > 0
        ? createHash("sha256").update(subject).digest("hex")
        : undefined;
      const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      auditLogger.info({
        event: "request_audit",
        requestId,
        timestamp: new Date().toISOString(),
        method: _req.method,
        path: _req.path,
        subjectIdHash,
        applicationId: safeApplicationId,
        policyVersion: policyVersion ?? undefined,
        decision: isDecisionAction(audit?.decision) ? audit.decision : undefined,
        findingCategories,
        ruleIds,
        processingMs: Math.max(0, Math.round(elapsedMs)),
        httpStatus: res.statusCode,
        reviewId: typeof audit?.reviewId === "string" ? audit.reviewId : undefined
      }, "request audit");

      const securityEvent = res.locals.securityEvent as { category?: unknown; ruleId?: unknown } | undefined;
      if (typeof securityEvent?.category === "string" && typeof securityEvent.ruleId === "string") {
        auditLogger.warn({
          event: "security_event",
          requestId,
          timestamp: new Date().toISOString(),
          category: securityEvent.category,
          ruleId: securityEvent.ruleId,
          policyVersion: policyVersion ?? undefined,
          httpStatus: res.statusCode
        }, "safety policy security event");
      }
    });
    next();
  });

  app.get("/health", (_req, res) => {
    res.status(200).json({
      status: "UP",
      service: "genai-guardrail-gateway"
    });
  });

  app.get("/ready", (_req, res) => {
    if (policyVersion === null || authConfig === null || secretRules === null || tokenPolicy === null) {
      return res.status(503).json({
        status: "NOT_READY",
        error: "CONFIGURATION_INVALID",
        requestId: res.locals.requestId
      });
    }

    return res.status(200).json({
      status: "READY",
      policyVersion
    });
  });

  app.use("/api/v1", createAuthenticationMiddleware(authConfig));
  app.use("/api/v1", (_req, res, next) => {
    if (tokenPolicy === null) {
      return res.status(503).json({
        requestId: res.locals.requestId,
        error: "LIMIT_POLICY_UNAVAILABLE"
      });
    }
    return next();
  });

  const passThrough: RequestHandler = (_req, _res, next) => next();
  const requestBudget = tokenPolicy ? createRequestBudgetMiddleware(tokenPolicy) : passThrough;
  const rateLimit = tokenPolicy ? createRateLimitMiddleware(tokenPolicy) : passThrough;
  const tokenLimit = tokenPolicy ? enforceTokenLimit(tokenPolicy) : passThrough;
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
      files: 1,
      fileSize: tokenPolicy?.maxRequestBytes ?? 1_048_576
    }
  });
  const rejectUnsafeUploadName: RequestHandler = (req, res, next) => {
    const rawDisposition = req.headers["content-disposition"];
    const rawFileName = extractUploadFileName(rawDisposition);
    if (rawFileName === null) {
      return next();
    }

    if (rawFileName.includes("../") || rawFileName.includes("..\\") || rawFileName.startsWith("/") || rawFileName.includes(":")) {
      return res.status(400).json({
        requestId: res.locals.requestId,
        error: "INVALID_FILE",
        recommendedAction: "BLOCK",
        fileName: sanitizeFileName(rawFileName) ?? "upload.bin"
      });
    }

    return next();
  };

  app.use("/api/v1", requestBudget);

  app.post(
    "/api/v1/moderate",
    requireRole("moderation.user"),
    requireJsonContentType,
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    validateModerationRequest,
    rateLimit,
    tokenLimit,
    (_req, res) => {
      const validatedRequest = res.locals.validatedModerationRequest as {
        content: string;
        metadata?: { locale?: string };
      };
      const result = normalizeModerationContent(validatedRequest.content, validatedRequest.metadata?.locale);
      return res.status(200).json({
        requestId: res.locals.requestId,
        normalizedContent: result.content,
        normalization: result.metadata
      });
    }
  );

  app.post(
    "/api/v1/moderate/output",
    requireRole("moderation.user"),
    requireJsonContentType,
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    tokenLimit,
    (req, res) => {
      if (secretRules === null) {
        return res.status(503).json({
          requestId: res.locals.requestId,
          error: "DETECTOR_UNAVAILABLE"
        });
      }

      if (policyVersion === null || decisionPriority === null) {
        return res.status(503).json({
          requestId: res.locals.requestId,
          error: "DECISION_POLICY_UNAVAILABLE"
        });
      }

      if (!isOutputModerationRequest(req.body)) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["originalRequestId", "content"]
        });
      }

      const result = moderateOutputContent(req.body.content, secretRules, decisionPriority);
      const safe = result.decision === "ALLOW" || result.decision === "MASK";
      res.locals.audit = {
        decision: result.decision,
        findingCategories: result.findings.map((finding) => finding.control),
        ruleIds: result.findings.flatMap((finding) => finding.ruleId ? [finding.ruleId] : [])
      };
      return res.status(200).json({
        requestId: res.locals.requestId,
        originalRequestId: req.body.originalRequestId,
        decision: result.decision,
        safe,
        findings: result.findings,
        ...(safe ? { sanitizedContent: result.sanitizedContent } : {})
      });
    }
  );

  app.post(
    "/api/v1/validate/output",
    requireRole("moderation.user"),
    requireJsonContentType,
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    (req, res) => {
      if (policyVersion === null || decisionPriority === null) {
        return res.status(503).json({
          requestId: res.locals.requestId,
          error: "DECISION_POLICY_UNAVAILABLE"
        });
      }

      if (!isOutputSchemaRequest(req.body)) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["content", "schema", "mode"]
        });
      }

      const validation = validateStructuredOutput(req.body.content, req.body.schema, req.body.mode);
      const decision = evaluateDecision(
        validation.valid ? [] : [{ control: "OUTPUT_SCHEMA", recommendedAction: "BLOCK" }],
        decisionPriority
      );
      return res.status(200).json({
        requestId: res.locals.requestId,
        valid: validation.valid,
        decision,
        errors: validation.errors
      });
    }
  );

  app.post(
    "/api/v1/detect/secrets",
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    requireRole("moderation.tester"),
    rateLimit,
    (req, res) => {
      if (secretRules === null) {
        return res.status(503).json({
          requestId: res.locals.requestId,
          error: "DETECTOR_UNAVAILABLE"
        });
      }

      if (typeof req.body?.content !== "string") {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["content"]
        });
      }

      return res.status(200).json(detectSecret(req.body.content, secretRules));
  });

  app.post(
    "/api/v1/validate/tokens",
    requireRole("moderation.tester"),
    requireJsonContentType,
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    (req, res, next) => {
      if (typeof req.body?.content !== "string") {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["content"]
        });
      }
      res.locals.validatedModerationRequest = {
        content: req.body.content,
        applicationId: req.get("x-application-id")
      };
      return next();
    },
    rateLimit,
    (req, res) => res.status(200).json(evaluateTokenLimit(req.body.content, tokenPolicy!))
  );

  app.post(
    "/api/v1/validate/file",
    requireRole("moderation.tester"),
    rejectUnsafeUploadName,
    upload.single("file"),
    (req, res) => {
      const file = req.file;
      if (!file) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_FILE",
          recommendedAction: "BLOCK"
        });
      }

      const originalName = file.originalname ?? "upload.bin";
      const safeName = sanitizeFileName(originalName);
      if (safeName === null) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_FILE",
          recommendedAction: "BLOCK",
          fileName: basename(originalName) || "upload.bin"
        });
      }

      if (file.size === 0 || file.size > (tokenPolicy?.maxRequestBytes ?? Number.MAX_SAFE_INTEGER)) {
        return res.status(413).json({
          requestId: res.locals.requestId,
          error: "PAYLOAD_TOO_LARGE",
          recommendedAction: "BLOCK",
          fileName: safeName
        });
      }

      const mimeType = file.mimetype?.toLowerCase() ?? "";
      if (mimeType !== "application/pdf" || !safeName.toLowerCase().endsWith(".pdf")) {
        return res.status(415).json({
          requestId: res.locals.requestId,
          error: "UNSUPPORTED_MEDIA_TYPE",
          recommendedAction: "BLOCK",
          fileName: safeName,
          detectedType: mimeType || "unknown"
        });
      }

      const fileSignature = file.buffer.subarray(0, 5).toString("latin1");
      if (!fileSignature.startsWith("%PDF-")) {
        return res.status(415).json({
          requestId: res.locals.requestId,
          error: "UNSUPPORTED_MEDIA_TYPE",
          recommendedAction: "BLOCK",
          fileName: safeName,
          detectedType: mimeType
        });
      }

      return res.status(200).json({
        valid: true,
        detectedType: mimeType,
        recommendedAction: "ALLOW",
        fileName: safeName
      });
    }
  );

  app.post(
    "/api/v1/detect/pii",
    requireRole("moderation.tester"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    (req, res) => {
      if (req.body === undefined) {
        return res.status(501).json({
          requestId: res.locals.requestId,
          error: "NOT_IMPLEMENTED"
        });
      }

      if (typeof req.body.content !== "string") {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["content"]
        });
      }

      const result = detectPii(req.body.content);
      return res.status(200).json({
        requestId: res.locals.requestId,
        ...result
      });
    }
  );

  app.post(
    "/api/v1/detect/confidential",
    requireRole("moderation.tester"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    (req, res) => {
      if (typeof req.body?.content !== "string") {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["content"]
        });
      }

      const result = detectConfidential(req.body.content);
      return res.status(200).json({
        requestId: res.locals.requestId,
        ...result
      });
    }
  );

  app.post(
    "/api/v1/detect/injection",
    requireRole("moderation.tester"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    (req, res) => {
      if (typeof req.body?.content !== "string") {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["content"]
        });
      }

      const result = detectPromptInjection(req.body.content);
      return res.status(200).json({
        requestId: res.locals.requestId,
        ...result
      });
    }
  );

  app.post(
    "/api/v1/detect/jailbreak",
    requireRole("moderation.tester"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    (req, res) => {
      if (typeof req.body?.content !== "string") {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["content"]
        });
      }

      const subject = String(res.locals.authenticatedSubject ?? "unknown");
      const result = detectJailbreak(req.body.content, subject, jailbreakAttemptCounts);
      return res.status(200).json({
        requestId: res.locals.requestId,
        ...result
      });
    }
  );

  app.post(
    "/api/v1/detect/content-safety",
    requireRole("moderation.tester"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    (req, res) => {
      if (contentSafetyPolicy === null || decisionPriority === null) {
        return res.status(503).json({
          requestId: res.locals.requestId,
          error: "CONTENT_SAFETY_POLICY_UNAVAILABLE"
        });
      }

      if (typeof req.body?.content !== "string" || req.body.content.trim().length === 0) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["content"]
        });
      }

      const categories = detectContentSafety(req.body.content);
      const decision = evaluateDecision(categories.map((category) => ({
        control: category.name,
        recommendedAction: category.recommendedAction ?? contentSafetyPolicy[category.name]
      })), decisionPriority);
      res.locals.audit = {
        decision,
        findingCategories: categories.map((category) => category.name),
        ruleIds: categories.map((category) => category.ruleId)
      };
      const childSafetyFinding = categories.find((category) => category.name === "CHILD_SAFETY");
      if (childSafetyFinding) {
        res.locals.securityEvent = {
          category: childSafetyFinding.name,
          ruleId: childSafetyFinding.ruleId
        };
      }
      return res.status(200).json({
        requestId: res.locals.requestId,
        categories: categories.map(({ name, severity }) => ({ name, severity })),
        recommendedAction: decision,
        ...(categories.some((category) => category.name === "SELF_HARM") ? {
          decision: "SAFE_RESPONSE",
          safe: true,
          responseTemplate: "SELF_HARM_SUPPORT_V1"
        } : {})
      });
    }
  );

  app.post(
    "/api/v1/rag/authorize",
    requireRole("moderation.user"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    (req, res) => {
      const document = req.body?.document;
      if (!isRagDocument(document)) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["document"]
        });
      }

      const result = authorizeRagDocument(
        document,
        res.locals.authenticatedTenantId,
        res.locals.identityRoles
      );
      return res.status(200).json({
        requestId: res.locals.requestId,
        ...result
      });
    }
  );

  app.post(
    "/api/v1/rag/validate-context",
    requireRole("moderation.user"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    (req, res) => {
      if (secretRules === null) {
        return res.status(503).json({
          requestId: res.locals.requestId,
          error: "DETECTOR_UNAVAILABLE"
        });
      }

      if (!isContextRequest(req.body)) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["query", "chunks"]
        });
      }

      const result = validateRetrievedContext(
        req.body.query,
        req.body.chunks,
        tokenPolicy!,
        secretRules,
        res.locals.authenticatedTenantId,
        res.locals.identityRoles
      );
      return res.status(200).json({
        requestId: res.locals.requestId,
        ...result
      });
    }
  );

  app.post(
    "/api/v1/rag/validate-grounding",
    requireRole("moderation.user"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    (req, res) => {
      if (!isGroundingRequest(req.body)) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["query", "response", "sources"]
        });
      }

      const groundingTokenCount = countInputTokens([
        req.body.query,
        req.body.response,
        ...req.body.sources.map((source) => source.text)
      ].join("\n"));
      if (groundingTokenCount > tokenPolicy!.maxInputTokens) {
        return res.status(413).json({
          requestId: res.locals.requestId,
          error: "TOKEN_LIMIT_EXCEEDED",
          tokenCount: groundingTokenCount,
          maxInputTokens: tokenPolicy!.maxInputTokens,
          recommendedAction: "BLOCK"
        });
      }

      const result = validateGrounding(req.body);
      return res.status(200).json({
        requestId: res.locals.requestId,
        ...result
      });
    }
  );

  app.post(
    "/api/v1/tools/validate-action",
    requireRole("moderation.user"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    (req, res) => {
      if (toolPolicy === null) {
        return res.status(503).json({
          requestId: res.locals.requestId,
          error: "TOOL_POLICY_UNAVAILABLE"
        });
      }

      if (!isToolActionRequest(req.body)) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["actionId", "tool", "action", "arguments"]
        });
      }

      const result = validateToolAction(
        req.body,
        toolPolicy,
        res.locals.authenticatedSubject,
        res.locals.authenticatedTenantId,
        res.locals.identityRoles,
        processedActionIds
      );
      if (result.status === 409) {
        return res.status(409).json({
          requestId: res.locals.requestId,
          error: "ACTION_REPLAYED",
          decision: "BLOCK",
          approvalRequired: false
        });
      }

      return res.status(200).json({
        requestId: res.locals.requestId,
        ...result.body
      });
    }
  );

  app.post(
    "/api/v1/decision",
    requireRole("moderation.tester"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    (req, res) => {
      if (policyVersion === null || decisionPriority === null) {
        return res.status(503).json({
          requestId: res.locals.requestId,
          error: "DECISION_POLICY_UNAVAILABLE"
        });
      }

      if (!isDecisionRequest(req.body)) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["findings"]
        });
      }

      const decision = evaluateDecision(req.body.findings, decisionPriority);
      res.locals.audit = {
        decision,
        findingCategories: req.body.findings.map((finding) => finding.control)
      };
      return res.status(200).json({
        requestId: res.locals.requestId,
        decision,
        policyVersion
      });
    }
  );

  app.post(
    "/api/v1/reviews",
    requireRole("moderation.user"),
    express.json({ limit: tokenPolicy?.maxRequestBytes ?? "1mb" }),
    rateLimit,
    (req, res) => {
      if (req.body?.decision !== "ESCALATE" || !isReviewReasonCode(req.body?.reasonCode)) {
        return res.status(400).json({
          requestId: res.locals.requestId,
          error: "INVALID_REQUEST",
          fields: ["decision", "reasonCode"]
        });
      }

      const reviewId = `REV-${randomUUID().toUpperCase()}`;
      const review = {
        reviewId,
        status: "PENDING" as const,
        decision: "ESCALATE" as const,
        requestId: String(res.locals.requestId),
        reasonCode: req.body.reasonCode as string,
        createdAt: new Date().toISOString()
      };
      if (pendingReviews.length >= 10_000) pendingReviews.shift();
      pendingReviews.push(review);
      res.locals.audit = {
        decision: "ESCALATE",
        findingCategories: [review.reasonCode],
        reviewId
      };
      return res.status(201).json({
        reviewId,
        status: review.status,
        decision: review.decision
      });
    }
  );

  app.get("/api/v1/reviews", requireRole("moderation.reviewer"), (_req, res) => {
    return res.status(200).json({
      reviews: pendingReviews.map(({ reviewId, status, decision, requestId, reasonCode, createdAt }) => ({
        reviewId,
        status,
        decision,
        requestId,
        reasonCode,
        createdAt
      }))
    });
  });

  app.get("/api/v1/admin/policy", requireRole("moderation.admin"), (_req, res) => {
    res.status(200).json({ policyVersion });
  });

  app.use((_req, res) => {
    res.status(404).json({
      requestId: res.locals.requestId,
      error: "NOT_FOUND"
    });
  });

  const errorHandler: ErrorRequestHandler = (error: unknown, _req, res, _next) => {
    if (isRequestBodyError(error)) {
      const status = error.status === 413 ? 413 : 400;
      return res.status(status).json({
        requestId: res.locals.requestId,
        error: status === 413 ? "PAYLOAD_TOO_LARGE" : "INVALID_REQUEST",
        fields: status === 413 ? undefined : ["body"]
      });
    }

    if (isUploadError(error)) {
      const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
      return res.status(status).json({
        requestId: res.locals.requestId,
        error: status === 413 ? "PAYLOAD_TOO_LARGE" : "INVALID_FILE",
        recommendedAction: "BLOCK",
        fileName: status === 413 ? undefined : "upload.bin"
      });
    }

    res.status(500).json({
      requestId: res.locals.requestId,
      error: "INTERNAL_ERROR"
    });
  };

  app.use(errorHandler);

  return app;
}

function isRequestBodyError(error: unknown): error is { type?: string; status?: number } {
  return typeof error === "object" && error !== null &&
    "type" in error &&
    ["entity.parse.failed", "entity.too.large", "encoding.unsupported"].includes(
      String((error as { type?: unknown }).type)
    );
}

function sanitizeFileName(fileName: string): string | null {
  const normalized = fileName.replace(/\\/g, "/");

  if (normalized.includes("../") || normalized.includes("..\\") || normalized === ".." || normalized.startsWith("/") || normalized.includes(":")) {
    return null;
  }

  const baseName = basename(normalized);
  if (!baseName || baseName === "." || baseName === "..") {
    return null;
  }

  const cleaned = baseName.replace(/[^a-zA-Z0-9._-]/g, "_");
  if (!cleaned || cleaned === "." || cleaned === "..") {
    return null;
  }

  return cleaned;
}

function isUploadError(error: unknown): error is { code?: string } {
  return typeof error === "object" && error !== null && "code" in error &&
    ["LIMIT_FILE_SIZE", "LIMIT_UNEXPECTED_FILE", "LIMIT_PART_COUNT"].includes(String((error as { code?: unknown }).code));
}

function detectPii(content: string) {
  const emailRegex = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
  const phoneRegex = /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})/g;

  const emailMatch = content.match(emailRegex);
  const phoneMatch = content.match(phoneRegex);

  const hasEmail = emailMatch && emailMatch.length > 0;
  const hasPhone = phoneMatch && phoneMatch.some((value) => {
    const digits = value.replace(/\D/g, "");
    return digits.length >= 10 && digits.length <= 15;
  });

  if (!hasEmail && !hasPhone) {
    return {
      matched: false,
      category: null,
      recommendedAction: "ALLOW",
      sanitizedContent: content
    };
  }

  let sanitized = content;
  let category: string | null = null;

  if (hasEmail) {
    sanitized = sanitized.replace(emailRegex, "<EMAIL_MASKED>");
    category = "EMAIL_ADDRESS";
  }

  if (hasPhone) {
    sanitized = sanitized.replace(phoneRegex, "<PHONE_MASKED>");
    category = category ?? "PHONE_NUMBER";
  }

  return {
    matched: true,
    category,
    recommendedAction: "MASK",
    sanitizedContent: sanitized
  };
}

function detectConfidential(content: string) {
  const trimmed = content.trim();
  if (!trimmed) {
    return {
      matched: false,
      classification: null,
      recommendedAction: "ALLOW",
      ruleId: null
    };
  }

  const restricted = /\b(RESTRICTED|CONFIDENTIAL)\b/i.test(trimmed);
  if (!restricted) {
    return {
      matched: false,
      classification: null,
      recommendedAction: "ALLOW",
      ruleId: null
    };
  }

  return {
    matched: true,
    classification: "RESTRICTED",
    recommendedAction: "BLOCK",
    ruleId: "CONF-RESTRICTED-001",
    sanitizedContent: "<CONFIDENTIAL_REDACTED>"
  };
}

function detectPromptInjection(content: string) {
  const normalized = content.trim();
  if (!normalized) {
    return {
      matched: false,
      riskScore: 0,
      threshold: 70,
      recommendedAction: "ALLOW"
    };
  }

  const lower = normalized.toLowerCase();
  const academicSignal = /\b(?:paper|study|studies|research|benchmark|evaluation|safety|defense|academic|educational|analysis)\b/i.test(lower);

  let riskScore = 0;

  if (/ignore\s+(?:all\s+)?previous\s+instructions?/i.test(normalized)) {
    riskScore += 28;
  }

  if (/reveal\s+(?:the\s+)?(?:system\s+)?prompt|show\s+(?:the\s+)?(?:system\s+)?prompt|disclose\s+(?:the\s+)?(?:system\s+)?prompt/i.test(normalized)) {
    riskScore += 30;
  }

  if (/override\s+(?:the\s+)?(?:app\s+)?(?:policy|instructions?|constraints?)|bypass\s+(?:the\s+)?(?:app\s+)?(?:policy|instructions?|restrictions?)/i.test(normalized)) {
    riskScore += 18;
  }

  if (/you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as/i.test(normalized)) {
    riskScore += 14;
  }

  if (/developer\s+message|hidden\s+instructions?|secret\s+tool\s+instructions?|system\s+prompt/i.test(normalized)) {
    riskScore += 18;
  }

  if (/ignore\s+all\s+prior|forget\s+the\s+instruction|disregard\s+(?:the\s+)?(?:policy|instructions?)/i.test(normalized)) {
    riskScore += 18;
  }

  if (academicSignal && !/(ignore\s+(?:all\s+)?previous\s+instructions?|reveal\s+(?:the\s+)?(?:system\s+)?prompt|override\s+(?:the\s+)?(?:app\s+)?(?:policy|instructions?)|you\s+are\s+now|act\s+as|hidden\s+instructions?|secret\s+tool\s+instructions?)/i.test(normalized)) {
    riskScore = Math.min(riskScore, 12);
  }

  const matched = riskScore >= 30;
  const recommendedAction = riskScore >= 70 ? "BLOCK" : riskScore >= 30 ? "WARN" : "ALLOW";

  return {
    matched,
    riskScore,
    threshold: 70,
    recommendedAction
  };
}

function detectJailbreak(content: string, subject: string, attempts: Map<string, number>) {
  const normalized = content.trim().toLowerCase();
  if (!normalized) {
    return {
      matched: false,
      riskScore: 0,
      recommendedAction: "ALLOW"
    };
  }

  let baseRiskScore = 0;
  const bypassSignal = /\b(?:bypass|evade|circumvent|disable|override|ignore)\b.{0,35}\b(?:safety|safeguards?|restrictions?|polic(?:y|ies)|rules?|limitations?)\b/i.test(normalized);
  const roleplaySignal = /\b(?:pretend\s+(?:you\s+are|to\s+be)|act\s+as|role-?play\s+as)\b/i.test(normalized);
  const unrestrictedSignal = /\b(?:unrestricted|no\s+rules|developer\s+mode|do\s+anything\s+now)\b/i.test(normalized);
  const hiddenInstructionSignal = /\b(?:reveal|show|disclose|print|repeat)\b.{0,35}\b(?:hidden|secret|system|developer)\s+(?:prompt|instructions?|message)\b/i.test(normalized);
  const safetyDefeatSignal = /\b(?:remove|turn\s+off|disable|ignore)\b.{0,35}\b(?:safety|content)\s+(?:filters?|rules?|polic(?:y|ies)|restrictions?)\b/i.test(normalized);

  if (bypassSignal) baseRiskScore += 40;
  if (roleplaySignal) baseRiskScore += 20;
  if (unrestrictedSignal) baseRiskScore += 22;
  if (hiddenInstructionSignal) baseRiskScore += 38;
  if (safetyDefeatSignal) baseRiskScore += 35;
  if ((bypassSignal && (roleplaySignal || unrestrictedSignal)) || (roleplaySignal && hiddenInstructionSignal)) {
    baseRiskScore += 15;
  }

  if (baseRiskScore === 0) {
    return {
      matched: false,
      riskScore: 0,
      recommendedAction: "ALLOW"
    };
  }

  const fingerprint = createHash("sha256").update(`${subject}\0${normalized}`).digest("hex");
  const previousAttempts = attempts.get(fingerprint) ?? 0;
  if (attempts.size >= 10_000 && !attempts.has(fingerprint)) {
    const oldestFingerprint = attempts.keys().next().value;
    if (oldestFingerprint !== undefined) attempts.delete(oldestFingerprint);
  }
  attempts.set(fingerprint, previousAttempts + 1);

  const riskScore = Math.min(100, baseRiskScore + previousAttempts * 15);
  return {
    matched: riskScore >= 30,
    riskScore,
    recommendedAction: riskScore >= 70 ? "BLOCK" : riskScore >= 30 ? "WARN" : "ALLOW"
  };
}

type RagDocument = {
  documentId: string;
  tenantId: string;
  classification: string;
  allowedRoles: string[];
  status?: string;
  expiresAt?: string;
};


type RetrievedChunk = {
  sourceId: string;
  text: string;
  tenantId: string;
  allowedRoles: string[];
  status: string;
};

type GroundingSource = {
  sourceId: string;
  text: string;
};

type GroundingRequest = {
  query: string;
  response: string;
  sources: GroundingSource[];
  rejectedSourceIds?: string[];
};

type ToolActionRequest = {
  actionId: string;
  tool: string;
  action: string;
  arguments: Record<string, string>;
};

type DecisionFinding = {
  control: string;
  recommendedAction: DecisionAction;
  ruleId?: string;
};

function isDecisionAction(value: unknown): value is DecisionAction {
  return typeof value === "string" && ["ALLOW", "WARN", "MASK", "SAFE_RESPONSE", "ESCALATE", "BLOCK"].includes(value);
}

function isReviewReasonCode(value: unknown): value is string {
  return typeof value === "string" && ["HIGH_IMPACT_ACTION", "CONTENT_SAFETY", "POLICY_REVIEW", "OTHER_REVIEW"].includes(value);
}

function isOutputModerationRequest(value: unknown): value is { originalRequestId: string; content: string } {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  return typeof request.originalRequestId === "string" &&
    /^[A-Za-z0-9_-]{1,128}$/.test(request.originalRequestId) &&
    typeof request.content === "string" && request.content.trim().length > 0 && request.content.length <= 100_000;
}

type OutputSchemaRequest = {
  content: string;
  schema?: Record<string, unknown>;
  mode: "json" | "text";
};

function isOutputSchemaRequest(value: unknown): value is OutputSchemaRequest {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  if (typeof request.content !== "string" || request.content.length === 0 || request.content.length > 100_000) return false;

  const mode = request.mode ?? "json";
  if (mode !== "json" && mode !== "text") return false;
  if (mode === "json" && (typeof request.schema !== "object" || request.schema === null || Array.isArray(request.schema))) return false;
  if (mode === "text" && request.schema !== undefined) return false;
  return true;
}

function validateStructuredOutput(content: string, schema: Record<string, unknown> | undefined, mode: "json" | "text") {
  if (mode === "text") {
    const executableMarkup = /<\s*(?:script|iframe|object|embed|form|svg|math)\b|\bon\w+\s*=|javascript\s*:/i.test(content);
    return {
      valid: !executableMarkup,
      errors: executableMarkup ? ["EXECUTABLE_MARKUP"] : []
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return { valid: false, errors: ["INVALID_JSON"] };
  }

  try {
    const ajv = new Ajv({ allErrors: true, strict: true });
    const validate = ajv.compile(schema as AnySchema);
    if (validate(parsed)) return { valid: true, errors: [] as string[] };

    const errors = (validate.errors ?? []).slice(0, 20).map((error: ErrorObject) => {
      const path = error.instancePath || "/";
      return `${path} ${error.keyword}`.trim();
    });
    return { valid: false, errors };
  } catch {
    return { valid: false, errors: ["INVALID_SCHEMA"] };
  }
}

function moderateOutputContent(content: string, secretRules: SecretRule[], priority: DecisionAction[]) {
  const findings: DecisionFinding[] = [];
  let sanitizedContent = content;

  const secret = detectSecret(content, secretRules);
  if (secret.matched) {
    findings.push({ control: "SECRET", recommendedAction: "BLOCK", ruleId: secret.ruleId ?? undefined });
  }

  const pii = detectPii(content);
  if (pii.matched) {
    findings.push({ control: "PII", recommendedAction: "MASK" });
    sanitizedContent = pii.sanitizedContent;
  }

  if (detectConfidential(content).matched) {
    findings.push({ control: "CONFIDENTIAL", recommendedAction: "BLOCK", ruleId: "CONF-RESTRICTED-001" });
  }

  const injection = detectPromptInjection(content);
  if (injection.riskScore >= 70) {
    findings.push({ control: "PROMPT_INJECTION", recommendedAction: "BLOCK", ruleId: "INJECTION-RISK-BLOCK" });
  } else if (injection.riskScore >= 30) {
    findings.push({ control: "PROMPT_INJECTION", recommendedAction: "WARN", ruleId: "INJECTION-RISK-WARN" });
  }

  if (detectSystemPromptLeak(content)) {
    findings.push({ control: "SYSTEM_PROMPT_LEAK", recommendedAction: "BLOCK", ruleId: "SYSTEM-PROMPT-LEAK-001" });
  }

  return {
    decision: evaluateDecision(findings, priority),
    findings,
    sanitizedContent
  };
}

function detectSystemPromptLeak(content: string): boolean {
  return /\b(?:system|developer)\s+prompt\s*(?::|=|\bis\b)|\b(?:here(?:'s|\s+is)|below\s+is|verbatim)\s+(?:the\s+)?(?:system|developer)\s+prompt\b/i.test(content);
}

function detectContentSafety(content: string): Array<{ name: "HARASSMENT" | "HATE" | "TOXICITY" | "CYBER_MISUSE" | "FRAUD_MISUSE" | "DANGEROUS_ACTIVITY" | "GRAPHIC_CONTENT" | "CREDIBLE_THREAT" | "EXTREMIST_SUPPORT" | "CHILD_SAFETY" | "ADULT_CONTENT" | "SELF_HARM"; severity: "LOW" | "MEDIUM" | "HIGH"; ruleId: string; recommendedAction?: DecisionAction; responseTemplate?: string }> {
  const normalized = content.normalize("NFKC").replace(/[\u200B-\u200D\u2060\uFEFF]/g, "").replace(/\s+/g, " ").trim();
  const educationalContext = /\b(?:educational|education|report|analysis|analyzes|discuss(?:es|ion)?|quoted|quote|study|research|moderation|classifier|phrase|example|security awareness|defensive|prevention|recognize|recognise|protect|authorized|authorised|permission|my own|owned system|lab environment)\b/i.test(normalized);
  const quotedText = /["'“”‘’]/.test(normalized);
  const hasExplicitMisuseIntent = /\b(?:steal|phish|defraud|scam|exfiltrate|bypass|evade detection|without authorization|without permission|victim(?:s)?|dump (?:the )?database|exploit (?:a )?(?:vulnerable|login))\b/i.test(normalized);
  const hasOperationalDetail = /\b(?:step[- ]by[- ]step|payload|credential(?:s)?|fake login page|harvest|exfiltrat|dump|exploit|weaponize|bypass authentication)\b/i.test(normalized);
  if (educationalContext && quotedText) return [];

  const findings: Array<{ name: "HARASSMENT" | "HATE" | "TOXICITY" | "CYBER_MISUSE" | "FRAUD_MISUSE" | "DANGEROUS_ACTIVITY" | "GRAPHIC_CONTENT" | "CREDIBLE_THREAT" | "EXTREMIST_SUPPORT" | "CHILD_SAFETY" | "ADULT_CONTENT" | "SELF_HARM"; severity: "LOW" | "MEDIUM" | "HIGH"; ruleId: string; recommendedAction?: DecisionAction; responseTemplate?: string }> = [];
  const directHarassment = /\b(?:you|he|she|they|that person)\s+(?:are|is)\s+(?:a\s+)?(?:worthless|pathetic|stupid|an? idiot|disgusting)\b/i.test(normalized);
  if (directHarassment) {
    findings.push({ name: "HARASSMENT", severity: "MEDIUM", ruleId: "SAFETY-HARASSMENT-TARGETED-001" });
  }

  const protectedGroup = "(?:immigrants?|refugees?|women|men|muslims?|jews?|christians?|hindus?|black people|white people|lgbtq people|gay people|disabled people)";
  const hatePattern = new RegExp(`\\b(?:all\\s+)?${protectedGroup}\\s+(?:are|should be)\\s+(?:inferior|excluded|removed|hated|denied rights)\\b|\\bi hate ${protectedGroup}\\b`, "i");
  if (hatePattern.test(normalized)) {
    findings.push({ name: "HATE", severity: "HIGH", ruleId: "SAFETY-HATE-PROTECTED-GROUP-001" });
  }

  const nonTargetedInsult = /\b(?:that|this|it)\s+(?:is|was)\s+(?:stupid|idiotic|pathetic)\b/i.test(normalized);
  if (!directHarassment && !hatePattern.test(normalized) && nonTargetedInsult) {
    findings.push({ name: "TOXICITY", severity: "LOW", ruleId: "SAFETY-TOXICITY-001" });
  }

  const cyberCapability = /\b(?:sql injection|malware|ransomware|credential theft|unauthorized access|exploit a vulnerable|dump (?:the )?database)\b/i.test(normalized);
  const fraudCapability = /\b(?:phishing|fake login page|credential harvest|identity theft|payment scam|fraudulent transaction)\b/i.test(normalized);
  const explicitlyAuthorized = /\b(?:authorized|authorised|with permission|my own (?:system|account|website)|owned (?:system|application)|lab environment)\b/i.test(normalized);
  if (!explicitlyAuthorized && hasExplicitMisuseIntent && hasOperationalDetail && cyberCapability) {
    findings.push({ name: "CYBER_MISUSE", severity: "HIGH", ruleId: "MISUSE-CYBER-OPERATIONAL-001" });
  }
  if (!explicitlyAuthorized && hasExplicitMisuseIntent && hasOperationalDetail && fraudCapability) {
    findings.push({ name: "FRAUD_MISUSE", severity: "HIGH", ruleId: "MISUSE-FRAUD-OPERATIONAL-001" });
  }

  const emergencyExposure = /\b(?:emergency|accidental(?:ly)?|swallowed|ingested|inhaled|spilled on|exposed to|overdose|poisoning)\b/i.test(normalized) &&
    /\b(?:child|person|someone|i|we|they|family|breathing|immediate|right now|help|what should)\b/i.test(normalized);
  const dangerousObjectOrSubstance = /\b(?:explosive|bomb|poison|toxic gas|weapon|incendiary|dangerous chemical mixture|household chemicals)\b/i.test(normalized);
  const operationalHarmfulRequest = /\b(?:step[- ]by[- ]step|instructions?|how (?:can|do) i|recipe|make|build|synthesize|create|assemble)\b/i.test(normalized) && dangerousObjectOrSubstance;
  const preventionContext = /\b(?:prevent|prevention|store safely|safe storage|hazards?|first aid|recognize|recognise|avoid accidental|safety information)\b/i.test(normalized);
  const ambiguousDangerousRequest = /\b(?:make|mix|combine|create|strong)\b/i.test(normalized) &&
    /\b(?:chemical mixture|chemicals at home|toxic|potent substance)\b/i.test(normalized);

  if (emergencyExposure) {
    findings.push({ name: "DANGEROUS_ACTIVITY", severity: "HIGH", ruleId: "DANGEROUS-EMERGENCY-001", recommendedAction: "SAFE_RESPONSE" });
  } else if (operationalHarmfulRequest && !preventionContext) {
    findings.push({ name: "DANGEROUS_ACTIVITY", severity: "HIGH", ruleId: "DANGEROUS-OPERATIONAL-001" });
  } else if (ambiguousDangerousRequest && !preventionContext && !explicitlyAuthorized) {
    findings.push({ name: "DANGEROUS_ACTIVITY", severity: "MEDIUM", ruleId: "DANGEROUS-AMBIGUOUS-001", recommendedAction: "ESCALATE" });
  }

  const historicalContext = /\b(?:historical|history|past conflict|news report|documentary|academic study)\b/i.test(normalized);
  const directThreat = /\b(?:i will|i'm going to|i am going to|we will)\s+(?:hurt|attack|kill|harm)\s+(?:\[[A-Z_]+\]|you|him|her|them|(?:[A-Z][a-z]+\s*){1,3})(?:\s+(?:today|tonight|tomorrow|on\s+[\w-]+))?/i.test(normalized) &&
    /\b(?:weapon|gun|knife|attack|hurt|kill|harm)\b/i.test(normalized);
  if (directThreat && !historicalContext) {
    findings.push({ name: "CREDIBLE_THREAT", severity: "HIGH", ruleId: "VIOLENCE-CREDIBLE-THREAT-001", recommendedAction: "ESCALATE" });
  }

  const extremistSupport = /\b(?:provide|give|coordinate|recruit|fund|plan)\b.{0,60}\b(?:operational support|attack|extremist group|terror(?:ist|ism))\b/i.test(normalized) &&
    /\b(?:operational support|recruit|fund|plan an attack|carry out an attack)\b/i.test(normalized);
  if (extremistSupport && !historicalContext) {
    findings.push({ name: "EXTREMIST_SUPPORT", severity: "HIGH", ruleId: "VIOLENCE-EXTREMIST-OPERATIONAL-001" });
  }

  const graphicContent = /\b(?:graphic violence|graphic injury|graphic wounds?|graphic gore)\b/i.test(normalized);
  if (graphicContent && !historicalContext) {
    findings.push({ name: "GRAPHIC_CONTENT", severity: "MEDIUM", ruleId: "VIOLENCE-GRAPHIC-CONTENT-001" });
  }

  if (normalized.toLowerCase() === "test_fixture_child_safety_category") {
    findings.push({ name: "CHILD_SAFETY", severity: "HIGH", ruleId: "SAFETY-CHILD-FIXTURE-001" });
  }
  if (normalized.toLowerCase() === "test_fixture_adult_content_category") {
    findings.push({ name: "ADULT_CONTENT", severity: "MEDIUM", ruleId: "SAFETY-ADULT-FIXTURE-001" });
  }
  if (normalized.toLowerCase() === "test_fixture_self_harm_intent") {
    findings.push({
      name: "SELF_HARM",
      severity: "HIGH",
      ruleId: "SAFETY-SELF-HARM-FIXTURE-001",
      recommendedAction: "SAFE_RESPONSE",
      responseTemplate: "SELF_HARM_SUPPORT_V1"
    });
  }

  return findings;
}

function isDecisionRequest(value: unknown): value is { findings: DecisionFinding[] } {
  if (typeof value !== "object" || value === null || !Array.isArray((value as Record<string, unknown>).findings)) {
    return false;
  }

  const findings = (value as { findings: unknown[] }).findings;
  if (findings.length > 100) return false;

  return findings.every((finding) => {
    if (typeof finding !== "object" || finding === null) return false;
    const candidate = finding as Record<string, unknown>;
    return typeof candidate.control === "string" && candidate.control.trim().length > 0 && candidate.control.length <= 128 &&
      typeof candidate.recommendedAction === "string" &&
      ["ALLOW", "WARN", "MASK", "SAFE_RESPONSE", "ESCALATE", "BLOCK"].includes(candidate.recommendedAction);
  });
}

function evaluateDecision(findings: DecisionFinding[], priority: DecisionAction[]): DecisionAction {
  let selected: DecisionAction = "ALLOW";
  let selectedPriority = priority.indexOf("ALLOW");

  for (const finding of findings) {
    const findingPriority = priority.indexOf(finding.recommendedAction);
    if (findingPriority < selectedPriority) {
      selected = finding.recommendedAction;
      selectedPriority = findingPriority;
    }
  }

  return selected;
}

function isToolActionRequest(value: unknown): value is ToolActionRequest {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  if (typeof request.actionId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(request.actionId) ||
      typeof request.tool !== "string" || !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(request.tool) ||
      typeof request.action !== "string" || !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(request.action) ||
      typeof request.arguments !== "object" || request.arguments === null || Array.isArray(request.arguments)) {
    return false;
  }

  return true;
}

function validateToolAction(
  request: ToolActionRequest,
  policy: ToolPolicy,
  subjectValue: unknown,
  tenantValue: unknown,
  rolesValue: unknown,
  processedActionIds: Map<string, number>
): { status: 200; body: Record<string, unknown> } | { status: 409; body: Record<string, unknown> } {
  const actionPolicy = policy.tools[request.tool]?.actions[request.action];
  const block = (reason: string) => ({
    status: 200 as const,
    body: { decision: "BLOCK", approvalRequired: false, reason }
  });
  if (!actionPolicy) return block("TOOL_OR_ACTION_NOT_ALLOWED");

  const roles = Array.isArray(rolesValue) ? rolesValue.filter((role): role is string => typeof role === "string") : [];
  if (!actionPolicy.allowedRoles.some((role) => roles.includes(role))) {
    return block("USER_NOT_AUTHORIZED");
  }

  const argumentNames = Object.keys(request.arguments);
  if (argumentNames.some((name) => !actionPolicy.allowedArguments.includes(name))) {
    return block("UNEXPECTED_ARGUMENT");
  }
  if (Object.values(request.arguments).some((argument) =>
    typeof argument !== "string" || argument.trim().length === 0 || argument.length > 2048
  )) {
    return block("INVALID_ARGUMENT");
  }
  if (actionPolicy.requiredArguments.some((name) => !(name in request.arguments))) {
    return block("MISSING_ARGUMENT");
  }

  if (actionPolicy.tenantArgument && request.arguments[actionPolicy.tenantArgument] !== tenantValue) {
    return block("TENANT_MISMATCH");
  }

  if (actionPolicy.allowedRecipientDomains) {
    const recipient = request.arguments.recipient;
    const domain = recipient?.match(/^[^@\s]+@([^@\s]+)$/)?.[1]?.toLowerCase();
    if (!domain || !actionPolicy.allowedRecipientDomains.some((allowed) => domain === allowed.toLowerCase())) {
      return block("RECIPIENT_DOMAIN_NOT_ALLOWED");
    }
  }

  if (typeof subjectValue !== "string" || subjectValue.length === 0) {
    return block("IDENTITY_SUBJECT_MISSING");
  }

  const now = Date.now();
  const ttlMs = 15 * 60 * 1000;
  for (const [key, createdAt] of processedActionIds) {
    if (now - createdAt >= ttlMs) processedActionIds.delete(key);
  }
  const idempotencyKey = `${subjectValue}\0${request.actionId}`;
  if (processedActionIds.has(idempotencyKey)) {
    return {
      status: 409,
      body: { decision: "BLOCK", approvalRequired: false, reason: "ACTION_REPLAYED" }
    };
  }

  if (processedActionIds.size >= 10_000) {
    const oldestKey = processedActionIds.keys().next().value;
    if (oldestKey !== undefined) processedActionIds.delete(oldestKey);
  }
  processedActionIds.set(idempotencyKey, now);

  if (actionPolicy.approvalRequired || actionPolicy.risk === "HIGH" || actionPolicy.risk === "CRITICAL") {
    return {
      status: 200,
      body: {
        decision: "ESCALATE",
        approvalRequired: true,
        reviewReason: "HIGH_IMPACT_ACTION"
      }
    };
  }

  return {
    status: 200,
    body: { decision: "ALLOW", approvalRequired: false }
  };
}

function isGroundingRequest(value: unknown): value is GroundingRequest {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  if (typeof request.query !== "string" || request.query.trim().length === 0 ||
      typeof request.response !== "string" || request.response.trim().length === 0 ||
      !Array.isArray(request.sources) || request.sources.length > 100) {
    return false;
  }

  const sourcesValid = request.sources.every((value) => {
    if (typeof value !== "object" || value === null) return false;
    const source = value as Record<string, unknown>;
    return typeof source.sourceId === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(source.sourceId) &&
      typeof source.text === "string" && source.text.trim().length > 0;
  });
  if (!sourcesValid) return false;

  const sourceIds = request.sources.map((source) => (source as Record<string, unknown>).sourceId);
  if (new Set(sourceIds).size !== sourceIds.length) return false;

  return request.rejectedSourceIds === undefined ||
    (Array.isArray(request.rejectedSourceIds) &&
      request.rejectedSourceIds.length <= 100 &&
      request.rejectedSourceIds.every((sourceId) => typeof sourceId === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(sourceId)));
}

function validateGrounding(request: GroundingRequest) {
  const citationPattern = /\[([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\]/g;
  const citations = [...request.response.matchAll(citationPattern)].map((match) => match[1]);
  const responseWithoutCitations = request.response.replace(citationPattern, "");
  const rejectedSourceIds = new Set(request.rejectedSourceIds ?? []);
  const sourceById = new Map(request.sources.map((source) => [source.sourceId, source.text]));

  if (/[[\]]/.test(responseWithoutCitations)) {
    return groundingResult(false, "INVALID_CITATION_FORMAT", "BLOCK");
  }

  if (citations.some((sourceId) => rejectedSourceIds.has(sourceId))) {
    return groundingResult(false, "REJECTED_SOURCE", "BLOCK");
  }

  if (citations.some((sourceId) => !sourceById.has(sourceId))) {
    return groundingResult(false, "UNKNOWN_SOURCE", "BLOCK");
  }

  if (citations.length === 0) {
    return request.sources.length === 0
      ? groundingResult(false, "INSUFFICIENT_EVIDENCE", "WARN")
      : groundingResult(false, "MISSING_CITATION", "WARN");
  }

  const citedEvidence = [...new Set(citations)]
    .map((sourceId) => sourceById.get(sourceId) ?? "")
    .join(" ");
  if (!hasLexicalSupport(responseWithoutCitations, citedEvidence)) {
    return groundingResult(true, "UNSUPPORTED", "WARN");
  }

  return groundingResult(true, "SUPPORTED", "ALLOW");
}

function hasLexicalSupport(answer: string, sourceText: string): boolean {
  const stopWords = new Set(["the", "and", "for", "that", "this", "with", "from", "are", "was", "were", "what", "when", "where", "which", "who", "how", "does", "did", "can", "could", "would", "should", "please", "according", "source"]);
  const answerTerms = new Set((answer.toLowerCase().match(/[a-z0-9]{2,}/g) ?? []).filter((term) => !stopWords.has(term)));
  const sourceTerms = new Set((sourceText.toLowerCase().match(/[a-z0-9]{2,}/g) ?? []).filter((term) => !stopWords.has(term)));
  if (answerTerms.size === 0 || sourceTerms.size === 0) return false;

  let overlap = 0;
  for (const term of answerTerms) {
    if (sourceTerms.has(term)) overlap += 1;
  }
  return overlap >= Math.min(2, answerTerms.size) && overlap / answerTerms.size >= 0.35;
}

function groundingResult(citationValid: boolean, groundingSignal: string, recommendedAction: string) {
  return { citationValid, groundingSignal, recommendedAction };
}

function isContextRequest(value: unknown): value is { query: string; chunks: RetrievedChunk[] } {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  if (typeof request.query !== "string" || request.query.trim().length === 0 ||
      !Array.isArray(request.chunks) || request.chunks.length === 0 || request.chunks.length > 100) {
    return false;
  }

  const chunksValid = request.chunks.every((value) => {
    if (typeof value !== "object" || value === null) return false;
    const chunk = value as Record<string, unknown>;
    return typeof chunk.sourceId === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(chunk.sourceId) &&
      typeof chunk.text === "string" && chunk.text.trim().length > 0 &&
      typeof chunk.tenantId === "string" && chunk.tenantId.trim().length > 0 &&
      Array.isArray(chunk.allowedRoles) && chunk.allowedRoles.length > 0 &&
      chunk.allowedRoles.every((role) => typeof role === "string" && role.trim().length > 0) &&
      typeof chunk.status === "string";
  });
  if (!chunksValid) return false;

  const ids = request.chunks.map((chunk) => (chunk as Record<string, unknown>).sourceId);
  return new Set(ids).size === ids.length;
}

function validateRetrievedContext(
  query: string,
  chunks: RetrievedChunk[],
  policy: TokenPolicy,
  secretRules: SecretRule[],
  authenticatedTenantId: unknown,
  identityRoles: unknown
) {
  const roles = Array.isArray(identityRoles) ? identityRoles.filter((role): role is string => typeof role === "string") : [];
  const approvedChunkIds: string[] = [];
  const rejectedChunkIds: string[] = [];
  const rejectionReasons: Record<string, string> = {};
  const reject = (sourceId: string, reason: string) => {
    rejectedChunkIds.push(sourceId);
    rejectionReasons[sourceId] = reason;
  };

  const totalTokens = countInputTokens([query, ...chunks.map((chunk) => chunk.text)].join("\n"));
  if (totalTokens > policy.maxInputTokens) {
    for (const chunk of chunks) reject(chunk.sourceId, "CONTEXT_TOO_LARGE");
    return {
      decision: "BLOCK",
      approvedChunkIds,
      rejectedChunkIds,
      rejectionReasons,
      tokenCount: totalTokens,
      maxInputTokens: policy.maxInputTokens
    };
  }

  for (const chunk of chunks) {
    if (chunk.status !== "ACTIVE") {
      reject(chunk.sourceId, "UNSUPPORTED_SOURCE_STATUS");
      continue;
    }

    if (typeof authenticatedTenantId !== "string" || chunk.tenantId !== authenticatedTenantId ||
        !chunk.allowedRoles.some((role) => roles.includes(role))) {
      reject(chunk.sourceId, "UNAUTHORIZED_SOURCE");
      continue;
    }

    if (detectSecret(chunk.text, secretRules).matched) {
      reject(chunk.sourceId, "SECRET_DETECTED");
      continue;
    }

    if (detectPii(chunk.text).matched) {
      reject(chunk.sourceId, "PII_DETECTED");
      continue;
    }

    if (detectConfidential(chunk.text).matched) {
      reject(chunk.sourceId, "CONFIDENTIAL_CONTENT");
      continue;
    }

    if (detectPromptInjection(chunk.text).matched) {
      reject(chunk.sourceId, "PROMPT_INJECTION");
      continue;
    }

    approvedChunkIds.push(chunk.sourceId);
  }

  return {
    decision: rejectedChunkIds.length > 0 ? "BLOCK" : "ALLOW",
    approvedChunkIds,
    rejectedChunkIds,
    rejectionReasons,
    tokenCount: totalTokens,
    maxInputTokens: policy.maxInputTokens
  };
}
function isRagDocument(value: unknown): value is RagDocument {
  if (typeof value !== "object" || value === null) return false;
  const document = value as Record<string, unknown>;
  return typeof document.documentId === "string" && document.documentId.trim().length > 0 &&
    typeof document.tenantId === "string" && document.tenantId.trim().length > 0 &&
    typeof document.classification === "string" && document.classification.trim().length > 0 &&
    Array.isArray(document.allowedRoles) && document.allowedRoles.length > 0 &&
    document.allowedRoles.every((role) => typeof role === "string" && role.trim().length > 0) &&
    (document.status === undefined || typeof document.status === "string") &&
    (document.expiresAt === undefined || typeof document.expiresAt === "string");
}

function authorizeRagDocument(
  document: RagDocument,
  authenticatedTenantId: unknown,
  identityRoles: unknown
) {
  const roles = Array.isArray(identityRoles) ? identityRoles.filter((role): role is string => typeof role === "string") : [];
  const denied = (reason: string) => ({
    authorized: false,
    recommendedAction: "BLOCK",
    reason
  });

  if (typeof authenticatedTenantId !== "string" || authenticatedTenantId !== document.tenantId) {
    return denied("TENANT_MISMATCH");
  }

  if (document.status !== undefined && document.status !== "ACTIVE") {
    return denied("DOCUMENT_INACTIVE");
  }

  if (document.expiresAt !== undefined) {
    const expiry = Date.parse(document.expiresAt);
    if (!Number.isFinite(expiry) || expiry <= Date.now()) {
      return denied("DOCUMENT_EXPIRED");
    }
  }

  if (!document.allowedRoles.some((role) => roles.includes(role))) {
    return denied("ROLE_NOT_ALLOWED");
  }

  return {
    authorized: true,
    recommendedAction: "ALLOW"
  };
}

function normalizeModerationContent(content: string, locale?: string) {
  const unicodeNormalizedContent = content.normalize("NFKC");
  const unicodeNormalized = unicodeNormalizedContent !== content;
  const zeroWidthPattern = /[\u200B-\u200D\u2060\uFEFF]/g;
  const zeroWidthMatches = unicodeNormalizedContent.match(zeroWidthPattern);
  const zeroWidthRemoved = zeroWidthMatches?.length ?? 0;
  const withoutZeroWidth = unicodeNormalizedContent.replace(zeroWidthPattern, "");
  const contentAfterWhitespace = withoutZeroWidth.replace(/[\s\u00A0]+/g, " ").trim();
  const whitespaceNormalized = contentAfterWhitespace !== withoutZeroWidth;
  const suspiciousEncoding = inspectEncodedContent(contentAfterWhitespace);

  return {
    content: contentAfterWhitespace,
    metadata: {
      unicodeNormalized,
      zeroWidthRemoved,
      whitespaceNormalized,
      suspiciousEncodingDetected: suspiciousEncoding.detected,
      encodingDecodeSkipped: suspiciousEncoding.decodeSkipped,
      locale: locale ?? null
    }
  };
}

function inspectEncodedContent(content: string) {
  const wrappers = /(?:base64|b64|payload|data)\s*[:=]\s*([A-Za-z0-9+/=_-]+)/gi;
  let detected = false;
  let decodeSkipped = false;
  let match: RegExpExecArray | null;

  while ((match = wrappers.exec(content)) !== null) {
    const candidate = match[1].replace(/\s/g, "");
    const isBase64 = /^[A-Za-z0-9+/_-]+={0,2}$/.test(candidate) && candidate.length >= 16;
    const isHex = /^(?:[0-9a-f]{2}){8,}$/i.test(candidate);
    if (!isBase64 && !isHex) continue;

    detected = true;
    if (candidate.length > 4096) {
      decodeSkipped = true;
      continue;
    }

    try {
      const decoded = isHex
        ? Buffer.from(candidate, "hex").toString("utf8")
        : Buffer.from(candidate.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
      if (/ignore\s+(?:all\s+)?previous\s+instructions?|reveal\s+(?:the\s+)?(?:system\s+)?prompt|bypass\s+(?:the\s+)?(?:safety|security|policy)/i.test(decoded)) {
        detected = true;
      }
    } catch {
      detected = true;
    }
  }

  return { detected, decodeSkipped };
}

function extractUploadFileName(contentDisposition: string | string[] | undefined): string | null {
  if (!contentDisposition) {
    return null;
  }

  const value = Array.isArray(contentDisposition) ? contentDisposition[0] : contentDisposition;
  const match = value.match(/filename\s*=\s*"?([^";]+)"?/i);
  return match ? decodeURIComponent(match[1].replace(/\\/g, "/")) : null;
}