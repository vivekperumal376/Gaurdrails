import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import type { RequestHandler } from "express";
import { countInputTokens, type TokenPolicy } from "../limits.js";

export function createRateLimitMiddleware(policy: TokenPolicy): RequestHandler {
  return rateLimit({
    windowMs: policy.rateLimitWindowMs,
    limit: policy.rateLimitMaxRequests,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    keyGenerator: (req, res) => {
      const ip = ipKeyGenerator(req.ip ?? "unknown");
      const subject = String(res.locals.authenticatedSubject ?? "unknown");
      const validated = res.locals.validatedModerationRequest as { applicationId?: string } | undefined;
      const applicationId = validated?.applicationId ?? req.get("x-application-id") ?? "default";
      return `${ip}:${subject}:${applicationId}`;
    },
    handler: (_req, res) => {
      res.status(429).json({
        requestId: res.locals.requestId,
        error: "RATE_LIMIT_EXCEEDED"
      });
    }
  });
}

export function createRequestBudgetMiddleware(policy: TokenPolicy): RequestHandler {
  let activeRequests = 0;

  return (_req, res, next) => {
    if (activeRequests >= policy.maxConcurrentRequests) {
      return res.status(503).json({
        requestId: res.locals.requestId,
        error: "CONCURRENCY_LIMIT_EXCEEDED"
      });
    }

    activeRequests += 1;
    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        activeRequests -= 1;
      }
    };

    const abortController = new AbortController();
    res.locals.abortSignal = abortController.signal;
    const timeout = setTimeout(() => {
      abortController.abort();
      if (!res.headersSent) {
        res.status(504).json({
          requestId: res.locals.requestId,
          error: "REQUEST_TIMEOUT"
        });
      }
      release();
    }, policy.timeoutBudgetMs);

    res.once("finish", () => {
      clearTimeout(timeout);
      release();
    });
    res.once("close", () => {
      clearTimeout(timeout);
      release();
    });

    return next();
  };
}

export function enforceTokenLimit(policy: TokenPolicy): RequestHandler {
  return (req, res, next) => {
    const content = res.locals.validatedModerationRequest
      ? (res.locals.validatedModerationRequest as { content: string }).content
      : req.body?.content;

    if (typeof content !== "string") {
      return next();
    }

    const tokenCount = countInputTokens(content);
    res.locals.tokenCount = tokenCount;
    if (tokenCount > policy.maxInputTokens) {
      return res.status(413).json({
        requestId: res.locals.requestId,
        error: "TOKEN_LIMIT_EXCEEDED",
        tokenCount,
        maxInputTokens: policy.maxInputTokens,
        recommendedAction: "BLOCK"
      });
    }

    return next();
  };
}