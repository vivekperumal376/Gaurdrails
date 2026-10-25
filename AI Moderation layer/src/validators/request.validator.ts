import { z } from "zod";
import type { RequestHandler } from "express";

const metadataSchema = z.object({
  channel: z.string().trim().min(1).max(64).optional(),
  locale: z.string().trim().min(2).max(35).optional()
}).strict();

export const moderationRequestSchema = z.object({
  content: z.string().trim().min(1).max(100_000),
  applicationId: z.string()
    .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/)
    .optional(),
  conversationId: z.string()
    .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
    .optional(),
  metadata: metadataSchema.optional()
}).strict();

export const requireJsonContentType: RequestHandler = (req, res, next) => {
  if (req.is("application/json") || req.is("application/*+json")) {
    return next();
  }

  return res.status(415).json({
    requestId: res.locals.requestId,
    error: "UNSUPPORTED_MEDIA_TYPE"
  });
};

export const validateModerationRequest: RequestHandler = (req, res, next) => {
  const result = moderationRequestSchema.safeParse(req.body);
  if (result.success) {
    res.locals.validatedModerationRequest = result.data;
    return next();
  }

  const fields = [...new Set(result.error.issues.map((issue) => {
    const field = issue.path[0];
    return typeof field === "string" ? field : "body";
  }))];

  return res.status(400).json({
    requestId: res.locals.requestId,
    error: "INVALID_REQUEST",
    fields
  });
};