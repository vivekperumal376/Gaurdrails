import pino from "pino";
import type { DestinationStream } from "pino";

const redactedFields = [
  "content",
  "*.content",
  "req.body.content",
  "authorization",
  "*.authorization",
  "token",
  "*.token",
  "password",
  "*.password",
  "secret",
  "*.secret",
  "apiKey",
  "*.apiKey",
  "privateKey",
  "*.privateKey"
];

export function createLogger(destination: DestinationStream = process.stdout) {
  return pino({
    level: process.env.LOG_LEVEL ?? "info",
    redact: {
      paths: redactedFields,
      censor: "[REDACTED]"
    }
  }, destination);
}

export const logger = createLogger();