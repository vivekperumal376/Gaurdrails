import { readFileSync } from "node:fs";
import { countTokens } from "gpt-tokenizer/encoding/cl100k_base";
import { parse } from "yaml";
import { z } from "zod";

const tokenPolicySchema = z.object({
  version: z.string().min(1),
  tokenizer: z.literal("cl100k_base"),
  maxInputTokens: z.number().int().positive(),
  maxRequestBytes: z.number().int().positive(),
  rateLimitWindowMs: z.number().int().positive(),
  rateLimitMaxRequests: z.number().int().positive(),
  timeoutBudgetMs: z.number().int().positive(),
  maxConcurrentRequests: z.number().int().positive()
}).strict();

export type TokenPolicy = z.infer<typeof tokenPolicySchema>;

export function loadTokenPolicy(filePath: string): TokenPolicy {
  return tokenPolicySchema.parse(parse(readFileSync(filePath, "utf8")));
}

export function countInputTokens(content: string): number {
  return countTokens(content);
}

export function evaluateTokenLimit(content: string, policy: TokenPolicy) {
  const tokenCount = countInputTokens(content);
  const valid = tokenCount <= policy.maxInputTokens;
  return {
    tokenCount,
    maxInputTokens: policy.maxInputTokens,
    valid,
    recommendedAction: valid ? "ALLOW" as const : "BLOCK" as const
  };
}