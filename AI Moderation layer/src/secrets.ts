import { readFileSync } from "node:fs";
import { parse } from "yaml";

export interface SecretRule {
  id: string;
  category: string;
  pattern: RegExp;
}

interface SecretRulesFile {
  rules: Array<{
    id: string;
    category: string;
    pattern: string;
    flags?: string;
  }>;
}

const allowedFlags = new Set(["i", "m", "s", "u"]);

export function loadSecretRules(filePath: string): SecretRule[] {
  const parsed: unknown = parse(readFileSync(filePath, "utf8"));
  if (!isSecretRulesFile(parsed) || parsed.rules.length === 0) {
    throw new Error("Secret rules must contain at least one valid rule.");
  }

  return parsed.rules.map((rule) => {
    const flags = rule.flags ?? "";
    if ([...flags].some((flag) => !allowedFlags.has(flag)) || new Set(flags).size !== flags.length) {
      throw new Error(`Secret rule ${rule.id} has unsupported regex flags.`);
    }
    return {
      id: rule.id,
      category: rule.category,
      pattern: new RegExp(rule.pattern, flags)
    };
  });
}

export function detectSecret(content: string, rules: SecretRule[]) {
  for (const rule of rules) {
    if (rule.pattern.test(content)) {
      return {
        matched: true,
        category: rule.category,
        recommendedAction: "BLOCK" as const,
        ruleId: rule.id
      };
    }
  }

  return {
    matched: false,
    category: null,
    recommendedAction: "ALLOW" as const,
    ruleId: null
  };
}

function isSecretRulesFile(value: unknown): value is SecretRulesFile {
  if (typeof value !== "object" || value === null || !Array.isArray((value as SecretRulesFile).rules)) {
    return false;
  }

  return (value as SecretRulesFile).rules.every((rule) =>
    typeof rule.id === "string" && rule.id.length > 0 &&
    typeof rule.category === "string" && rule.category.length > 0 &&
    typeof rule.pattern === "string" && rule.pattern.length > 0 &&
    (rule.flags === undefined || typeof rule.flags === "string")
  );
}