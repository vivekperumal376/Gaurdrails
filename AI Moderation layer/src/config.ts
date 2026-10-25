import { readFileSync } from "node:fs";
import { parse } from "yaml";

export interface PolicyConfig {
  version: string;
  decisionPriority: DecisionAction[];
  contentSafety: ContentSafetyPolicy;
}

export const DECISION_ACTIONS = ["ALLOW", "WARN", "MASK", "SAFE_RESPONSE", "ESCALATE", "BLOCK"] as const;
export type DecisionAction = (typeof DECISION_ACTIONS)[number];
export const CONTENT_SAFETY_CATEGORIES = ["HARASSMENT", "HATE", "TOXICITY", "CYBER_MISUSE", "FRAUD_MISUSE", "DANGEROUS_ACTIVITY", "GRAPHIC_CONTENT", "CREDIBLE_THREAT", "EXTREMIST_SUPPORT", "CHILD_SAFETY", "ADULT_CONTENT", "SELF_HARM"] as const;
export type ContentSafetyCategory = (typeof CONTENT_SAFETY_CATEGORIES)[number];
export type ContentSafetyPolicy = Record<ContentSafetyCategory, DecisionAction>;

export function loadPolicyConfig(filePath: string): PolicyConfig {
  const parsed: unknown = parse(readFileSync(filePath, "utf8"));

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    typeof (parsed as Record<string, unknown>).version !== "string" ||
    !(parsed as Record<string, unknown>).version
  ) {
    throw new Error("Policy configuration must include a non-empty version.");
  }

  const priority = (parsed as Record<string, unknown>).decisionPriority;
  if (
    !Array.isArray(priority) ||
    priority.length !== DECISION_ACTIONS.length ||
    priority.some((action) => typeof action !== "string" || !DECISION_ACTIONS.includes(action as DecisionAction)) ||
    new Set(priority).size !== DECISION_ACTIONS.length
  ) {
    throw new Error("Moderation policy must define each decision action exactly once in decisionPriority.");
  }

  const contentSafety = (parsed as Record<string, unknown>).contentSafety;
  const categoryActions = typeof contentSafety === "object" && contentSafety !== null
    ? (contentSafety as Record<string, unknown>).categoryActions
    : null;
  if (typeof categoryActions !== "object" || categoryActions === null || Array.isArray(categoryActions) ||
      CONTENT_SAFETY_CATEGORIES.some((category) =>
        typeof (categoryActions as Record<string, unknown>)[category] !== "string" ||
        !DECISION_ACTIONS.includes((categoryActions as Record<string, unknown>)[category] as DecisionAction)
      )) {
    throw new Error("Moderation policy must define a supported action for every content-safety category.");
  }

  return {
    version: (parsed as Record<string, string>).version,
    decisionPriority: priority as DecisionAction[],
    contentSafety: Object.fromEntries(CONTENT_SAFETY_CATEGORIES.map((category) => [
      category,
      (categoryActions as Record<string, DecisionAction>)[category]
    ])) as ContentSafetyPolicy
  };
}