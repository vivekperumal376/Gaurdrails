import "dotenv/config";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "./app.js";
import { loadAuthConfig } from "./auth.js";
import { loadPolicyConfig, type DecisionAction } from "./config.js";
import { logger } from "./logger.js";
import { loadSecretRules, type SecretRule } from "./secrets.js";
import { loadTokenPolicy, type TokenPolicy } from "./limits.js";
import { loadToolPolicy, type ToolPolicy } from "./tool-policy.js";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const policyPath = process.env.POLICY_PATH
  ? resolve(process.env.POLICY_PATH)
  : resolve(projectRoot, "config/moderation-policy.yaml");
const secretRulesPath = resolve(projectRoot, "config/secret-rules.yaml");
const tokenPolicyPath = resolve(projectRoot, "config/token-policy.yaml");
const toolPolicyPath = resolve(projectRoot, "config/tool-policy.yaml");
const port = Number(process.env.PORT ?? "3000");

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  logger.error("PORT must be an integer between 1 and 65535.");
  process.exit(1);
}

let policyVersion: string | null = null;
let decisionPriority: DecisionAction[] | null = null;
let contentSafetyPolicy: ReturnType<typeof loadPolicyConfig>["contentSafety"] | null = null;

try {
  const policy = loadPolicyConfig(policyPath);
  policyVersion = policy.version;
  decisionPriority = policy.decisionPriority;
  contentSafetyPolicy = policy.contentSafety;
} catch {
  logger.error("Policy configuration validation failed; readiness is disabled.");
}

const authConfig = loadAuthConfig(process.env);
if (authConfig === null) {
  logger.error("Authentication configuration validation failed; readiness is disabled.");
}

let secretRules: SecretRule[] | null = null;
try {
  secretRules = loadSecretRules(secretRulesPath);
} catch {
  logger.error("Secret detector rules failed to load; readiness is disabled.");
}

let tokenPolicy: TokenPolicy | null = null;
try {
  tokenPolicy = loadTokenPolicy(tokenPolicyPath);
} catch {
  logger.error("Token and request limit policy failed to load; readiness is disabled.");
}

let toolPolicy: ToolPolicy | null = null;
try {
  toolPolicy = loadToolPolicy(toolPolicyPath);
} catch {
  logger.error("Tool action policy failed to load; tool validation is disabled.");
}

const app = createApp(policyVersion, authConfig, secretRules, tokenPolicy, toolPolicy, decisionPriority, undefined, contentSafetyPolicy);

app.listen(port, "0.0.0.0", () => {
  logger.info({ port }, "Guardrail gateway started.");
});