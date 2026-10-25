import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { z } from "zod";

const actionPolicySchema = z.object({
  allowedRoles: z.array(z.string().min(1).max(128)).min(1),
  requiredArguments: z.array(z.string().min(1).max(64)),
  allowedArguments: z.array(z.string().min(1).max(64)),
  allowedRecipientDomains: z.array(z.string().min(1).max(253)).optional(),
  tenantArgument: z.string().min(1).max(64).optional(),
  risk: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  approvalRequired: z.boolean()
}).strict().superRefine((action, context) => {
  if (action.requiredArguments.some((argument) => !action.allowedArguments.includes(argument))) {
    context.addIssue({ code: "custom", message: "Required arguments must also be allowlisted." });
  }
  if (action.tenantArgument && !action.requiredArguments.includes(action.tenantArgument)) {
    context.addIssue({ code: "custom", message: "The tenant argument must be required." });
  }
});

const toolPolicySchema = z.object({
  version: z.string().min(1),
  tools: z.record(z.string().min(1).max(64), z.object({
    actions: z.record(z.string().min(1).max(64), actionPolicySchema)
  }).strict())
}).strict().refine((policy) => Object.keys(policy.tools).length > 0, "At least one tool must be configured.");

export type ToolPolicy = z.infer<typeof toolPolicySchema>;
export type ToolActionPolicy = z.infer<typeof actionPolicySchema>;

export function loadToolPolicy(filePath: string): ToolPolicy {
  return toolPolicySchema.parse(parse(readFileSync(filePath, "utf8")));
}
