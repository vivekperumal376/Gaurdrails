import "dotenv/config";
import jwt from "jsonwebtoken";
import { loadAuthConfig } from "../src/auth.js";

const config = loadAuthConfig(process.env);

if (!config || config.mode !== "local") {
  console.error("Configure local JWT authentication in .env before creating a development token.");
  process.exit(1);
}

const args = process.argv.slice(2);
const requestedRoles = args.filter((arg) => !arg.startsWith("--"));
const tenantArgument = args.find((arg) => arg.startsWith("--tenant="));
const businessRoleArgument = args.find((arg) => arg.startsWith("--business-role="));
const unknownOption = args.find((arg) => arg.startsWith("--") && !arg.startsWith("--tenant=") && !arg.startsWith("--business-role="));
const tenantId = tenantArgument?.slice("--tenant=".length);
const businessRole = businessRoleArgument?.slice("--business-role=".length);
const roles = requestedRoles.length > 0 ? requestedRoles : ["moderation.user"];
const allowedRoles = new Set([
  "moderation.user",
  "moderation.tester",
  "moderation.reviewer",
  "moderation.admin"
]);

if (roles.some((role) => !allowedRoles.has(role))) {
  console.error(`Roles must be selected from: ${[...allowedRoles].join(", ")}.`);
  process.exit(1);
}

if (unknownOption || (tenantId !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(tenantId))) {
  console.error("Options must use --tenant=<tenant-id> and/or --business-role=<role-name>.");
  process.exit(1);
}

if (businessRole !== undefined && !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(businessRole)) {
  console.error("Business role must be a simple role name up to 64 characters.");
  process.exit(1);
}

const tokenRoles = businessRole ? [...roles, businessRole] : roles;

const token = jwt.sign(
  { sub: "postman-local-user", roles: tokenRoles, ...(tenantId ? { tenantId } : {}) },
  config.secret,
  {
    algorithm: "HS256",
    issuer: config.issuer,
    audience: config.audience,
    expiresIn: "15m"
  }
);

console.log(token);