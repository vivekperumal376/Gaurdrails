import jwt, { type JwtPayload, type VerifyOptions } from "jsonwebtoken";
import jwksRsa from "jwks-rsa";
import type { RequestHandler, Response } from "express";

export const AUTHORIZATION_ROLES = [
  "moderation.user",
  "moderation.tester",
  "moderation.reviewer",
  "moderation.admin"
] as const;

export type AuthorizationRole = (typeof AUTHORIZATION_ROLES)[number];

export type AuthConfig =
  | { mode: "local"; secret: string; issuer: string; audience: string }
  | { mode: "oidc"; jwksUri: string; issuer: string; audience: string };

export function loadAuthConfig(env: NodeJS.ProcessEnv): AuthConfig | null {
  const issuer = env.JWT_ISSUER;
  const audience = env.JWT_AUDIENCE;

  if (!issuer || !audience) {
    return null;
  }

  if (env.AUTH_MODE === "local") {
    const secret = env.JWT_SECRET;
    if (!secret || secret.length < 32) {
      return null;
    }
    return { mode: "local", secret, issuer, audience };
  }

  if (env.AUTH_MODE === "oidc") {
    const jwksUri = env.OIDC_JWKS_URI;
    if (!jwksUri || !isHttpsUrl(jwksUri)) {
      return null;
    }
    return { mode: "oidc", jwksUri, issuer, audience };
  }

  return null;
}

export function createAuthenticationMiddleware(
  config: AuthConfig | null
): RequestHandler {
  const jwks = config?.mode === "oidc"
    ? jwksRsa({
        jwksUri: config.jwksUri,
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 10
      })
    : null;

  return async (req, res, next) => {
    if (!config) {
      return res.status(503).json({
        requestId: res.locals.requestId,
        error: "AUTHENTICATION_UNAVAILABLE"
      });
    }

    const authorization = req.get("authorization") ?? "";
    const match = /^Bearer\s+([^\s]+)$/i.exec(authorization);
    if (!match) {
      res.setHeader("WWW-Authenticate", "Bearer");
      return res.status(401).json({
        requestId: res.locals.requestId,
        error: "UNAUTHENTICATED"
      });
    }

    try {
      const options: VerifyOptions = {
        algorithms: [config.mode === "local" ? "HS256" : "RS256"],
        issuer: config.issuer,
        audience: config.audience
      };
      const decoded = config.mode === "local"
        ? jwt.verify(match[1], config.secret, options)
        : await verifyOidcToken(match[1], options, jwks);

      if (typeof decoded === "string") {
        throw new Error("JWT payload must be an object.");
      }

      const payload = decoded as JwtPayload;
      if (typeof payload.exp !== "number") {
        throw new Error("Token expiry is required.");
      }

      res.locals.authenticatedSubject = payload.sub;
      res.locals.authenticatedTenantId = typeof payload.tenantId === "string" ? payload.tenantId : undefined;
      res.locals.identityRoles = extractIdentityRoles(payload.roles);
      res.locals.roles = extractRoles(payload.roles);
      return next();
    } catch {
      res.setHeader("WWW-Authenticate", "Bearer");
      return res.status(401).json({
        requestId: res.locals.requestId,
        error: "UNAUTHENTICATED"
      });
    }
  };
}

export function requireRole(role: AuthorizationRole): RequestHandler {
  return (_req, res, next) => {
    const roles = res.locals.roles as AuthorizationRole[] | undefined;
    if (!roles?.includes(role)) {
      return sendForbidden(res);
    }
    return next();
  };
}

function extractRoles(value: unknown): AuthorizationRole[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(
    (role): role is AuthorizationRole =>
      typeof role === "string" && AUTHORIZATION_ROLES.includes(role as AuthorizationRole)
  );
}

function extractIdentityRoles(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(
    (role): role is string => typeof role === "string" && role.length > 0 && role.length <= 128
  ).slice(0, 50);
}

function sendForbidden(res: Response) {
  return res.status(403).json({
    requestId: res.locals.requestId,
    error: "FORBIDDEN"
  });
}
function verifyOidcToken(
  token: string,
  options: VerifyOptions,
  jwks: ReturnType<typeof jwksRsa> | null
): Promise<string | JwtPayload> {
  if (!jwks) {
    return Promise.reject(new Error("OIDC signing keys are unavailable."));
  }

  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      (header, callback) => {
        if (!header.kid) {
          callback(new Error("Token key ID is missing."));
          return;
        }
        jwks.getSigningKey(header.kid)
          .then((key) => callback(null, key.getPublicKey()))
          .catch((error: Error) => callback(error));
      },
      options,
      (error, decoded) => {
        if (error || decoded === undefined) {
          reject(error ?? new Error("Token is invalid."));
          return;
        }
        resolve(decoded);
      }
    );
  });
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}