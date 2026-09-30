import type { RequestHandler } from "express";
import {
  AuthorizationServer,
  MemoryRateLimitStore,
  RedisClusterRateLimitStore,
  ConsulRateLimitStore,
  WafRuleEngine,
  type RateLimitStore,
  type OAuthClient,
} from "@audit-ledger/security";

export const OAUTH_ISSUER = process.env.OAUTH_ISSUER ?? "http://localhost:3002/oauth";

/**
 * Baseline security headers required by the ZAP baseline scan. Applied to
 * every response (including /robots.txt and /sitemap.xml) so the scanner
 * stops reporting:
 *   - 10055 CSP: Failure to Define Directive with No Fallback
 *   - 10063 Permissions Policy Header Not Set
 *   - 10037 Server Leaks Information via "X-Powered-By"
 *   - 10049 Storable and Cacheable Content
 *
 * `default-src 'self'` gives every fetch directive a fallback, and the
 * explicit `frame-ancestors`/`base-uri`/`form-action` directives cover the
 * ones that do NOT inherit from `default-src`.
 */
export const securityHeaders: RequestHandler = (_req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "connect-src 'self'",
    ].join("; "),
  );
  res.setHeader(
    "Permissions-Policy",
    [
      "accelerometer=()",
      "camera=()",
      "geolocation=()",
      "gyroscope=()",
      "magnetometer=()",
      "microphone=()",
      "payment=()",
      "usb=()",
    ].join(", "),
  );
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  // ZAP 10037: strip the framework fingerprint.
  res.removeHeader("X-Powered-By");
  // ZAP 10049: prevent caching of API/HTML responses.
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
};

/**
 * The OIDC/OAuth2 issuer. When `OIDC_JWKS_URI` is configured, deployments
 * are expected to run a real external IdP (Auth0/Okta/Keycloak/etc) and the
 * `authenticateBearer` resource-server middleware verifies against that
 * instead — this local issuer only exists to make the API self-sufficient
 * for local development, CI, and the demo clients below.
 */
export const authorizationServer = new AuthorizationServer({ issuer: OAUTH_ISSUER });

const DEFAULT_CLIENTS: OAuthClient[] = [
  {
    clientId: process.env.OAUTH_SPA_CLIENT_ID ?? "audit-ledger-dashboard",
    name: "Audit Ledger Dashboard (public SPA)",
    redirectUris: (process.env.OAUTH_SPA_REDIRECT_URIS ?? "http://localhost:3000/callback").split(","),
    allowedScopes: ["events:read", "stats:read", "export:read"],
    allowedGrantTypes: ["authorization_code", "refresh_token"],
    isPublic: true, // no client secret — MUST use PKCE
    defaultRole: "viewer",
  },
  {
    clientId: process.env.OAUTH_SERVICE_CLIENT_ID ?? "audit-ledger-ingest-service",
    clientSecret: process.env.OAUTH_SERVICE_CLIENT_SECRET ?? "dev-only-service-secret-change-me",
    name: "Backend ingest/automation service",
    redirectUris: [],
    allowedScopes: ["events:read", "events:write", "stats:read", "export:read", "admin:keys", "admin:waf"],
    allowedGrantTypes: ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    isPublic: false,
    defaultRole: "admin",
  },
];

for (const client of DEFAULT_CLIENTS) authorizationServer.registerClient(client);

export const wafRuleEngine = new WafRuleEngine();

/**
 * Selects a rate-limit backend to match the deployment topology:
 *  - `redis-cluster` — multiple horizontally-scaled API instances behind a
 *    load balancer, sharing limits via Redis Cluster (REDIS_CLUSTER_NODES).
 *  - `consul` — deployments that already run Consul for service mesh /
 *    config and prefer not to add Redis as another moving part
 *    (CONSUL_HTTP_ADDR).
 *  - `memory` (default) — single instance / local dev / CI.
 */
export function createConfiguredRateLimitStore(): RateLimitStore {
  const backend = (process.env.RATE_LIMIT_BACKEND ?? "memory").toLowerCase();

  if (backend === "redis-cluster" || backend === "redis") {
    // Loaded lazily, via `require` rather than a static import, so ioredis
    // (and an actual Redis endpoint) are only required when this backend is
    // selected — and so this file doesn't statically pull in ioredis's own
    // type declarations, which would otherwise collide with the separate
    // copy of ioredis's types resolved inside @audit-ledger/security's own
    // node_modules (two structurally-similar but nominally distinct
    // `Cluster`/`Redis` classes, since this repo has no npm workspace to
    // dedupe them).
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const IORedis = require("ioredis");
    const nodes = (process.env.REDIS_CLUSTER_NODES ?? "127.0.0.1:6379")
      .split(",")
      .map((hostPort) => {
        const [host, port] = hostPort.trim().split(":");
        return { host, port: Number(port) || 6379 };
      });

    const client = backend === "redis-cluster" && nodes.length > 1
      ? new IORedis.Cluster(nodes)
      : new IORedis(nodes[0].port, nodes[0].host);

    return new RedisClusterRateLimitStore(client);
  }

  if (backend === "consul") {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const Consul = require("consul");
    const client = new Consul({
      host: process.env.CONSUL_HTTP_ADDR_HOST ?? "127.0.0.1",
      port: process.env.CONSUL_HTTP_ADDR_PORT ?? "8500",
      promisify: true,
    });
    return new ConsulRateLimitStore(client);
  }

  return new MemoryRateLimitStore();
}
