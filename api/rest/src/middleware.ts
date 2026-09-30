import { Request, Response, NextFunction } from "express";
import { validateKey, ApiKeyRecord } from "./keys";

declare global {
  namespace Express {
    interface Request {
      apiKeyRecord?: ApiKeyRecord;
    }
  }
}

const keyBuckets = new Map<string, { tokens: number; lastRefill: number }>();

const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX ?? "100", 10);
const RATE_LIMIT_REFILL_RATE = parseInt(process.env.RATE_LIMIT_REFILL_RATE ?? "100", 10);
const RATE_LIMIT_REFILL_INTERVAL_MS = parseInt(process.env.RATE_LIMIT_REFILL_INTERVAL_MS ?? "60000", 10);

function getBucket(key: string) {
  let bucket = keyBuckets.get(key);
  if (!bucket) {
    bucket = { tokens: RATE_LIMIT_MAX, lastRefill: Date.now() };
    keyBuckets.set(key, bucket);
  }
  const now = Date.now();
  const elapsed = now - bucket.lastRefill;
  const refillCount = Math.floor((elapsed / RATE_LIMIT_REFILL_INTERVAL_MS) * RATE_LIMIT_REFILL_RATE);
  if (refillCount > 0) {
    bucket.tokens = Math.min(RATE_LIMIT_MAX, bucket.tokens + refillCount);
    bucket.lastRefill = now;
  }
  return bucket;
}

/**
 * Baseline security headers required by the OWASP ZAP baseline scan.
 *
 * Addresses:
 *  - ZAP [10055] CSP: Failure to Define Directive with No Fallback
 *  - ZAP [10063] Permissions Policy Header Not Set
 *  - ZAP [10037] Server Leaks Information via "X-Powered-By"
 *  - ZAP [10049] Storable and Cacheable Content
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "frame-src 'none'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "style-src 'self'",
  "script-src 'self'",
  "manifest-src 'self'",
  "upgrade-insecure-requests",
].join("; ");

export const PERMISSIONS_POLICY = [
  "geolocation=()",
  "microphone=()",
  "camera=()",
  "payment=()",
  "usb ()",
  "magnetometer=()",
  "gyroscope=()",
  "accelerometer=()",
].join(", ");

export function securityHeadersMiddleware(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
  res.setHeader("Permissions-Policy", PERMISSIONS_POLICY);
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  // ZAP [10037] - do not advertise the framework in response headers.
  res.removeHeader("X-Powered-By");
  // ZAP [10049] - prevent sensitive API responses from being stored/cached.
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
}

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.method === "GET") {
    return next();
  }

  const key = req.headers["x-api-key"] as string
    ?? req.headers["authorization"]?.replace("Bearer ", "");

  if (!key) {
    res.status(401).json({ error: "Unauthorized: missing API key" });
    return;
  }

  const record = validateKey(key);
  if (!record) {
    res.status(401).json({ error: "Unauthorized: invalid API key" });
    return;
  }

  req.apiKeyRecord = record;
  next();
}

export function rateLimitMiddleware(req: Request, res: Response, next: NextFunction): void {
  const key = req.headers["x-api-key"] as string
    ?? req.headers["authorization"]?.replace("Bearer ", "")
    ?? `ip:${req.ip}`;

  const bucket = getBucket(key);
  const limit = RATE_LIMIT_MAP;
  const remaining = bucket.tokens;
  const resetSeconds = Math.ceil(
    (RATE_LIMIT_REFILL_INTERVAL_MS - (Date.now() - bucket.lastRefill)) / 1000
  );

  res.setHeader("X-RateLimit-Limit", String(limit));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, remaining)));
  res.setHeader("X-RateLimit-Reset", String(Math.max(0, resetSeconds)));

  if (bucket.tokens <= 0) {
    const retryAfter = Math.ceil((1 / RATE_LIMIT_REFILL_RATE) * RATE_LIMIT_REFILL_INTERVAL_MS / 1000);
    res.setHeader("Retry-After", String(retryAfter));
    res.status(429).json({ error: "Rate limit exceeded", retryAfter });
    return;
  }

  bucket.tokens--;
  next();
}
