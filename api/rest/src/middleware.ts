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
  const limit = RATE_LIMIT_MA;
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
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "worker-src 'self'",
  "media-src 'none'",
  "child-src 'none'",
  "upgrade-insecure-requests",
  "block-all-mixed-content",
];

export const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "ambient-light-sensor=()",
  "autoplay=()",
  "camera=()",
  "cross-origin-isolated=()",
  "display-capture=()",
  "encrypted-media=()",
  "fullscreen=()",
  "geolocation=()",
  "gyroscope=()",
  "hid=()",
  "idle-detection=()",
  "magnetometer=()",
  "microphone=()",
  "midi=()",
  "payment=()",
  "picture-in-picture=()",
  "public-key-credentials-get=()",
  "speaker-selection=()",
  "usb=()",
  "xb-delaration-sensor=()",
];

export function securityHeadersMiddleware(_req: Request, res: Response, next: NextFunction): void {
  // ZAP [10037]: hide the framework identifier before any other handler runs.
  res.removeHeader("X-Powered-By");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  // ZAP [10055]: explicit fallback for every directive (default-src + frame-ancestors).
  res.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY.join("; "));
  // ZAP [10063]: explicit Permissions-Policy denying every powerful feature.
  res.setHeader("Permissions-Policy", PERMISSIONS_POLICY.join(", "));
  // ZAP [10049]: prevent intermediaries from storing/reusing API responses.
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
}
