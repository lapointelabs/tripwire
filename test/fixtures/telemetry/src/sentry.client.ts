import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  tracesSampleRate: 1,
  // Enable sending user PII (Personally Identifiable Information)
  sendDefaultPii: true,
});

export function identify(user) {
  Sentry.setUser({ id: user.id, email: user.email, username: user.username });
}

export function clearIdentity() {
  Sentry.setUser(null);
}

// SAFE: an opaque id only — must not be flagged
export function identifySafely(user) {
  Sentry.setUser({ id: user.id });
}
