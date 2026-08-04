import * as Sentry from "@sentry/nextjs";

// SAFE: PII off, sampled, and gated full tracing in development only.
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  sendDefaultPii: false,
  tracesSampleRate: 0.1,
});

if (process.env.NODE_ENV === "development") {
  Sentry.init({ tracesSampleRate: 1.0 });
}
