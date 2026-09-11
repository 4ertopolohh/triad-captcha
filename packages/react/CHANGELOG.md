# Changelog

All notable changes to `@triadcaptcha/react` are documented here. The package follows Semantic Versioning and is versioned with repository tags.

## 0.2.0 - 2026-09-11

- Added the opaque logical-attempt handshake required by the hardened Django
  challenge flow while preserving the public `protectedFetch()` signature.
- Rejects malformed 428 challenge instructions and strips caller-supplied proof
  and attempt headers before the initial request.
- Preserves exact-origin policy, redirect rejection, credential mode, and a single
  automatic challenge retry.

## 0.1.1 - 2026-08-07

- Bound the default browser `fetch` to `globalThis`, preventing `Illegal invocation` failures in Chromium while preserving custom fetch implementations.

## 0.1.0 - 2026-08-07

- Initial React 18/19 SDK.
- Added same-origin protected Fetch wrapper with one challenge retry.
- Added invisible ALTCHA v2 Web Worker solver.
- Added interaction metadata collector and React hook.
- Added stable public error types.
