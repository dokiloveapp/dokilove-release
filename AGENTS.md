# Public automation repository

All tracked files, commits, workflow definitions, run metadata, logs, artifacts, and caches are public.

- Commit generic automation only. Never commit application source, private repository identifiers, source history, infrastructure addresses, credentials, or runtime configuration.
- Runtime requests must be authenticated and encrypted. Keep plaintext configuration and diagnostics in restricted temporary files.
- Print only fixed phase messages. Do not print raw subprocess output or error objects.
- Upload only authenticated encrypted diagnostics. Do not use public Actions caches for private source, dependencies, or image layers.
- Validate immutable source references and request shape before executing application code.
- Use GitHub-hosted runners. Bound build resources and retain migration, deployment, readiness, and rollback checks in the private execution code.
- Preserve the independent account identity. Do not copy application Git history or use another account's author identity.
