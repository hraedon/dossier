# Dossier suite-console UI shell

This directory is the Phase 0 reference implementation for Plan 024. Open
`index.html` directly in a browser; it has no build step, framework, network
request, or production data dependency.

## What is stable

- six primary areas: Work, Knowledge, Activity, Evidence, Operations,
  Administration;
- semantic landmarks, skip link, heading order, accessible status text, and
  keyboard-reachable controls;
- role/scope/freshness context;
- action queue, estate summary, findings, and provider-state patterns;
- explicit warning, failure, unknown, stale, and partial states;
- narrow-screen content priority;
- the rule that high-risk actions lead to a review page rather than executing
  inline.

Production templates should implement these concepts through typed view models
and server-rendered routes. Tests should assert accessible names, route results,
status/freshness semantics, and authorization—not CSS class names or pixel
positions.

## What is disposable

Everything visual: colors, typography, spacing, card treatment, grid, icons,
density, and responsive composition. `shell.css` intentionally contains all
visual decisions in one file. A later design pass may replace it wholesale.

## Prototype limits

- All data is synthetic and static.
- Links are illustrative and do not target production routes.
- It is a role-aware information-architecture example, not an authorization
  implementation.
- It does not model secret/private-key entry because those values are prohibited
  from the browser surface.
- It is not a second application and should not acquire a backend.

## Implementation sequence

1. Add typed shell/navigation/status/freshness view models.
2. Decompose the production base template into semantic shell macros.
3. Move current Work pages into the shell without changing their gateway logic.
4. Implement each remaining area against its component provider contract.
5. Add accessibility and golden-journey tests.
6. Replace the visual layer after the semantic contract is stable.
