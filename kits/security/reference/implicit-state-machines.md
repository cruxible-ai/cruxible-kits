# Implicit State Machines

Reference for hunters: optional strategy, not a rule.

Most codebases have state machines nobody designed as one. Finding them during reconnaissance, before class-based hunting starts, surfaces business-logic and access-control bugs that scanners miss.

## Finding them

Look for:
- **Status columns** (`status`, `state`, `stage`) and every handler that writes them.
- **Boolean flags and nullable timestamps** that encode a transition rather than a fact: `verified`, `paid`, `locked`, `deleted_at`, `approved_at`, `cancelled_at`. A null-to-non-null write is a transition even without a `status` column.
- **Multi-request flows tied by a session or token**: checkout, onboarding, password reset, OAuth callback, multi-step forms. The token or session ID is the state carrier between requests.
- **Cached or derived state meant to track a source**: a denormalized counter, a materialized view, a search index entry, a permission cache keyed to a role that can change.

For each one found, write down:
1. Its states, including implicit ones like "never started" and "abandoned mid-flow."
2. The code location that performs each transition.
3. Who may trigger each transition — which principal, from which entry point.

## Checking them

For each machine:
- Is every transition enforced at the trust boundary, not just reachable from it? A transition guarded in the normal UI path but reachable through an admin tool, import, batch job, or legacy endpoint without the same check is a candidate finding.
- What does a **concurrent** transition do — two requests racing to move the same record out of the same state? Is the check-then-act atomic?
- What does a **replayed** transition do — the same request submitted twice (double-click, retry, a captured request replayed)?
- What does a **retried** transition do after a timeout or partial response — does the client's retry collide with a server-side effect that already happened?
- What does a **partially failed** transition leave behind — if step 2 of 3 fails, is step 1 rolled back, or does the record sit in an invalid intermediate state?
- Are there **terminal states** (cancelled, deleted, refunded, closed) that transitions should never leave? Confirm no code path re-enters a terminal state from a different trigger.

## Coverage

Treat each state machine crossing a trust boundary as its own coverage unit: one unit per machine × boundary, with the concern named after the machine (for example `concern: order-status-transitions` or `concern: invite-token-lifecycle`). If a transition can't be checked yet — the handler is unreachable without a specific role, or it needs a live fixture to exercise — note it as blocked coverage naming the missing fact, rather than leaving the unit silently unchecked.
