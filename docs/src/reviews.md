# Pull request reviews

Two review paths share the same engine:

- **Local**: `/review` in the TUI, reviewing uncommitted changes, a commit, a branch, or a PR.
- **Hosted**: the GitHub App service `freedas-review`, which posts inline comments and a check run on pull requests in a workspace.

## Local review

```
/review              # uncommitted changes (tracked diff + untracked files)
/review <sha>        # a commit
/review <branch>     # branch diff against HEAD
/review <number>     # PR via `gh pr diff`, else the GitHub API with a stored token
```

The engine gathers the diff, reads the full file around each hunk, asks the
review agent for findings as `path:line: severity: problem. fix.`, and
validates each file/line against the diff. Severities:
`blocker|high|medium|low|nit`. `/standards-review` returns an over-engineering
delete list; `/ui-review` reports UI/UX findings; the `*-audit` variants scan
the whole repository.

## Hosted reviews

The control plane receives `POST /github/webhook`, verifies the
`X-Hub-Signature-256` HMAC against `FREEDAS_GITHUB_WEBHOOK_SECRET`, records
the delivery for replay protection, applies the workspace's review policy
(filters, drafts, `automatic`), and writes a `reviews` row in `queued`
status. Dedupe is a unique index on `(workspace_id, repo, pr_number,
head_sha)`: a `synchronize` event for an unchanged head does not double-bill.

`freedas-review` leases `queued` rows with `UPDATE ... SET status='running'
... RETURNING` (one per `--concurrency`, default 4), then:

1. Mint a repository-scoped installation token for the App (`--github-app-id`, `--github-private-key-path`).
2. Fetch the PR diff (`gh` when available, else the GitHub API base pinned by `--github-api-base`, default `https://api.github.com`).
3. Run the review agent with the policy's custom rules, context files, and linked repositories.
4. Post the review (inline comments plus summary), a `freedas/review` check run, and an optional reviewer request or auto-approval when thresholds pass.
5. Mark `completed`/`failed`/`skipped` with findings, confidence, risk, and cost; retry up to the worker's bound.

Review records store metadata and findings (findings are posted to GitHub);
the diff and transcript are never stored.

## Review policy

`GET/PATCH /reviews/config` holds per-workspace policy:

```jsonc
{
  "automatic": "opened",          // never | opened | pushes | all
  "include_drafts": false,
  "strictness": "medium",         // low | medium | high
  "filters": [],
  "custom_rules": [],
  "context_files": [],
  "linked_repositories": [],
  "summary": {},
  "status_check": null,
  "auto_approve": null
}
```

Strictness: `low` reports everything including nits; `medium` drops nits;
`high` only posts findings with `confidence >= 3` and severity `high` or
`blocker`. `status_check`/`auto_approve` gate the check-run conclusion and
the `APPROVE` review on minimum confidence and maximum risk.

## Running the worker

```bash
DATABASE_URL=postgres://... freedas-review \
  --control-url http://127.0.0.1:8080 \
  --github-app-id 123456 \
  --github-private-key-path /secrets/app.pem \
  --webhook-secret <secret> \
  --gateway-url http://127.0.0.1:8081 \
  --concurrency 4
```

`--github-app-id`, `--github-private-key-path`, `--webhook-secret`, and
`--gateway-url` are all required; the worker refuses to start without them.
