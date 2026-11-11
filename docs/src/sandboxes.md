# Cloud sandboxes

A cloud sandbox runs one task to completion on an ephemeral checkout:
queued → provisioning → running → stopped | failed | cancelled. The
sandbox-runner image does the checkout, runs `freedas run --auto --format
json`, pushes a `freedas/sandbox-<id>` branch, and opens a draft PR. Compute
bills per second with a 60-second minimum, separately from model usage.

## Control plane

Sandboxes are rows in the control-plane `sandboxes` table, created from the
dashboard (`POST /sandboxes` with `repo`, `base_branch`, `task`) when
`sandboxes_enabled` is on for the workspace, the wallet covers the 60-second
minimum, and no workspace budget would be exceeded by that minimum —
exhausted budgets reject the create with `402`. Endpoints: `GET/POST /sandboxes`, `GET /sandboxes/{id}`,
`POST /sandboxes/{id}/stop`, `POST /sandboxes/{id}/heartbeat`,
`POST /sandboxes/{id}/token` (mints the scoped model/GitHub token the runner
injects). A sandbox that misses heartbeats for 60 s is reaped as `failed`.
The workspace's `sandbox_session_limit_minutes` caps a run; past that it is
failed with `session_limit`.

## Runner

`freedas-sandbox-runner` polls the shared Postgres for `queued` rows with a
lease (`UPDATE ... status='provisioning' ... RETURNING`), runs the workload,
heartbeats while `running`, and settles compute billing into `wallet_ledger`
and `audit_log`.

```bash
DATABASE_URL=postgres://... freedas-sandbox-runner \
  --backend docker \
  --control-url http://127.0.0.1:8080 --runner-token <token> \
  --image freedas/sandbox:<version> \
  --concurrency 4 --session-limit-minutes 60 \
  --github-token <token> --push-remote origin
```

Flags: `--backend docker|k8s`, `--control-url`/`--runner-token` (both required
to mint tokens; unset runs without injection), `--image`, `--namespace`
(default `freedas-sandboxes`), `--concurrency`, `--poll-interval`,
`--session-limit-minutes`, `--agent-cmd` (default
`freedas run --auto --format json`), `--push-remote`, `--github-token`
(without it no draft PR is created), `--fixture-root` (allow local repo
paths), `--work-dir`.

## Docker backend

One container per sandbox:

- runs as UID 1000 with `--cap-drop ALL`, `no-new-privileges`, read-only root filesystem, tmpfs `/tmp`;
- bounded CPU and memory;
- bridge network (egress policy belongs to the deployment's proxy/firewall, not the container);
- the workspace bind-mounted at `/workspace`, an optional source at `/src:ro`;
- stays alive for `docker exec` steps; killed on timeout/cancel and removed on teardown.

## Kubernetes backend

One `batch/v1` Job per sandbox in `--namespace`:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: freedas-sbx-<id>
spec:
  activeDeadlineSeconds: <session-limit>
  ttlSecondsAfterFinished: 300
  template:
    spec:
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: agent
          image: <image>          # prefer a digest-pinned image
          imagePullPolicy: Always
          resources:
            limits: { cpu: "2", memory: "4Gi", ephemeral-storage: "1Gi" }
          securityContext:
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
            readOnlyRootFilesystem: true
          volumeMounts:
            - { name: workspace, mountPath: /workspace }
            - { name: tmp, mountPath: /tmp }
      volumes:
        - { name: workspace, emptyDir: { sizeLimit: "512Mi" } }
        - { name: tmp, emptyDir: { sizeLimit: "128Mi" } }
```

The Job image does the checkout/push itself with injected tokens; the runner
watches status and bills. The Job, Secret, and NetworkPolicy are deleted on
teardown, and teardown failures are logged with the sandbox id so orphaned
objects can be reconciled. The per-sandbox NetworkPolicy is default-deny
except DNS and TCP 443 to non-private space (the `ipBlock` excludes
RFC1918, loopback, link-local, and metadata ranges where the CNI honors
`except`); an FQDN-aware CNI can tighten 443 further. Sandbox ids are
validated (`[A-Za-z0-9_-]{1,64}`) before they reach object names or host
paths, and a non-finite or negative `compute_rate_usd` fails the row instead
of billing garbage.

## Tokens

The control plane mints short-lived, single-sandbox tokens: a model token
scoped to `/v1` plus the sandbox's own rows, and a repository-scoped GitHub
token. Both expire at teardown. No inbound route is opened to a sandbox.
