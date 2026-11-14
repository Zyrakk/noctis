# Native capture admission contract

SQL 006 adds an opt-in PostgreSQL budget. It does not activate accounts or authorize a real pilot. Migrations 001–005 remain unchanged. Existing native accounts have no implicit capture permission.

`v2 telegram collect`, `backfill`, and `resolve-source` require `--capture-policy-file` in an absolute path, with a regular mode 0600 file inside a mode 0700 directory. JSON rejects unknown fields and trailing values. `capture-policy-validate` validates that file without credentials, session, client, or database. `capture-status` reads sanitized durable counters using the database secret file; it starts no Telegram client. Authentication and read-only inventory are separate explicit operations. Authentication processes login tokens only and returns before capture recovery or actions; inventory cannot capture or initialize native cursors.

Policy version 1 has these required fields:

```json
{
  "version": 1,
  "budget_id": "00000000-0000-4000-8000-000000000001",
  "account": "EXPLICIT_ACCOUNT_ID",
  "auth_generation": "00000000-0000-4000-8000-000000000002",
  "window_seconds": 600,
  "process_seconds": 300,
  "global": {"api": 256, "observations": 1000, "payload_bytes": 67108864, "metadata_bytes": 4194304},
  "phases": {
    "control": {"api": 32, "observations": 0, "payload_bytes": 0, "metadata_bytes": 0},
    "bootstrap": {"api": 64, "observations": 100, "payload_bytes": 8388608, "metadata_bytes": 1048576},
    "live": {"api": 160, "observations": 900, "payload_bytes": 58720256, "metadata_bytes": 3145728}
  },
  "peers": [{
    "source_id": "00000000-0000-4000-8000-000000000003",
    "peer_type": "channel",
    "peer_id": 1,
    "live_epoch": "00000000-0000-4000-8000-000000000004",
    "bootstrap_epoch": "00000000-0000-4000-8000-000000000005"
  }]
}
```

This is a proposed example, not an activated policy. Account, auth generation, budget ID, peers, source identities, epochs, durations and limits are immutable after first binding. A changed/missing file, exhausted budget, or database outage cannot create a fresh implicit budget. The account link cannot be cleared or swapped. A new process retains counters and the original expiry, including downtime. Every process is additionally bounded by its own deadline, with the earlier deadline winning. Legacy import has its own archival contract and cannot reset or spend this native budget.

The unit `api` means an admitted application API operation or one control establishment operation. The control reservation commits before `telegram.Client.Run` and covers SDK-internal initialization and its retries, which are not individually metered. A one-shot public DC resolver permits only the first Primary connection and cancels on reconnect, migration, media or CDN establishment. The projection guard covers initial establishment through readiness with a 20-second total deadline; startup Self waits before acquiring its own guard, and normal operations resume only after the initial guard is released. Every public application invocation then consumes its own admission, including nested calls. The cap is not a count of internal SDK API invocations, physical MTProto packets, retransmissions or salts. Uncertain responses and process death never refund reservations. Global Differences consume global and explicit phase caps, not per-channel quotas. FloodWait persists `retry_at` and stops the client.

Startup regression checks required alongside the existing native suite are `TestNativeStartupRejectsBeforeRealRunResolverPostgres`, `TestNativeStartupRealRunSelfAndDurableControlPostgres`, `TestNativeStartupRealRunCancelClosesBeforeGuardReleasePostgres`, `TestNativeStartupRealRunRejectsReconnectBeforeBaseResolverPostgres`, `TestNativeStartupResolverRejectsAdditionalEstablishments`, and `TestNativeResolveFailurePersistsPauseAndAdmissionPostgres`. These use real gotd `Client.Run` with synthetic local MTProto or a controlled resolver; they do not contact Telegram. Auth and inventory retain their separate admission behavior and the shared session flock.

`observations` counts newly inserted observation identities. `payload_bytes` counts the payload attached to each new observation, conservatively including an already deduplicated content blob; it does not claim to measure ingress or MTProto traffic. `metadata_bytes` charges JSON metadata plus retained inbox identity text and a conservative 32-byte identity allowance, including excluded/protocol-only dispositions. Replay of a receipt or an existing inbox identity is free. Allowlist checks precede payload and metadata callbacks. A whole-batch preflight checks global and phase caps before native/capture writes; counters, inbox, observations, jobs, checkpoint and receipt then commit atomically. Exceeding any cap rolls the entire batch back.

Capture consent is separate from the current analytic policy. Each RPC collects `policy_version` and `policy_revision` under the same projection guard and transaction as admission. Responses carry that snapshot to their native commit or resolved-peer binding. A pause/resume or policy revision between response and commit rejects all publication before callbacks. A subsequent admitted RPC can use the new analytic policy with the same immutable capture consent. A policy file or stored JSON that includes the superseded `policy_version` consent field is rejected; it is never silently reinterpreted or rewritten. Spontaneous updates use current authorization atomically during their commit.

Dedicated direct PostgreSQL connections or session pooling are required. Transaction/statement pooling cannot maintain session advisory locks. AI holds the AI configuration guard `76238451004` before projection `76238451003`; native commit takes projection, account, budget, then capture locks. Network guards retain the stable session through response close, use a total deadline including lock wait, and release before publication/accounting on another connection. Cleanup has its own bounded context. Revocation that wins admission permits zero external calls; admitted E/S delays revocation until completion/cancellation. A lost database session cannot recall remotely accepted bytes. Guards serialize bounded I/O globally.

Native and inventory processes share a protected `.lock` sidecar acquired before session load and retained until client shutdown. Atomic replacement of the session file does not replace the lock inode. Local flock does not prove exclusion on another host or against a copied session. An expired PostgreSQL owner lease never proves transport closure: process death leaves `closed=false`, and takeover requires separate closure evidence. No expired-owner takeover or collector activation is introduced.

## Production consent and current-channel onboarding (007)

Migration007 adds independent production consent, period usage and private inventory tables. It preserves SQL001–006 and the v1 canonical policy bytes, 600-second window and 300-second process ceiling. Once an account explicitly selects production consent, a v1 policy cannot start capture for that account.

Production policy `version: 2` retains the v1 identity/limits/peers fields and adds `period_anchor`, `expires_at`, `predecessor` (empty on first install), `revision` (starting at1), `actor` and `reason`. The hourly period is explicit (`window_seconds:3600`); each process remains bounded to at most300seconds. `capture-consent-propose --account ACCOUNT --actor OPERATOR --reason PURPOSE` writes a protected proposal to `--capture-policy-file`, without installing it or contacting Telegram. Defaults are seven days of consent, the existing global ceilings per hour (256 API admissions,1000 observations,64MiB payload,4MiB metadata),64control admissions and192live admissions. Bootstrap capture is disabled. These conservative limits do not assert capacity for any specific channel count.

After reviewing the protected file, `capture-consent-install` explicitly installs it. Installation/renewal uses the account row lock, immutable policy digest, predecessor and revision CAS, and requires the previous owner to have recorded closure. Expired leases alone cannot authorize renewal. Repeating the same installation is idempotent. Renewal preserves generation, period anchor, global and phase limits; changing the consent ID or peer set does not reset usage. Usage is keyed by `(account_id,auth_generation,period_start)` and retained across restarts, renewals and source changes. Immutable consent versions and historical usage remain available for audit. Key-generation replacement requires the separate transition below.

`capture-consent-revoke` revokes exactly the protected policy's current ID/revision under the projection guard. Expiry or revocation stops capture and requires explicit operator action. `capture-status` exposes sanitized state, expiry, current counters and next period time. The production collector closes each gotd run and records owner closure before reopening. Exhaustion waits until the next anchored period without opening a client. Only a planned process deadline or persisted FloodWait authorizes automatic reopening; uncertain transport/database/closure failures stop the supervisor. Restarting never resets usage or replays an uncertain API reservation.

A rejected quota batch can exceed the remaining allowance before counters reach their ceilings. Its native transaction rolls back to a savepoint taken after the account lock, discarding payload, inbox, receipt, cursor and counter changes. While retaining that same lock it commits only `quota_wait_until` and `quota_wait_reason` for the rejected period. `capture-status` then reports `exhausted` with the next period even when counters remain below the cap. Admissions and restarted supervisors honor this durable wait without opening a Telegram client. The wait expires by database time at the next anchored period; expired records remain audit metadata and cannot exhaust a later period. Revocation and consent expiry take precedence over quota wait.

An unplanned production client failure also creates a durable terminal fence. `RunOwned` records an immutable failure revision with account, auth generation and consent in the same transaction that proves client closure. If recording fails, the account remains `closed=false`; a replacement process cannot assume closure. `Acquire`, policy binding and the supervisor reject an unacknowledged failure across process/Deployment restarts. `capture-status` reports `blocked` and `failure_revision`. Renewing consent does not clear this fence.

After diagnosing the failure and proving closure, an operator may explicitly run `capture-resume --failure-revision REVISION --actor OPERATOR --reason DIAGNOSIS` with the current protected `--capture-policy-file`. Resume checks the exact failure revision by CAS, current account/generation/consent identity, closed owner with no lease, and unrevoked/unexpired consent. It appends an immutable acknowledgment and changes only the acknowledged failure revision: no quota, period, cursor, epoch or receipt resets. A later uncertain failure creates a new revision and blocks replacement clients again. Resume cannot resurrect a revoked or expired consent.

Planned process completion is recognized only when the full error tree contains cancellation/deadline results caused by that process window. An `errors.Join` containing an additional error is terminal; the process-window marker cannot mask it. Only a persisted known FloodWait, a known quota denial, a pure planned process close or a completed intentional shutdown permits the corresponding controlled restart. A heartbeat/closure/persistence error remains terminal even when another joined error is retryable.

With capture stopped and all other copies of the authorization excluded, run `telegram inventory-import --actor OPERATOR` using the existing protected credential/session flags. This operation uses the durable native owner fence and local session lock, existing authorization only, and the read-only active/archived dialogs RPC allowlist. It neither logs in, joins/leaves, fetches history, nor imports legacy data. Only current channel identities, names, private access hashes, auth generation and `Dialog.Pts` baselines enter a new private snapshot. Message payloads from dialogs are not persisted. Access hashes and auth generation never appear in candidate product responses.

## Explicit generation replacement (008)

For a production account, `telegram auth` verifies the account identity and
prepares the authenticated key generation. It retains the installed generation
and consent until an explicit transition, and returns only after recording
transport closure. A prepared different key blocks both policy versions and old
inventory imports. Accounts with a bound v1 pilot budget fail authentication
preflight before any account/session mutation; pilot migration is not supported.

With all session copies excluded and any capture failure explicitly acknowledged:

1. Authenticate the replacement protected session with the existing `auth`
   command. This also prepares repair of a legacy account-B/consent-A mismatch.
2. Run `capture-generation-propose --account ACCOUNT --actor OPERATOR --reason
   REASON --transition-file /private/transition.json`. Review its account,
   account/consent/destination generations, consent ID/revision and owner fence.
3. Apply `capture-generation-transition /private/transition.json --session-file
   /private/session.json`. Local session exclusion and SQL row locking protect
   exact CAS. Closure requires `closed=true`, no owner/lease and no pending
   failure; lease expiry alone is insufficient. Repeating the same ID/content
   succeeds; changed content or an obsolete CAS fails. Revoking the predecessor,
   updating generation and appending immutable audit commit atomically, leaving
   capture pending. This never acknowledges failures or deletes historical data.
4. Run `inventory-import --actor OPERATOR` for B. Import each selected current
   candidate and explicitly approve its source policy. Reimport under a pending
   transition replaces the private key binding and pauses the source until that
   approval; source epochs and channel cursors remain unchanged. This workflow
   neither resolves a gap nor recovers history. Inventory failure while capture
   is pending cannot be attributed to the retired consent.
5. Propose/review/install B's consent using the normal commands. Its
   `generation_transition` must match the exact pending ID and its predecessor
   must identify A's audited consent. Current B inventory and authorization are
   mandatory. Installation clears the capture-pending marker atomically. Normal
   later renewal proposals omit `generation_transition` and cannot cross keys.

Rotation forfeits all remaining allowance until the next boundary of the
original one-hour period. The original anchor, window, global/phase limits and
usage history remain intact. Any later quota wait or FloodWait remains in force;
repeated rotations do not shorten it. This conservative rule deliberately does
not copy counters between generations. Neither transition nor consent
installation opens a collector. A legacy mismatch with an unacknowledged failure
remains blocked; transition does not serve as failure repair or acknowledgment.

The Sources panel lists candidates from the latest snapshot, including private channels without usernames. Selecting **Importar canal en pausa** creates an inactive source/binding only. Reload the source list, assign an existing explicit PIR policy and activate the source separately. First activation sets the live epoch/activation time and initializes channel pts from the current snapshot. Missing/zero pts rejects activation with `current_channel_baseline_required`; stale or wrong-generation snapshots reject import/activation. Reimporting an existing source preserves its enabled/pause decision, epochs and capture cursors. Consent installation requires current snapshot bindings and nonzero channel baselines. No list of legacy sources is loaded automatically.

Production refuses `MessagesGetHistory`, channel Difference with pts0, and `UpdatesChannelDifferenceTooLong` historical snapshots before materializing their messages. The latter preserves the durable channel cursor and requires intervention. Bootstrap envelopes never invoke payload/metadata callbacks for production observations. Account GetState initialization is charged to control and does not authorize history.

Focused verification uses isolated PostgreSQL16 and synthetic RPC fixtures. The real browser runner is `NOCTIS_ONBOARDING_BROWSER=1 NOCTIS_V2_TEST_DATABASE_URL=... go test ./internal/runtimev2 -run '^TestTelegramOnboardingBrowserPostgresHTTPS$'`; it exercises the empty project → candidates → paused import → explicit PIR activation flow through HTTPS and PostgreSQL, with no Telegram or AI connection. Generate the checksum fixture only when adding a migration with `python3 tools/check_v2_migrations.py --write`; normal CI checks it without rewriting SQL or fixtures.
