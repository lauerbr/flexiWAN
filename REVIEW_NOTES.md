# Review fixes – notes for deployers

This fork imports the upstream flexiWAN code and adds security, performance and dead-code fixes on top of it.

## Upstream code

| Directory | Upstream repository | Upstream commit |
|---|---|---|
| `flexiagent/` | `gitlab.com/flexiwangroup/flexiagent` | `0da70af` |
| `fleximanage/` | `gitlab.com/flexiwangroup/fleximanage` | `1309daf` |

Some parts of upstream are not included:

- The private submodules `client/`, `vpnportal/` and `backend/billing`.
- The RSA key that upstream commits as `backend/bin/cert.local.flexiwan.com/domain.key`. It was not imported.

## Where the changes are

The commit `Import flexiagent and fleximanage upstream snapshots` holds the upstream code exactly as it was. Every commit after it is a fix.

Use `git log --no-merges` to list the fixes, one topic per commit.

## Validation

**flexiManage**

- ESLint is clean.
- jest results with a local Redis:
  - 21 of 22 suites pass.
  - `deviceLogic/tests/validators.test.js` fails without MongoDB or network access. It failed the same way before these changes.
- Not tested against a real MongoDB:
  - the new index migration
  - the rewritten `devicesGET` aggregation pipeline
- Not tested against the private UI.

**flexiEdge**

- All files compile.
- pyflakes finds no new warnings. The warning count went from 274 to 168.
- The 35 new unit tests in `flexiagent/tests/unit` pass.
- The upstream test suites were not run. They need VPP and real network hardware.

## Before deploying

### flexiManage

**Secrets**

- Outside `development` and `testing`, the server refuses to start unless both of these are set, each 32 characters or longer:
  - `USER_SECRET_KEY`
  - `DEVICE_SECRET_KEY`
- If you use the webhooks, also set `WEBHOOK_ADD_USER_KEY` and `WEBHOOK_REGISTER_DEVICE_KEY`.

**HTTPS key**

- The HTTPS key must be provisioned for each install.
- If it is missing:
  - in `development`, the server generates a temporary self-signed certificate;
  - in any other environment, the server exits.

**Database migration**

- Run `npm run migrate` to build the new indexes.
- Only after that, optionally set `MONGO_AUTO_INDEX=false`.

**New configuration keys**

| Key | Default | Notes |
|---|---|---|
| `trustProxy` / `TRUST_PROXY` | `1` | Replaces the unconditional `trust proxy: true`. Set it to match your proxy hops. |
| `enableDbAdmin` / `ENABLE_DB_ADMIN` | `false` | mongo-express at `/admindb`. Also requires development mode and `ME_CONFIG_BASICAUTH_*`. |
| `deviceWsMaxPayload` | 50 MB | |
| `mongoPoolSize` | 20 | |
| `mongoAutoIndex` | `true` | |
| `haLeaderTtl` | 12000 ms | Failover now takes up to about 12 s. |
| `limitersUseRedis` | `true` | |

**Behaviour changes**

- Sessions and tokens:
  - Logging out revokes that user's refresh tokens in every session.
  - A password reset revokes the user's refresh tokens.
  - Unused password-reset links issued before the upgrade stop working.
  - Refresh tokens must be real refresh tokens. API access keys are no longer accepted on the refresh path.
- Requests that are now rejected:
  - Requests with `$`-prefixed keys get a 400 response.
  - Filters or sorts on sensitive fields get a 400 response.
  - Device websocket connections without a valid `Origin` header.
- `POST /devices/{id}/send`: only admins may use it, except for the read-only `get-device-*` APIs.
- Webhooks:
  - They no longer follow redirects.
  - They are refused when the target resolves to a private, loopback or link-local address.
- The per-org encryption-method setting is cached for up to 60 s.

### flexiEdge

**RPC socket**

- The local RPC moved from TCP `127.0.0.1:9090` to the unix socket `/run/flexiwan/fwagent.sock`.
  - The socket's directory is 0700 and the socket is 0600.
  - Only root may connect.
- `daemon_socket: host:port` settings are ignored.
- Local tools that used the port must switch to the socket.

**Runtime files**

- Volatile data moved from `/dev/shm` to `/run/flexiwan`. The agent refuses to start if that directory is not owned by it.
- The token file, SQLite databases, `hostapd.conf`, PPPoE secrets and VPN keys are now root-only (0600).

**Stricter input validation**

Invalid values are now rejected instead of being passed to shell commands or config files. This affects:

- BGP passwords (no spaces, quotes, `$` or backslash)
- route-filter descriptions
- LTE APN, user, password and PIN
- link-monitor servers and timeouts
- route addresses
- PPPoE and Wi-Fi values (no control characters)
- remote VPN and ntop app parameters
- the upgrade version string

**Registration token**

- The `server` and `repo` claims in the registration token must use https. Plain http is allowed only when `bypass_certificate` is set.
- You can restrict the allowed hosts with the new `token_allowed_hosts` setting.

**Upgrades**

- The apt repository must use https.
- To pin the repository signing key, set `SW_REPOSITORY_GPG_KEY_FINGERPRINT` in `fwupgrade.sh`.

**Other changes**

- The FRR vty password is now random. Telnet to FRR daemons with `zebra` no longer works.
- Remote VPN TLS verification can only be skipped with `setenv AUTH_SCRIPT_SKIP_TLS_VERIFY 1` in `server.conf`.
- `fwdump` archives are 0600 and no longer contain the device token files.
- Add `UMask=0077` to the systemd unit in your packaging. The repository contains no unit file.

## Deliberately not done (TODO)

### flexiManage

**Major upgrades**

- mongoose 5 → 7+ and mongodb driver 3 → 6
- Node 16 → 22 LTS (CI image)
- kue → BullMQ
- redis 3 → 4
- express 4 → 5
- nodemailer 7+
- uuid 11
- serialize-javascript 7

**Dependency replacements**

- Replace `node-zendesk`, which pulls in `request`.
- Replace `easyrsa`, which bundles node-forge 0.7.6.

**npm audit**

- It still reports 68 advisories, down from 112, of which 33 are in production dependencies.
- CI's `audit-ci` job already failed before these changes, on advisories that are not allow-listed.

**Security**

- Invite acceptance: invited users are still added without confirming.
- `validateOpenAPIRequest` is still `false`. Explicit type checks and a global `$`-key sanitizer were added instead.
- The device token is still sent in the websocket URL. Moving it to a header needs an agent protocol change.
- Swagger UI and the raw spec are still public.
- The password policy was not strengthened.

**Scaling**

- Shard the `fw-dev-info` broadcast by owning host.
- Move the express API rate limiter to Redis.
- Add response compression.
- `iterateJobsByOrg` still scans every tenant's jobs.

### flexiEdge

**Code structure**

- Split `fwutils.py`, which is over 5,000 lines, and break the circular imports.

**Config database**

- Move from pickle to JSON storage.
- Batch commits per aggregated request.

**VPP**

- Read interface statistics from the VPP stats segment.
- Move the remaining ~50 `vppctl` shell-outs to `cli_inband`.
- Batch the per-tunnel `sw_interface_dump` calls.

**Duplicate code**

- Consolidate the QoS policer blocks.
- Consolidate the two default-route query implementations.

**Optional cleanup**

- Remove the ~28k lines of unused `scripts/**/*.cli` test data.
- Squash the old migrations.
