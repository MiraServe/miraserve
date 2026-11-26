# Security Policy

## Reporting a vulnerability

Please report security problems privately to **support@miraserve.org**. Do not open a public issue for a
vulnerability and do not post details publicly until a fix is available.

Include, as far as you can: the MiraServe version (`miraserve version`), the platform, the configuration
involved (with secrets removed), and the steps or request that show the problem.

There is no formal response-time commitment yet. Reports are read by the maintainer, and you will get an
answer by email.

## Supported versions

Only the latest released version receives fixes. MiraServe is pre-1.0: fixes are shipped in the next
0.1.x release, not back-ported.

## What to expect from the project

MiraServe has not been audited by an outside security firm. `docs/THREAT_MODEL.md` describes the trust
boundaries and `docs/SECURITY_AUDIT_PREP.md` maps the attack surface and records the internal review rounds.
Known issues of each release are listed at <https://miraserve.org/releases/>.
