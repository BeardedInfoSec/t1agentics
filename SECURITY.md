# Security Policy

T1 Agentics is a security product. We take vulnerability reports seriously and respond quickly.

## Reporting a vulnerability

**Email:** `security@t1agentics.ai`

Please include:

- A description of the vulnerability
- The version and deployment configuration where you reproduced it
- Steps to reproduce, ideally with a proof-of-concept
- The impact you believe it has
- Any suggested mitigation

**Do not** file a public GitHub Issue for a security vulnerability. Public disclosure before a fix is available puts every operator at risk.

We acknowledge receipt of every report within **48 hours**. We aim to provide an initial assessment within **5 business days** and to ship a fix or mitigation within **30 days** for high-severity issues. Low-severity issues are batched into the next scheduled release.

If you do not receive an acknowledgement within 48 hours, please resend — your message may have been caught by spam filters.

## Coordinated disclosure

We follow standard coordinated disclosure:

1. You report the vulnerability privately.
2. We confirm, scope, and develop a fix.
3. We release the fix in a patch version.
4. We publish a security advisory crediting you (unless you prefer to remain anonymous).
5. After a reasonable embargo (typically 7 to 14 days post-release), full technical details may be published.

If you intend to publish your own write-up, please coordinate the timing with us so operators have a chance to upgrade first.

## Supported versions

We support the **latest minor release only**. Security fixes are backported to that version and shipped as a patch release.

| Version | Supported |
| --- | --- |
| Latest minor (e.g. `0.1.x`) | Yes |
| Anything older | No |

If you are running an older version, the supported upgrade path is to update to the latest minor.

## Scope

In scope:

- The backend API
- The frontend application
- The default Docker Compose configuration
- The connector engines and built-in connectors shipped with the platform
- The platform admin and tenant admin surfaces

Out of scope:

- Vulnerabilities in your own infrastructure (host OS, network, DNS)
- Vulnerabilities in third-party connectors you have authored or installed from outside this repo
- Denial of service from intentionally malformed input that requires platform-admin credentials
- Social engineering, physical attacks, or attacks against our hosted services that are not part of the open-source distribution

## PGP key

If you prefer to encrypt your report:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP key will be published here when available — until then, please email
plaintext and we will respond with an encrypted channel if needed.]
-----END PGP PUBLIC KEY BLOCK-----
```

Fingerprint: `TBD`

## Hall of fame

We credit researchers who report valid vulnerabilities, with their permission.

_No reports have been acknowledged yet. Be the first._
