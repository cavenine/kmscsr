# Security Audit Report

**Project:** `github.com/cavenine/kmscsr`
**Audit date:** 2026-07-11
**Review basis:** Commit `417fb8d` (`main`, tag `v0.0.1`) plus the uncommitted workflow, README, and `go.mod` changes present at audit completion
**Scope:** Go library, CLI, tests, module dependencies, release workflow, GoReleaser configuration, and the checked-in Linux executable

## Executive summary

The project has a small, understandable attack surface and makes good foundational choices: private key operations remain in AWS KMS, KMS keys are checked for `SIGN_VERIFY` usage, the implementation uses the Go standard library for X.509 processing, and CLI output files are created with mode `0600`.

The audit found no critical or high-severity issues. It found four medium-severity and three low-severity issues. The most immediate application defect is malformed ASN.1 encoding of every requested KeyUsage extension. The most immediate distribution concern is the checked-in executable: it was built from a dirty, earlier revision with Go 1.25.5 and is reported by `govulncheck` as containing vulnerable standard-library symbols.

| Severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | 4 |
| Low | 3 |
| Informational | 2 |

Recommended priority:

1. Correct KeyUsage encoding and add semantic extension tests.
2. Remove and replace the checked-in executable, then rebuild releases with a patched Go toolchain.
3. Propagate cancellation and deadlines into every AWS operation.
4. Harden the release workflow and validate signing/EKU configuration rather than silently overriding it.

## Remediation status

**Updated:** 2026-07-11
**Status:** All seven findings remediated in the current working tree

| Finding | Status | Resolution |
| --- | --- | --- |
| KMSCSR-001 | Resolved | KeyUsage now uses validated, bit-reversed DER encoding with semantic tests for every supported bit. |
| KMSCSR-002 | Resolved | Context-aware construction was added, build contexts reach KMS signing, and the CLI handles signals with a configurable 30-second default timeout. |
| KMSCSR-003 | Resolved | The tracked executable was removed and ignored; the project/release toolchain was raised to patched Go 1.26.5. |
| KMSCSR-004 | Resolved | Actions are pinned to full commit SHAs, GoReleaser is pinned to v2.17.0, unused package-write permission was removed, and release verification was expanded. |
| KMSCSR-005 | Resolved | The configured signing algorithm is validated against the public-key type and KMS-advertised algorithms; silent fallback was removed. |
| KMSCSR-006 | Resolved | Unsupported EKUs return errors, empty EKU encodings are rejected, and `ExtKeyUsageAny` is encoded explicitly. |
| KMSCSR-007 | Resolved | Email, street address, and postal code are encoded and covered by CSR round-trip tests. |

Post-remediation verification passes unit tests, the race detector, `go vet`, build, strict lint, module verification, GitHub Actions validation, GoReleaser configuration validation, and `govulncheck` with no vulnerabilities found. Library coverage is 78.9%; CLI coverage is 45.5%.

## Methodology

The review included:

- Manual data-flow and trust-boundary review of all Go source.
- Review of KMS key retrieval, digest signing, CSR construction, extension encoding, input handling, and output handling.
- Review of GitHub Actions and GoReleaser supply-chain controls.
- Heuristic secret search in the current tree and Git history.
- `go test ./...`, `go test -race -cover ./...`, and `go vet ./...`.
- Source and binary vulnerability scans with `govulncheck v1.6.0`.
- Inspection of the checked-in binary's embedded Go module and VCS metadata.

No live AWS account or KMS key was used. IAM policies, key policies, CloudTrail configuration, release assets already published on GitHub, and runtime environment hardening were therefore outside the audit scope.

## Findings

### KMSCSR-001: KeyUsage extensions are encoded as invalid ASN.1 BIT STRINGs

**Severity:** Medium
**Location:** `builder.go:290-307`
**Affected behavior:** Every CSR with a nonzero `Builder.KeyUsage`, including all default CA and end-entity CSRs

`keyUsageExtension` writes `[]byte{byte(usage >> 8), byte(usage)}` with a fixed `BitLength` of 9. X.509 KeyUsage numbering is the reverse of ASN.1's bit ordering within each byte. Go's own `crypto/x509` implementation reverses each byte, omits an unused second byte, and computes the actual bit length.

The current representation is not merely a different usage value. For the defaults, it puts set bits into positions declared to be padding. DER requires those padding bits to be zero, so strict parsers reject the extension as an invalid BIT STRING. For example:

- End entity: `DigitalSignature | KeyEncipherment` (`0x05`) becomes bytes `00 05` with seven unused bits.
- CA: `CertSign | CRLSign` (`0x60`) becomes bytes `00 60` with seven unused bits.

The outer CSR still parses because `x509.ParseCertificateRequest` generally retains requested extensions as raw values. A CA that parses the extension can reject the CSR; a CA that copies it can produce an invalid certificate. This defeats the API's advertised key-usage constraint and may cause issuance failures or unusable certificates.

**Recommendation:**

- Encode KeyUsage using the same bit reversal, trimming, and bit-length calculation as `crypto/x509.marshalKeyUsage` (for example, using `math/bits.Reverse8`).
- Add table-driven tests for all nine `x509.KeyUsage` bits and the default combinations.
- In tests, ASN.1-decode the extension and assert each semantic bit with `asn1.BitString.At`; do not only assert that an extension OID exists.
- Test the resulting CSR with at least Go and OpenSSL parsing, and call `csr.CheckSignature()`.

### KMSCSR-002: Caller cancellation and deadlines are discarded for AWS calls

**Severity:** Medium
**CWE:** CWE-400 (Uncontrolled Resource Consumption)
**Location:** `builder.go:82-116`, `builder.go:182-231`, `builder.go:259-268`; `cmd/kmscsr/main.go:126-128`

`BuildWithKMS` accepts a `context.Context` but deliberately ignores it. `kmsSigner.Sign` creates a new `context.TODO()`, and the constructor also uses `context.TODO()` for AWS configuration loading and `GetPublicKey`.

As a result, canceling a request does not cancel the KMS signing operation. In a long-running service, stalled network calls can outlive their callers and accumulate resources. A sign request can also complete after the caller believes it was canceled. The CLI uses an unbounded background context, so it has no application-level deadline either.

**Recommendation:**

- Store the caller's build context on the short-lived `kmsSigner` and pass it to `KMSClient.Sign`.
- Add a context-aware constructor (or constructor option) so config loading and `GetPublicKey` also receive a caller-controlled context.
- Reject a nil context rather than replacing it silently.
- In the CLI, use `signal.NotifyContext` and a documented timeout; make the timeout configurable if KMS latency requirements vary.
- Add tests whose mock blocks until `ctx.Done()` and verify cancellation for both `GetPublicKey` and `Sign`.

### KMSCSR-003: The checked-in executable is stale, non-reproducible, and built with a vulnerable toolchain

**Severity:** Medium
**Location:** `kmscsr` repository-root executable

The repository tracks a 13 MB ELF executable. Embedded metadata from `go version -m ./kmscsr` reports:

- Go toolchain `go1.25.5`.
- VCS revision `57d106d2ea864485d59b4da39588d09ee0626ea0`, not the reviewed `417fb8d` revision.
- `vcs.modified=true`, meaning the artifact was built from a dirty worktree.
- CGO enabled, unlike the GoReleaser configuration's `CGO_ENABLED=0`.

`govulncheck -mode=binary ./kmscsr` reports 13 standard-library advisories with vulnerable symbols in this binary. Fix versions range from Go 1.25.6 through Go 1.25.12. Several affected networking and TLS symbols are present because the CLI communicates with AWS KMS. Binary-mode symbol matching can overstate practical reachability, but the artifact is unquestionably built below all listed fixed patch levels.

Tracking an opaque executable also creates a path for source/binary divergence and makes code review insufficient to establish what users execute.

**Recommendation:**

- Remove the executable from version control and add `/kmscsr` to `.gitignore`; distribute binaries only through the release pipeline.
- Rebuild supported release artifacts with Go 1.25.12 or later in the 1.25 line, or a later fully patched supported Go release.
- Replace any already-published vulnerable artifacts.
- Generate an SBOM and signed provenance/attestation for release artifacts, and document checksum/signature verification.
- Add CI that runs `govulncheck ./...` and scans the actual release binaries.

### KMSCSR-004: Release dependencies are mutable and the release token is over-permissioned

**Severity:** Medium
**CWE:** CWE-494 (Download of Code Without Integrity Check)
**Location:** `.github/workflows/release.yml:8-34`, `.goreleaser.yaml`

The release job executes three third-party actions through mutable tag references (`actions/checkout@v7.0.0`, `actions/setup-go@v6.5.0`, and `goreleaser/goreleaser-action@v7.2.3`). The GoReleaser action is additionally told to download a mutable `~> v2` GoReleaser version. A compromised upstream tag or release can therefore run with `contents: write` and publish altered binaries. The job also grants `packages: write`, although this workflow does not publish packages. The new test workflow uses similarly mutable action tags, although its read-only token limits the impact.

**Recommendation:**

- Pin every action to a reviewed full commit SHA and use an update bot to propose SHA changes.
- Pin GoReleaser to an exact reviewed version rather than a version range.
- Remove `packages: write`; set permissions at the job level and retain only `contents: write` if GitHub Releases require it.
- Consider GitHub artifact attestations or another keyless signing mechanism for release provenance.
- Run tests and vulnerability checks in a separate least-privileged job before the write-enabled release job.

### KMSCSR-005: The advertised signing algorithm setting is ignored

**Severity:** Low
**Location:** `builder.go:44`, `builder.go:111`, `builder.go:137-154`, `builder.go:350-366`

`Builder.HashAlgo` is public and documented as configurable, but it is never read. `loadPublicKey` selects SHA-256 solely from whether the public key is RSA or ECDSA and ignores both `HashAlgo` and KMS's returned `SigningAlgorithms`. A caller that selects SHA-384 or SHA-512 still gets SHA-256. For larger RSA keys or P-384/P-521 keys, this silently provides less security strength than requested. The default case in `getSignatureAlgorithm` also falls back to RSA/SHA-256 instead of rejecting an invalid value.

SHA-256 is not currently broken, which limits the severity, but silently overriding cryptographic policy is unsafe API behavior.

**Recommendation:**

- Replace `HashAlgo` with one unambiguous signing-algorithm setting, or make it private and expose a validating setter/option.
- Verify the selected algorithm is present in `GetPublicKeyOutput.SigningAlgorithms` and compatible with the parsed key and curve.
- Return an error for unknown or incompatible algorithms; never use a cryptographic fallback.
- Add tests that inspect the exact `kms.SignInput.SigningAlgorithm`, signer options, CSR signature OID, and digest length.

### KMSCSR-006: Unsupported extended usages are silently omitted

**Severity:** Low
**Location:** `builder.go:310-347`

`extKeyUsageOID` returns `nil` for unsupported values, and `extKeyUsageExtension` silently drops them. If every requested value is unsupported, the code still emits an empty EKU sequence. Callers can therefore believe a usage policy was included when it was not, and the CSR may be rejected or interpreted differently by an issuer.

**Recommendation:** Return an error identifying the unsupported value, reject an empty encoded usage list, and add tests for `ExtKeyUsageAny`, unknown numeric values, and mixed supported/unsupported inputs. If `ExtKeyUsageAny` is intentionally supported, encode its standard OID explicitly.

### KMSCSR-007: Accepted subject attributes are omitted from the signed CSR

**Severity:** Low
**Location:** `builder.go:68-78`, `builder.go:100-108`; `cmd/kmscsr/main.go:89-100`

`SubjectInfo` and the CLI accept email address, street address, and postal code, but the constructor never copies them into `pkix.Name` or another CSR attribute. This can mislead an operator or enrollment workflow into believing identity data is covered by the CSR signature when it is absent.

**Recommendation:** Encode supported fields into the subject using the appropriate X.509 OIDs, or remove the fields and CLI flags. Add a round-trip test that parses the CSR and asserts every accepted subject field. Document any identity fields that are intentionally represented as SANs rather than distinguished-name attributes.

## Informational observations

### INF-001: Local source scan found a Go standard-library advisory

The source scan used the active local toolchain, Go 1.26.4. The uncommitted `go.mod` and release-workflow changes also select Go 1.26.4 via `go-version-file`. The scan reported reachable symbols for [GO-2026-5856](https://pkg.go.dev/vuln/GO-2026-5856), fixed in Go 1.26.5. The issue concerns Encrypted Client Hello, which the project does not explicitly configure, so default AWS SDK use may not exercise the vulnerable condition. Nonetheless, `go.mod`, development environments, and CI should be upgraded to Go 1.26.5 or later in the 1.26 line before releasing.

The source scan found no called vulnerabilities in required third-party modules. It also reported [GO-2026-4970](https://pkg.go.dev/vuln/GO-2026-4970) in an imported standard-library package with no call path from this project.

### INF-002: Security regression coverage is incomplete

Library statement coverage was 74.8%, but the CLI had 0% coverage. The tests parse generated CSRs but do not call `CertificateRequest.CheckSignature`, semantically decode KeyUsage/EKU/BasicConstraints, assert KMS request parameters, exercise cancellation, or test malformed/nil KMS responses. These gaps allowed the extension and context defects above to pass.

## Original audit verification results

| Check | Result |
| --- | --- |
| `go test ./...` | Pass |
| `go test -race -cover ./...` | Pass; library 74.8%, CLI/example 0% |
| `go vet ./...` | Pass |
| `govulncheck v1.6.0 ./...` | No called third-party module vulnerabilities; one active-toolchain finding |
| `govulncheck v1.6.0 -mode=binary ./kmscsr` | 13 standard-library findings in checked-in Go 1.25.5 binary |
| Heuristic current-tree/history secret search | No credentials or private keys found; only placeholders and workflow token references |
| `golangci-lint run ./...` | Not completed: installed linter was built with Go 1.25 and panicked while loading the active Go 1.26 standard library |

## Positive controls observed

- Private key material remains inside AWS KMS.
- The KMS key's usage is checked for `SIGN_VERIFY` before CSR construction.
- KMS receives a digest with `MessageTypeDigest`, avoiding ambiguous raw-message hashing behavior.
- Public keys are parsed with `crypto/x509`, and unsupported public-key types are rejected.
- CLI output files are requested with restrictive mode `0600`.
- Errors from AWS and CSR construction are generally wrapped with useful context.
- No production use of weak hashes, disabled TLS validation, shell execution, or embedded credentials was found.

## Remediation acceptance criteria

The audit's primary findings can be considered addressed when:

- Default CA and end-entity KeyUsage extensions decode to exactly the requested Go `x509.KeyUsage` values in Go and OpenSSL.
- Canceling the context passed to construction/build cancels the associated KMS call, and the CLI responds to termination signals and timeouts.
- No executable is tracked in the source tree; all distributed binaries are built from a clean tagged commit with a currently patched Go toolchain and verifiable provenance.
- Release actions and GoReleaser are immutably pinned, and the release job has no unused write permissions.
- Unsupported or incompatible signing algorithms and EKUs produce errors rather than silent fallback or omission.
- Tests verify CSR signatures, complete subject round trips, extension semantics, and KMS request parameters.
