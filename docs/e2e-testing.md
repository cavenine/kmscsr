# End-to-End Testing Against AWS KMS

The unit tests mock the KMS client, so they prove the library builds a
well-formed request but not that AWS accepts the key, signs with it, or returns
a signature the CSR can carry. This document records an end-to-end run against a
real AWS account and describes how to repeat it.

## Last Run

| | |
| --- | --- |
| Date | 2026-08-08 |
| Region | `us-east-1` |
| Keys | `RSA_2048` and `ECC_NIST_P256`, both `SIGN_VERIFY`, customer managed |
| Go | 1.26.5 |
| AWS CLI | 2.36.19 |
| Verifier | OpenSSL 3.0.13 |
| Result | All checks passed |

Account identifiers are redacted throughout as `xxxxxxxxxxxx`, and IAM principal
names as `USER_NAME`. Substitute your own.

## Results

### CLI

| Check | Key | Outcome |
| --- | --- | --- |
| Full subject (all nine fields), two DNS SANs, IPv4 and IPv6 SANs, `--output` to file | RSA 2048 | Passed |
| Minimal subject, one DNS SAN, PEM to stdout | ECC P-256 | Passed |
| `--ca` | ECC P-256 | Passed |
| `--timeout 1ms` fails with one `error:` line and no usage text | RSA 2048 | Passed |
| Missing required flag still prints usage | n/a | Passed |
| Output file created with `0600` permissions | RSA 2048 | Passed |

Every generated CSR was verified independently:

```
$ openssl req -in request.csr -noout -verify
Certificate request self-signature verify OK
```

The RSA request decoded to the expected structure:

```
Subject: C = US, ST = Florida, L = Tampa Bay, street = 1 Example Street,
         postalCode = 33601, O = CaveNine, OU = Engineering,
         CN = e2e-rsa.example.com, emailAddress = admin@example.com
Requested Extensions:
    X509v3 Basic Constraints:
        CA:FALSE
    X509v3 Key Usage: critical
        Digital Signature, Key Encipherment
    X509v3 Extended Key Usage:
        TLS Web Server Authentication, TLS Web Client Authentication
    X509v3 Subject Alternative Name:
        DNS:www.example.com, DNS:api.example.com,
        IP Address:192.0.2.1, IP Address:2001:DB8:0:0:0:0:0:1
Signature Algorithm: sha256WithRSAEncryption
```

Two details worth noting in that output: `CA:FALSE` confirms basic constraints
are requested on non-CA CSRs, and the IPv4 SAN renders as `192.0.2.1` rather
than an IPv4-mapped IPv6 address, confirming the four-byte encoding.

The `--ca` request produced `Basic Constraints: critical, CA:TRUE`, key usage
`Certificate Sign, CRL Sign`, and extended key usage `OCSP Signing`.

### Key provenance

The public key was pulled straight from KMS and byte-compared against the key
embedded in each CSR. Both matched exactly, confirming the request is bound to
the KMS key rather than to something generated locally:

```bash
aws kms get-public-key --key-id "$ARN" --query PublicKey --output text \
  | base64 -d | openssl pkey -pubin -inform DER -outform PEM > kms.pem
openssl req -in request.csr -noout -pubkey > csr.pem
cmp kms.pem csr.pem
```

### Library

These paths are unreachable from the CLI, which requires a non-empty common
name, so they were driven through the package API:

| Check | Outcome |
| --- | --- |
| Empty subject marks the SAN extension critical (RFC 5280 §4.2.1.6) | Passed |
| `HashAlgo` override to `RSASSA_PKCS1_V1_5_SHA_384` | Passed |
| `HashAlgo` override to `RSASSA_PKCS1_V1_5_SHA_512` | Passed |
| ECDSA algorithm on an RSA key is rejected | Passed |
| Symmetric key produces an error rather than a panic | Passed |
| Nonexistent key ARN produces an error rather than a panic | Passed |

## Open Finding

Pointing the tool at a **symmetric** KMS key produces an unhelpful message. AWS
rejects `GetPublicKey` for symmetric keys with an `UnsupportedOperationException`
carrying an empty body, and the wrapped error inherits that emptiness:

```
failed to load public key from KMS: could not get public key from KMS:
operation error KMS: GetPublicKey, https response error StatusCode: 400,
RequestID: ..., UnsupportedOperationException:
```

Nothing states that the key must be asymmetric with `SIGN_VERIFY` usage. The
existing usage check in `loadPublicKey` cannot help here because
`GetPublicKey` fails before it runs. Detecting this API error and replacing it
with a message naming the requirement would remove a likely support question.

## Reproducing

### 1. Assume the test role

A dedicated role, `kmscsr-e2e-test`, carries exactly the permissions this
procedure needs. See [Test Role](#test-role) for its scope and limits.

```bash
eval "$(aws sts assume-role \
  --role-arn "arn:aws:iam::xxxxxxxxxxxx:role/kmscsr-e2e-test" \
  --role-session-name kmscsr-e2e \
  --query 'Credentials.[
      `export AWS_ACCESS_KEY_ID=` && AccessKeyId,
      `export AWS_SECRET_ACCESS_KEY=` && SecretAccessKey,
      `export AWS_SESSION_TOKEN=` && SessionToken]' \
  --output text | tr '\t' '\n')"

aws sts get-caller-identity   # should show .../kmscsr-e2e-test/kmscsr-e2e
```

Sessions last one hour. **The account root user cannot assume roles** — AWS
rejects the call with `Roles may not be assumed by root accounts` — so run this
as an IAM user, not as root.

### 2. Create the keys

Asymmetric keys cost about $1/month each, prorated hourly, and **cannot be
deleted immediately** — KMS enforces a seven-day minimum deletion window. A
create-test-destroy cycle costs roughly $0.23 per key.

The `Purpose=kmscsr-e2e-test` tag below is not cosmetic: the role's permissions
are conditioned on it, so a key created without it cannot subsequently be signed
with or deleted by this role.

```bash
export RSA_ARN=$(aws kms create-key \
  --key-usage SIGN_VERIFY --key-spec RSA_2048 \
  --description "kmscsr E2E test key (RSA 2048) - safe to delete" \
  --tags TagKey=Purpose,TagValue=kmscsr-e2e-test \
  --query 'KeyMetadata.Arn' --output text)

export ECC_ARN=$(aws kms create-key \
  --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
  --description "kmscsr E2E test key (ECC P-256) - safe to delete" \
  --tags TagKey=Purpose,TagValue=kmscsr-e2e-test \
  --query 'KeyMetadata.Arn' --output text)
```

### 3. Run and verify

```bash
go build -o /tmp/kmscsr ./cmd/kmscsr

/tmp/kmscsr --kms-arn "$RSA_ARN" \
  --common-name "e2e-rsa.example.com" \
  --organization "CaveNine" \
  --san-dns "www.example.com,api.example.com" \
  --san-ip "192.0.2.1" --san-ip "2001:db8::1" \
  --output /tmp/e2e-rsa.csr

openssl req -in /tmp/e2e-rsa.csr -noout -verify
openssl req -in /tmp/e2e-rsa.csr -noout -text
```

Repeat with `$ECC_ARN`, and again with `--ca`, checking that basic constraints
become critical with `CA:TRUE`.

### 4. Clean up

```bash
for arn in "$RSA_ARN" "$ECC_ARN"; do
  aws kms schedule-key-deletion --key-id "$arn" --pending-window-in-days 7
done
```

Keys become unusable immediately and are destroyed after the window.
`aws kms cancel-key-deletion --key-id "$arn"` reverses this at any point before
the deletion date.

Confirm nothing was left behind:

```bash
aws kms list-keys --query 'Keys[].KeyId' --output text | tr '\t' '\n' \
  | xargs -I{} aws kms describe-key --key-id {} \
      --query 'KeyMetadata.[KeyManager,KeyState,KeySpec]' --output text
```

Every `CUSTOMER` managed key from the run should report `PendingDeletion`.

## Test Role

`kmscsr-e2e-test` exists so this procedure never needs account root or
administrator credentials.

| | |
| --- | --- |
| Role | `arn:aws:iam::xxxxxxxxxxxx:role/kmscsr-e2e-test` |
| Trusted principal | A single IAM user, named in the role's trust policy |
| Inline policy | `kmscsr-e2e-kms-access` |
| Max session | 1 hour |

Inspect the current trust policy to see which principal is allowed:

```bash
aws iam get-role --role-name kmscsr-e2e-test \
  --query 'Role.AssumeRolePolicyDocument' --output json
```

The policy has three statements:

- **Unscoped**, because AWS does not permit resource scoping on them:
  `kms:CreateKey`, `kms:ListKeys`, `kms:ListAliases`.
- **`kms:TagResource`**, conditioned on `aws:RequestTag/Purpose` equalling
  `kmscsr-e2e-test`, so the role can only ever apply the test tag.
- **Everything operational** — `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey`,
  `kms:Verify`, `kms:ListResourceTags`, `kms:ScheduleKeyDeletion`,
  `kms:CancelKeyDeletion` — conditioned on `aws:ResourceTag/Purpose` equalling
  `kmscsr-e2e-test`.

The practical effect is that the role **cannot sign with, describe, or delete
any key it did not create for testing**. It also holds no `kms:Decrypt`,
`kms:DisableKey`, or `kms:PutKeyPolicy`, and nothing outside KMS.

Verified with the IAM policy simulator:

| Scenario | Result |
| --- | --- |
| `Sign`, `GetPublicKey`, `DescribeKey`, `ScheduleKeyDeletion` on a key tagged `Purpose=kmscsr-e2e-test` | allowed |
| The same actions on an untagged key | implicitDeny |
| The same actions on a key tagged `Purpose=production` | implicitDeny |
| `CreateKey`, `ListKeys` | allowed |
| `TagResource` with `Purpose=kmscsr-e2e-test` | allowed |
| `TagResource` with `Purpose=production` | implicitDeny |
| `kms:Decrypt`, `kms:DisableKey`, `kms:PutKeyPolicy` | implicitDeny |
| `iam:CreateUser`, `s3:GetObject`, `sts:AssumeRole` | implicitDeny |

Re-run those checks after editing the policy:

```bash
ROLE=arn:aws:iam::xxxxxxxxxxxx:role/kmscsr-e2e-test
KEY=arn:aws:kms:us-east-1:xxxxxxxxxxxx:key/11111111-2222-3333-4444-555555555555

# Expect: allowed
aws iam simulate-principal-policy --policy-source-arn "$ROLE" \
  --action-names kms:Sign kms:ScheduleKeyDeletion --resource-arns "$KEY" \
  --context-entries 'ContextKeyName=aws:ResourceTag/Purpose,ContextKeyValues=kmscsr-e2e-test,ContextKeyType=string' \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text

# Expect: implicitDeny
aws iam simulate-principal-policy --policy-source-arn "$ROLE" \
  --action-names kms:Sign kms:ScheduleKeyDeletion --resource-arns "$KEY" \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
```

### Changing who can assume the role

Edit the trust policy rather than widening the permission policy. Replace the
principal with the IAM user or role that should be allowed:

```bash
aws iam update-assume-role-policy --role-name kmscsr-e2e-test \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::xxxxxxxxxxxx:user/USER_NAME"},
      "Action": "sts:AssumeRole"
    }]
  }'
```

The assuming principal also needs `sts:AssumeRole` on this role ARN in its own
IAM policy.

### Removing the role

```bash
aws iam delete-role-policy --role-name kmscsr-e2e-test --policy-name kmscsr-e2e-kms-access
aws iam delete-role --role-name kmscsr-e2e-test
```
