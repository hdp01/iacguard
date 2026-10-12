# IaCGuard

A serverless service that scans Terraform for security misconfigurations and
uses **Amazon Nova** to explain each finding in plain language and write the
corrected code.

Upload a `.tf` file and an event-driven pipeline parses it, runs 35 security
rules against it, asks Nova for a fix per finding, and stores the result. There
is no server, and nothing runs between scans.

```
$ python3 app.py

  IaCGuard — Terraform security scanning on AWS, with Amazon Nova
  writing the fixes

Enter a .tf file, a folder, or a .zip: samples/insecure.tf

Uploading 1 file(s) to AWS (scan 8cf1f0fa81f7)

╭──────────── Scan result ─────────────╮
│ Files scanned  1                     │
│ Posture score  0/100  FAILING        │
│      Findings  6 critical  8 high    │
│   Nova tokens  6950 in / 4004 out    │
╰──────────────────────────────────────╯
```

## Architecture

```
  app.py                        (boto3, IAM auth)
       │
       │  upload uploads/<scan_id>/<file>.tf
       ▼
  ┌──────────┐   ObjectCreated   ┌──────────────────┐
  │    S3    │ ────────────────▶ │  Lambda scanner  │
  │  (KMS)   │                   │  python3.12/arm64│
  └──────────┘                   └────────┬─────────┘
                                          │
                        ┌─────────────────┼─────────────────┐
                        ▼                 ▼                 ▼
                 ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
                 │  Bedrock    │  │  DynamoDB    │  │  CloudWatch  │
                 │ Nova Lite   │  │  (on-demand) │  │ logs+metrics │
                 └─────────────┘  └──────────────┘  └──────────────┘
                                          │
                                          ▼
                               results shown in app.py
```

**Five AWS services:** S3, Lambda, DynamoDB, Bedrock, CloudWatch.
IAM and KMS secure those five rather than being features in their own right.

The scan id is generated client-side and carried in the S3 object key, which is
why the project needs no API tier: the app already knows where its own results
will appear and polls DynamoDB directly.

## Quick start

```bash
make deploy   # build the Lambda, apply the Terraform, write the config
make run      # start the app
make test     # 46 unit tests, no AWS needed
make destroy  # remove everything
```

`make help` lists every target. `make screens` captures the terminal output
of real runs as PNGs, for use in documentation. (`make deck` builds a slide
deck from them, but its generator holds presentation content rather than
project code and is not kept in this repository.)

## Using it

Run `make run` (or `python3 app.py`) and give it one of:

- a **Terraform file** — `samples/insecure.tf`
- a **folder** — scanned recursively for `.tf` files
- a **zip** — extracted safely, with path-traversal entries refused

It uploads, waits for the Lambda to finish, prints a severity-ranked table,
and then offers to show Nova's explanation and corrected code for each
finding. It loops until you type `q`.

A path can also be given as an argument for scripting:

```bash
python3 app.py ~/infra/production.zip
```

## The rule set

35 rules across S3, security groups, IAM, RDS, EC2/EBS, DynamoDB, Lambda,
CloudTrail, KMS, load balancers, EKS, and hardcoded secrets. Severity is
CRITICAL, HIGH, MEDIUM or LOW, and the posture score subtracts a weight per
finding from 100.

Rules are cross-resource aware. Modern Terraform splits S3 configuration
across sibling resources, so a missing inline attribute is only reported when
no sibling supplies it either — otherwise correct code would be flagged.

Adding a rule means adding one decorated function in `lambda/rules.py`:

```python
@rule("IAC999", HIGH, "Short title",
      "Why this matters, in plain language, for the Nova prompt.",
      "aws_some_resource")
def _(res, doc):
    if truthy(res["body"].get("dangerous_flag")):
        return "dangerous_flag = true"
    return None
```

## Why it is cheap

- Nothing is provisioned. Lambda and DynamoDB both scale to zero.
- DynamoDB is on-demand, so there is no capacity to pay for between scans.
- Nova Lite costs roughly $0.06 per million input tokens; a 23-finding scan
  uses about 3,600 input and 2,800 output tokens.
- S3 uploads expire after 7 days and scan results after 30 via DynamoDB TTL.
- CloudWatch Logs retention is 14 days, the single biggest log cost lever.
- `bucket_key_enabled` on the S3 bucket cuts KMS request charges by ~99%.

A full demo run costs a fraction of a cent.

## Security posture

- **In transit:** a bucket policy denies any request where
  `aws:SecureTransport` is false, so TLS is enforced server-side rather than
  trusted to the client.
- **At rest:** a customer-managed KMS key with annual rotation encrypts S3
  objects, the DynamoDB table and the Lambda's environment variables.
- **Public access:** all four S3 public-access-block flags are on, so the
  bucket cannot be made public by a later change.
- **Least privilege:** the Lambda role has no wildcard action and no wildcard
  resource. It can read only `uploads/*`, write only its own table, invoke only
  Nova, and publish only to the `IaCGuard` metric namespace.
- **Blast radius:** uploads expire automatically, so sensitive IaC does not
  accumulate in the account.

### Accepted findings on our own infrastructure

Scanning `infra/` with the app scores 98/100, with two LOW findings left
open deliberately:

| Rule | Why it is accepted |
|---|---|
| `IAC005` S3 access logging disabled | Needs a second bucket, which would itself be flagged for having no logging. Not worth the recursion for a scanner whose uploads expire in 7 days. |
| `IAC061` No Lambda X-Ray tracing | X-Ray would be a sixth AWS service, and the project is deliberately capped at five. |

A third finding, `IAC060` (unencrypted Lambda environment variables), was found
by the tool on its own Terraform and fixed — see `kms_key_arn` in
`infra/lambda.tf`. The score went from 94 to 98.

## Known behaviour under load

Bedrock is rate-limited per account, not per function, so concurrent scans
contend with each other. A 20-scan burst throttled Bedrock and about 10% of
findings came back without AI text. This is a graceful degradation rather than
a failure: rules are deterministic and run before any model call, so the
finding is always reported and only the explanation is missing, marked with
`ai_status`. The retry budget is 8 attempts with adaptive rate limiting.

Lambda throttles too, since S3 invokes it asynchronously and this account's
concurrency limit is 10. Those events retry with backoff and drain on their
own; the load test's 20 scans all completed.

## Layout

```
app.py                the app: prompt, upload, render
lambda/handler.py     S3-triggered entrypoint
lambda/parser.py      HCL2 parsing and normalisation
lambda/rules.py       the 35 rules
lambda/engine.py      rule execution and scoring
lambda/remediate.py   Amazon Nova calls
infra/                Terraform for all five services
samples/              insecure.tf and its hardened counterpart
scripts/              build, load test, metrics, docs
tests/                46 unit tests
```

## Notes for other accounts

- `var.lambda_reserved_concurrency` defaults to `-1`. AWS requires an account
  to keep at least 10 unreserved executions, so on a new account whose total
  limit is 10 any reservation is rejected. With the default limit of 1000, set
  it to `5`.
- Nova is reachable as plain on-demand in `us-east-1`. In some regions,
  including `ap-south-1`, it is available only through a cross-region inference
  profile, where the model id must be prefixed (`apac.amazon.nova-lite-v1:0`).
- The Lambda build pins wheels to the runtime's architecture. `python-hcl2`
  depends on `regex`, which is a compiled extension, so building x86_64 wheels
  for an arm64 function fails at import. Override with
  `LAMBDA_ARCH=x86_64 ./scripts/build_lambda.sh` if you change
  `architectures`.
