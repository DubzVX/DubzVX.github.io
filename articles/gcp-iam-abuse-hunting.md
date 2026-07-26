# GCP IAM Abuse — Hunting What Terraform Hides

### Why your cloud audit logs are full of legitimate noise that attackers use as cover

> **TL;DR** — In GCP, attackers don't drop payloads. They call APIs. The same APIs your CI/CD pipelines, your Terraform runs, and your applications call every day. This article breaks down the IAM abuse techniques that matter, the detection logic that actually works, and the blind spots that will get you if you're not looking for them.

---

## The core problem with cloud detection

On an endpoint, an attacker eventually touches something they shouldn't — a suspicious binary, an unusual parent-child process relationship, a LSASS memory access. The behavioral baseline is narrow enough that anomalies surface.

In GCP, the baseline is enormous. `GetIamPolicy` runs thousands of times a day. `SetIamPolicy` fires every time Terraform touches your infrastructure. `GenerateAccessToken` is called constantly by workloads running under Workload Identity Federation. The API calls that map to the most dangerous attacker techniques are the exact same calls your legitimate stack makes continuously.

This is the fundamental challenge of cloud detection: the noise isn't incidental. It's structural. And attackers know it.

IAM is the epicenter because whoever controls IAM controls everything else — compute, storage, secrets, data. A compromised service account with the right bindings doesn't need to exploit anything. It just calls APIs.

---

## The log source: what GCP actually gives you

Everything here runs against **GCP Audit Logs** ingested into Splunk via the Google Cloud TA. Every event represents an API call, and three fields carry most of the weight:

- `data.protoPayload.methodName` — the API method called. This is the central field in every query.
- `src_user` — alias for `data.protoPayload.authenticationInfo.principalEmail`. The actor.
- `data.protoPayload.status.message` — empty on success, populated on error. Useful for detecting trial-and-error permission probing.

One thing to understand before going further: **GCP Audit Logs are split into two categories with very different default states.**

Admin Activity logs are enabled by default and can't be disabled. They cover configuration changes: IAM modifications, resource creation, deployments. This is where most of the techniques in this article live.

Data Access logs cover reads — GCS object access, BigQuery queries, Secret Manager reads. They are **disabled by default** and must be explicitly enabled per service, per project. In practice, most organizations have significant gaps here. The absence of results on a Secret Manager hunt doesn't mean nothing happened — it may mean logging was never turned on.

Before drawing conclusions from clean results, validate coverage. Wiz does this well at scale across projects.

---

## IAM Enumeration: separating tools from Terraform

The recon phase of any GCP compromise runs through the IAM API. An attacker with a foothold — a compromised service account, a leaked key — will probe their own permissions before acting. The relevant methods: `GetIamPolicy`, `QueryGrantableRoles`, `ListServiceAccounts`, `TestIamPermissions`.

The naive approach is to alert on these methods. That produces an alert storm. Terraform calls `GetIamPolicy` constantly. So does your compliance tooling, your audit scripts, your onboarding automation.

**The signal that cuts through the noise is `TestIamPermissions`.**

Terraform doesn't call `TestIamPermissions`. Neither does the GCP SDK in normal operation. `TestIamPermissions` lets a caller explicitly test which permissions they hold against a resource before attempting anything — it's the fingerprinting method of choice for attack frameworks like ScoutSuite and Pacu. If you see it in your logs, someone is mapping the environment, not building infrastructure.

Beyond that single method, enumeration patterns become composite signals. A scoring approach across four dimensions works well in practice:

| Signal | Weight |
|---|---|
| `TestIamPermissions` called | High |
| User-agent outside expected set (`terraform`, `google-cloud-sdk`, internal agents) | Medium |
| Enumeration across multiple projects | Medium |
| 3+ distinct IAM methods in the same time window | Low |

The user-agent is extracted via `rex` from `_raw` because it's not surfaced as a native field in this schema. `python-requests`, `curl`, `go-http-client`, and empty user-agents all flag. The expected set for your environment will differ — build it from your own baseline, not from assumptions.

A Terraform pipeline calling `GetIamPolicy` in a loop on its own project scores zero on this model and stays invisible. An attacker using a Python script to map an organization's role bindings scores high before they've touched anything sensitive.

---

## Service Account Impersonation: the invisible pivot

This is the technique that worries me most in GCP environments, because it's both highly effective and nearly invisible without targeted detection.

If an attacker controls an identity with `roles/iam.serviceAccountTokenCreator` on a target service account, they can generate a valid access token for that SA via `iamcredentials.googleapis.com`. No private key. No key file on disk. No resource creation. The API call looks identical to the token refresh operations your workloads perform continuously.

The methods: `GenerateAccessToken`, `GenerateIdToken`, `SignJwt`, `SignBlob`.

The detection challenge is that legitimate impersonation chains are everywhere in mature GCP environments. Workload Identity Federation, deployment pipelines, cross-project service integrations — they all produce `GenerateAccessToken` events constantly.

Two filters eliminate most of the legitimate volume before any scoring:

**Self-refresh exclusion** — a service account generating a token for itself is refreshing its own credential. Normal. Excluded by comparing `src_user` to the target SA extracted from `resourceName` via `rex`.

**Intra-project, non-privileged exclusion** — a deployment SA impersonating a runner SA in the same project is a legitimate delegation pattern. The query keeps only cross-project impersonations, or intra-project impersonations where the target SA name matches high-privilege patterns: `admin`, `owner`, `terraform`, `security`, `org`, `iam`, `break-glass`.

What remains after those filters is small and worth looking at. A burst of multiple impersonations toward admin-named SAs in a short window is the clearest signal — that's not automation behaving normally, that's someone pivoting methodically.

The furtiveness of this technique is worth emphasizing: it produces no child process, no file write, no network connection outside normal GCP API traffic. On an endpoint, you'd have process telemetry and parent-child relationships to work with. Here, you have log events that look like every other log event.

---

## SetIamPolicy: persistence hiding in IaC noise

`SetIamPolicy` is the most commonly abused method for persistence in GCP. Bind an attacker-controlled identity to `roles/owner` at the organization level, and they have inherited access to every project below it — permanently, until someone explicitly removes the binding.

The detection problem is that `SetIamPolicy` is called constantly in environments using infrastructure-as-code. Every `terraform apply`, every policy change, every automated compliance remediation — all of it fires `SetIamPolicy`. The method itself carries no signal. The context around it does.

**Two filtering layers cut the legitimate volume before scoring:**

User-agent exclusion removes IaC tooling. Terraform, Pulumi, `google-cloud-sdk`, `google-api-go-client`, `terraform-provider-google` — if the user-agent matches, the event is excluded upstream of all aggregation. This alone eliminates the vast majority of events.

Domain exclusion via a lookup table handles the rest. Internal identities — your organization's service accounts, your employee accounts — are excluded by matching the domain portion of `src_user` against a maintained list. What's left should be a small, auditable set of events worth reviewing.

The scoring model then weights two dimensions: resource level and timing. A `SetIamPolicy` at `organizations/` or `folders/` scores higher than one at `projects/` — the blast radius is fundamentally different. Actions outside business hours amplify the score without being conclusive on their own.

**This is the hunt that found something in production.**

A personal Gmail account holding `roles/iam.admin` surfaced through this detection. Single session, distributed BigQuery roles to four internal accounts. Classic scenario: someone was granted admin access "temporarily" for a troubleshooting session and the binding was never cleaned up. The account had been sitting there with admin rights for an unknown period before this hunt ran.

The lesson isn't that the attacker was sophisticated — they weren't. The lesson is that without proactive hunting, that binding would have remained indefinitely. Automated detection would have caught it if the account had done something obviously malicious. Idle admin rights don't trigger anything.

---

## Service Account Key Creation: the backdoor that survives everything

User-managed SA keys are the durable persistence mechanism in GCP. Unlike impersonation tokens that rely on maintaining access to the originating identity, a key works autonomously until explicitly revoked. It survives password resets, session terminations, identity provider changes, and MFA enforcement updates.

An attacker who creates a key on an admin-scoped SA has a foothold independent of their initial access vector.

The methods to monitor: `CreateServiceAccountKey`, `ListServiceAccountKeys`, `UploadServiceAccountKey`, `DeleteServiceAccountKey`.

`CreateServiceAccountKey` is the primary signal. In environments that have properly deployed Workload Identity Federation, user-managed key creation should be essentially non-existent — WIF eliminates the need for long-lived keys entirely. A `CreateServiceAccountKey` event in a WIF environment is a finding by definition.

`UploadServiceAccountKey` is rarer and more suspicious — it indicates someone importing a key generated outside of GCP. That's an attacker introducing a credential they already control.

`DeleteServiceAccountKey` is worth monitoring as a covering tracks indicator, particularly when it follows shortly after a creation event from a different actor.

In the environment where I ran this hunt, the query returned zero results — consistent with a mature WIF deployment. Zero results here is a good answer. But "zero results" and "nothing to validate" are different things. I cross-referenced against Wiz to confirm no existing user-managed keys were sitting around from before WIF was enforced. Some were. That's a separate remediation track.

---

## BigQuery Dataset Sharing: the silent exfiltration path

This one emerged directly from the `SetIamPolicy` finding. When you confirm that an account with `roles/iam.admin` has been distributing BigQuery roles, the next mandatory question is: did any of those roles result in external data exposure?

BigQuery dataset sharing is one of the quietest exfiltration paths available in GCP. Grant read access to an external identity, and they can query your data from their own project. No file transfer. No egress alert. No quota anomaly on the source side. The only evidence is the policy modification event that granted the access.

The detection extracts added members from the JSON payload of `SetIamPolicy` events on BigQuery resources and classifies them:

**External members** — `allUsers`, `allAuthenticatedUsers`, or any email from a domain not in the internal lookup. This is immediate escalation. Public datasets or personal-account access are both findings.

**Cross-project service accounts** — an SA from a project you don't control receiving read access to your dataset is the stealthy variant. The attacker creates a GCP project, adds a SA, grants it access from inside your environment, then queries freely from the outside. No personal email involved, no public exposure — but the data is accessible.

The `SetIamPolicy` finding made this hunt mandatory, not optional. In threat hunting, findings cascade. One confirmed anomaly raises the probability of adjacent techniques being present.

---

## Secret Manager: credential collection at the end of the kill chain

Secret Manager concentrates the most sensitive non-IAM credentials in a GCP environment: API keys for third-party services, database passwords, OAuth tokens, certificates. In a GCP kill chain, it's typically the final stop — after IAM access is established, the attacker drains credentials to pivot elsewhere or to establish persistence outside GCP.

The behavioral distinction between offensive and legitimate access is consistent: **legitimate workloads know what they need and access it directly. They don't browse.**

An application calls `AccessSecretVersion` on a specific secret by name, every time it starts, with no variance. An attacker calls `ListSecrets` first to see what's available, then accesses multiple secrets across different categories. That sequence — enumerate then access — doesn't exist in normal application behavior.

Three patterns score high in this model:

**Enumerate then access** — `ListSecrets` followed by `AccessSecretVersion` in the same session. The behavioral fingerprint of a collection script.

**Write then access** — `AddSecretVersion` followed by `AccessSecretVersion`. This is credential tampering: replacing a legitimate secret with a value the attacker controls, then waiting for consuming applications to pick it up. More sophisticated than collection, and more dangerous.

**Mass access across distinct secrets** — more than five different secrets accessed in a single session. Workloads don't do this. A credential sweep does.

As with the other hunts, IaC tooling and internal domain actors are excluded upstream. What remains after those filters represents genuine anomalies in access patterns.

---

## The blind spots you need to know about

**Data Access logs are opt-in.** Admin Activity logs capture IAM modifications. Data Access logs capture the actual reads — GCS object access, BigQuery queries, Secret Manager `AccessSecretVersion`. Without them, Hunt 06 returns nothing regardless of what's happening. Before treating a clean result as confirmation that an environment is clean, verify that the relevant Data Access logs are enabled.

**User-agent filtering is brittle.** The detection logic for IAM enumeration and `SetIamPolicy` relies on user-agent exclusion to remove legitimate tooling. An attacker who knows your environment can spoof a Terraform user-agent in a scripted API call. The behavioral signals — cross-project scope, method diversity, off-hours timing — hold up better than header-based filtering. Layer both, but don't anchor your confidence in the user-agent exclusion alone.

**The domain lookup table is manual maintenance.** Every new vendor domain, new subsidiary, new partner integration has to be added explicitly or it generates false positives that erode analyst confidence in the detections. The right long-term solution is a dynamic source — an authoritative identity registry — rather than a static CSV.

---

## References

- [MITRE ATT&CK — Cloud Tactics](https://attack.mitre.org/tactics/TA0002/)
- [GCP Audit Logs Documentation](https://cloud.google.com/logging/docs/audit)
- [Pacu — Cloud Attack Framework](https://github.com/RhinoSecurityLabs/pacu)
- [ScoutSuite — Cloud Security Auditing](https://github.com/nccgroup/ScoutSuite)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
