# Valsec architecture

The upload API validates and expands configuration files, detects each device vendor independently, and creates one `Config` lifecycle per file. Celery dispatches each audit separately. Cisco, Juniper, and Fortinet adapters emit the shared schema; the generic adapter emits source-backed unknown findings.

The matcher checks user-and-vendor-scoped approved mappings before local Ollama is asked for proposals. Valid proposals are persisted as `probable`; missing or invalid proposals remain `unverified`. Both require operator approval. Only `confirmed` findings are assembled into the neutral configuration passed to compliance.

Framework catalogues contain deterministic predicates. The compliance engine alone produces verdict, severity, and score. Remediation selects a deterministic vendor template first, then may request a validated local Ollama configuration block marked as AI generated. Reports render persisted deterministic results.

## Seed-based neighbor discovery

Discovery is an additive evidence and orchestration layer in front of the
existing pull path. A `DiscoverySession` owns persistent `DiscoveredDevice`
records, and each successfully pulled device links to the ordinary `Config`
that Celery audits. Sessions use breadth-first traversal with hard depth and
device limits, address deduplication, per-device failure isolation, and target
resolution/pinning before every connection.

Valsec authenticates to each eligible seed over SSH and executes a fixed vendor
command set. Cisco discovery prefers CDP and then LLDP; Juniper uses LLDP;
Linux/OpenWrt uses LLDP when installed plus `ip neigh show` and
`/proc/net/arp`. Kernel neighbor evidence supplies an address, MAC, interface,
and bounded raw evidence, but does not prove that the host is a router or
identify its vendor.

An advertised vendor/profile can be processed automatically when the operator
explicitly allows reuse of the seed credentials. A passive-only candidate is
persisted as `needs_input`. The UI asks for the minimum missing fixed profile
and credentials; it never asks the operator to re-enter the discovered IP.
Valsec then revalidates the stored target and uses the same pull, `Config`
persistence, and Celery dispatch as direct ingestion. Unrelated passive hosts
can be marked `skipped`. This avoids subnet scanning, credential spraying,
vendor guessing, and a second audit implementation.

SSH devices retain their fixed vendor read commands. The legacy Cirotech
profile uses its Linux Telnet shell and the documented read-only `mib all`
configd dump. It never invokes the separate `mib commit` write operation.
Telnet is restricted to private/link-local addresses, is plaintext, and is
intended only for an isolated management LAN where the appliance offers no SSH.
Credentials remain request-local and are never stored on discovery records.
Direct pull and the earlier evidence/revalidation endpoints remain available
for compatibility.
