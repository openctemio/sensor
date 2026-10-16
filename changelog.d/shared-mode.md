### Security: shared mode for a sensor that runs jobs of many tenants

- `-shared` (or `SENSOR_SHARED_MODE=1`) switches on sdk-go's shared isolation profile. The tool sandbox, network confinement and a local policy are required. No writable state is shared between jobs. Private targets need the operator's switch and the job's zone ranges. Loopback, link-local, metadata and CGNAT addresses are never reached. The sensor advertises `shared.isolation@1`.
- Shared mode runs only jobs signed for the instance scope and this sensor, so a job-signing root or key must be pinned. Results are bound to the job's signed organization. Unsigned `zone_ranges` are ignored.
- In shared mode, `SENSOR_TOOL_RUNTIME=in-process` is refused: every tool runs out of process, in its sandbox.
- Known limit: a trivy task is refused in shared mode. trivy writes its scan cache next to the managed vulnerability database, which would be a writable cache shared between jobs. The network tools are unaffected.

### Fixed: a confined tool task dials only addresses the local policy checked

- The daemon's tool admission gives the tool host the addresses the local policy admitted (`AdmittedAddrs`). The host no longer resolves the name a second time with no check, which left a gap for DNS rebinding.
