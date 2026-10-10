### Security: port- and path-limited targets enforced by the task sandbox

- A sensor whose tools run out of process in a sandbox that confines their network advertises `scope.limits@1` in its manifest. The platform then sends it crawler, template and top-ports jobs on targets that only port- or path-limited scope entries cover, with the limits in the signed job (sdk-go `pkg/scopelimit`).
- The limits come from the verified signed statement only. The task's forwarder refuses other ports of a limited host and every HTTP request outside the path prefixes, terminating TLS. A job with limits is refused for a tool run in the sensor process (`SENSOR_TOOL_RUNTIME=in-process`), a recon tool not on the tool contract, a raw-socket naabu scan, or a sandbox without network confinement.
- The tools are also told to keep inside: naabu scans the limited ports instead of its top-N list, and katana crawls under the limited path prefixes. Enforcement does not depend on these flags.
- sdk-go bumped for `pkg/scopelimit`, the statement limits and the forwarder's path guard.
