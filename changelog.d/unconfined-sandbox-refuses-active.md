### Security: on a host without the tool sandbox, tools that contact their targets are refused unless the operator turns it off

- The tool sandbox is Linux only. With `SENSOR_SANDBOX=auto` (the default) on macOS or Windows every tool ran as a plain process with only a start-up warning. Tools of tier T1 and above (nuclei, httpx, katana, naabu, retests and validations) are now refused there with the reason `unconfined_sandbox`; passive lookups (rdap, asn, subfinder, dnsx) and code scanners still run (sdk-go).
- `SENSOR_SANDBOX=off` is the explicit acknowledgement that every tool runs unconfined. The state is in the config report (`runtime.sandbox_unconfined`) and the manifest posture (`sandbox.unconfined`), shown on the console's sensor page.
- `SENSOR_TOOL_RUNTIME=in-process` (which skips the tool host's checks) refuses to start on such a host unless `SENSOR_SANDBOX=off`.
- Upgrade note: a macOS or Windows sensor that runs active scans must set `SENSOR_SANDBOX=off` to keep running them.
