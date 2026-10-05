### Added: httpx and nuclei run out of process, on the tool contract

httpx and nuclei are ported to the tool contract (sdk-go `pkg/tool`,
docs/rfcs/sensor-sdk-v2.md). Each scan re-executes the sensor as
`openctemio-sensor __openctem-tool <name>` inside the task sandbox; the tool
runs there and speaks adapter protocol v1 to the sensor, which checks every
record again (CTIS validity, the tool's declared output types, record and
byte limits, control characters) and stamps the provenance
(`metadata.properties.provenance`: tool, adapter version, manifest digest,
sandbox status, task). The CTIS output is the same as before (golden tests
compare both paths). nuclei's interactsh token and proxy credentials reach
the tool as declared credentials only. The manifests are compiled into the
binary and reported to the platform by digest (`tools[].contract`);
`openctemio-sensor tools manifests [--json]` prints them.
`SENSOR_TOOL_RUNTIME=in-process` runs both tools in the sensor's process as
before (rollback switch).
