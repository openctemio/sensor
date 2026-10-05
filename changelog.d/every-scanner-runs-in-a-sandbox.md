### Added: every scanner runs in a sandbox

The daemon confines each tool run (sdk-go `pkg/sensorkit/executor`): a private
throwaway directory, resource limits (memory, processes, file size, open
files), no_new_privs, Landlock (writes only in its directory and the paths its
wrapper declares; no read of the sensor's credentials file, outbox and key,
local policy, `-config` file, Tenable.sc connector configuration), a seccomp
filter, and a non-dumpable sensor. `SENSOR_SANDBOX=auto` (default for the
daemon), `required`, `off`; one-shot runs sandbox only when it is set. Each
scanner declares what it writes (its report directory, nuclei's private
configuration, the CodeQL database). Checked with every bundled scanner in
the image: the same templates, assets and findings with the sandbox off and
required.
