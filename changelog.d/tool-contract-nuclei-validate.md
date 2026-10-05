### Added: nuclei re-verification runs out of process, on the tool contract

- A `validate` command that re-runs a finding's nuclei template runs in the
  task sandbox as `openctemio-sensor __openctem-tool nuclei-validate`, with the
  same safety flags as before (one signed template, one target, destructive
  tag classes excluded, rate ceiling). Outcomes, summaries, template digests
  and evidence are unchanged (parity tests compare both paths).
- `SENSOR_TOOL_RUNTIME=in-process` runs it in the sensor process again.
- The manifest is listed by `openctemio-sensor tools manifests [--json]`.

### Behaviour change: the local policy admits each re-verification

- The re-verify target is admitted against the sensor-local policy in force
  before nuclei starts (kill switch, target rules), like every ported tool.
- `tools.allow` admits `nuclei-validate` exactly when it admits nuclei (by
  name, by the name nuclei is configured under, or by `nuclei-validate`). A
  policy whose `tools.allow` leaves nuclei out now refuses re-verifications.
