### Changed: nuclei releases a task's hosts wave by wave

- A nuclei task over several hosts runs in up to 4 waves of whole hosts, one after the other. Each wave's findings are delivered and its targets settle when the wave ends, so the platform hands those hosts to the next tool of a pipeline while later waves run. Before, every host of the task stayed held until the whole task ended.
- Measured: nuclei reports no per-host end. With the default template-spray strategy every host's last result came within 0.3 s of the end of the run, so waves are the finest release that never frees a host nuclei is still scanning.
- Cost: one template load per extra wave (about 5 s with 10 000 templates). A wave's hosts get no more request rate than a one-host task.
- A wave that fails keeps the earlier waves' results. Its targets and the later ones are unfinished and go out again.
- Needs sdk-go with `core.RunWaves`.
