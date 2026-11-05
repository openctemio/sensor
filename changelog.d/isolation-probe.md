### Added: the sensor proves its isolation backends at start-up

- At start-up the sensor runs a confined task on each isolation backend it has and reports the outcome as the config check `runtime.isolation` (the process sandbox today). It advertises `isolation.strong@1` only when a strong backend passed its probe; no setting can add it. No strong backend ships yet, so no sensor advertises it, and jobs of a tool that needs strong isolation (none yet) wait for another sensor.
