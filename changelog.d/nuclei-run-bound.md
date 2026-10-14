### Fixed: a long nuclei list run is no longer cut at one hour

- nuclei's own process bound was a fixed 60 minutes, so a large target list was killed long before the job's budget ran out and only the output so far was kept. The bound is now the tool manifest's `resources.timeout` (24 h); the job's budget and overrun, which the platform sets, decide how long a run may take.
