### Fixed: httpx no longer waits about 30 s per target in a confined task

- httpx's JARM probes dial the host directly and do not use `-proxy`. In a task whose network is confined to its forwarder they have no route, so every target with an HTTPS service waited about three times httpx's timeout (30 s) for a fingerprint that never came; a 72-target probe took close to an hour. With a proxy (confined, or an explicit one) httpx is no longer asked for JARM. Unconfined probes keep it.
- Through an explicit proxy, JARM's direct connections went around the proxy; they no longer do.
