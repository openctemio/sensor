### Added: httpx fetches web content for the capability monitor.web_content@1

- httpx now implements `monitor.web_content@1`. For that capability only, it asks httpx for the response (`-irr`, read at most 5 MiB with `-response-size-to-read`), skips the favicon and JARM probes, and reports per URL: the input URL, final URL, status, content type, size, the SHA-256 of the bytes read and, for text, HTML, JavaScript and JSON only, a body of at most 512 KiB (`web_content` asset property). Other jobs run exactly as before.
- The raw output the sensor keeps now drops the `body`, `request` and `raw_header` members of httpx lines, as it already dropped `header`; the body never reaches a log line. Needs sdk-go and ctis with `monitor.web_content@1` (re-pinned).
