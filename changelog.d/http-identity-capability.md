### Added: the sensor reports http.identity@1

- A sensor whose tools run out of process (through the tool host) advertises `http.identity@1`: every request of its tools carries the job's User-Agent and headers, such as a bug-bounty program's required identification. The platform gives jobs that carry such identification only to sensors that report it, instead of deciding by the SDK version.
