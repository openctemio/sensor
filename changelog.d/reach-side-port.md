### Fixed: a web origin is not reported unreached because of another port

- nuclei templates that try a side port of the host (for example 4040) can
  time out and make nuclei skip that host:port. The reach report matched
  that outcome to the job's target by host alone, so an origin such as
  `http://192.0.2.11:8008` that answered every request was reported
  unreached, and the platform failed the run with "No target was reachable".
  An outcome on a port other than the one the target names is no longer
  recorded for that target; host-wide outcomes and outcomes on the target's
  own port still are, and a bare name or address target keeps every port.
