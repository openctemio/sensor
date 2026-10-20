### Fixed: retests of nuclei findings no longer fail on every target of a confined sensor

- The retest's reachability check connected directly, which has no route in a tool sandbox that confines the network, so every target read as down and every item ended with no verdict. It now goes through the task's forwarder (the same way scans reach targets) and a refusal by the forwarder is reported as a refusal.
- An item on a target the sensor could not connect to now carries the reason in its verdict instead of a bare "no verdict".
