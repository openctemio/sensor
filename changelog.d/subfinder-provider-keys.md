### Added: subfinder uses the organization's source keys

- subfinder declares a credential for each passive source that takes a key
  (tool descriptor 2.1.0). Each task gets the keys of the job's organization
  from the platform (and, on the organization's own sensor, the operator's
  keys for the sources it left unset), written into a provider configuration
  in the task's own directory (0600, removed with it) and passed with `-pc`.
  The task log lists each source's results, requests and errors.

### Security: subfinder never reads the host user's provider configuration

- Out of process, every subfinder task now reads only its own provider
  configuration, so keys in the sensor user's `~/.config/subfinder` are no
  longer used for every organization's scans on a shared sensor. Move such
  keys to the platform (Settings, Scanning, Tool source keys).
