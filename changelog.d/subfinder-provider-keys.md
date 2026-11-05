### Added: subfinder uses the organization's source keys

- subfinder declares a credential for each passive source that takes a key
  (tool descriptor 2.1.0), exactly the subfinder providers of the secrets
  contract's registry. Each task gets the keys the signed job lists, fetched
  sealed from the platform for that task only (and, on the organization's own
  sensor, the operator's keys for the sources the job leaves to it), written
  into a provider configuration in the task's own directory (0600, removed
  with it) and passed with `-pc`. The task log lists each source's results,
  requests and errors.

### Security: subfinder reaches only the passive sources' own services

- subfinder's network class is `vendor` instead of any public host: the task's
  forwarder admits the keyless sources' hosts listed in the descriptor and, for
  each key the task received, only that provider's hosts from the registry.
  Every other host and every other name (DNS included) is refused, so a key
  cannot be sent anywhere else.
- A key is written only when it passes the registry's rules for its source
  (format, minimum length, and for a key that names a host, the source's own
  service only). A key for a source outside the registry is dropped.

### Security: subfinder never reads the host user's provider configuration

- Out of process, every subfinder task now reads only its own provider
  configuration, so keys in the sensor user's `~/.config/subfinder` are no
  longer used for every organization's scans on a shared sensor. Move such
  keys to the platform (Settings, Integrations, Data source keys).
