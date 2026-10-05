### Added: pair the sensor instead of pasting an API key (api RFC-052)

- `openctemio-sensor pair [CODE]`: the sensor creates its own Ed25519 key
  (`<state dir>/identity/`, 0600 files in a 0700 directory) and prints a code
  and a fingerprint; an administrator compares the fingerprint and approves
  it under Sensors > Pair a sensor. With a code from "Expect a sensor" it
  attaches to that code instead. `pair -repair` replaces a lost or
  compromised key.
- A daemon started without `API_KEY` pairs on first start, then signs every
  request with its key. `SENSOR_CA_FINGERPRINT` and `SENSOR_PLATFORM_KEY`
  from the install snippet pin the platform at first contact (`API_URL` must
  then use a host name).

### Behaviour change

- A server-controlled daemon without `API_KEY` no longer exits with code 2:
  it pairs. Without `API_URL` it still exits with code 2.
