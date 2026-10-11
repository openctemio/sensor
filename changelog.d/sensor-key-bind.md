### Security: a sensor with an API key moves to a key-bound identity by itself

- With sdk-go's self-binding, a sensor started with `API_KEY` makes its own Ed25519 key, binds it once (the platform retires the API key) and signs every request from then on, which also lets it use sensor protocol v3. `SENSOR_KEY_BIND=off` keeps the API key. Back up the state directory: it then holds the sensor's only credential.
- Protocol v3 remembers a failing gRPC binding (back-off from 30 minutes to 4 hours) and never falls back on an identity refusal.
