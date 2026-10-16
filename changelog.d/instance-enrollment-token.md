### Added: enroll a shared sensor with SENSOR_INSTANCE_ENROLLMENT_TOKEN

- A sensor with no identity and `SENSOR_INSTANCE_ENROLLMENT_TOKEN` set (a single-use token a super administrator issued, or one the install registered for its bundled sensor) pairs with its own key and is enrolled as a shared sensor of the instance, without a further approval (sdk-go `sensorkit`, api RFC-100 §7). The token is never printed, cannot be combined with `SENSOR_PAIRING_CODE`, and is ignored once the sensor is paired.
- sdk-go pinned to the commit that adds it.
