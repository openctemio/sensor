### Security: pairing saves only what the platform signed

- sdk-go with signed pairing answers: the identity, content keys, job signer
  and (with a private-CA platform) TLS roots a new pairing pins come only
  from a grant the platform signs with the pairing key whose fingerprint the
  administrator compares, bound to this sensor's key and request. Someone in
  the middle of the first pairing can no longer swap them.
- A missing, altered or replayed grant stops `pair` and auto-pairing with an
  error naming the step and `pairing_answer_unsigned`; nothing is saved.

### Behaviour change: pairing needs a platform that signs its answers

- A platform from before signed pairing answers is refused with "upgrade the
  platform". Already paired sensors are unaffected.
