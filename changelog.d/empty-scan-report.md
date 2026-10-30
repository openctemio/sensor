### Behaviour change: a scan that finds nothing still reports to the platform

- With sdk-go's empty scan report, a scan job that found nothing now pushes one empty report bound to its command (tool, version, the template release the run used, coverage), instead of nothing. The platform can then close findings a covered scan no longer sees; nothing is created on the platform.
