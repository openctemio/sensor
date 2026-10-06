### Changed: SARIF results convert through the ctis importer

- SARIF written by a scanner without its own parser (CodeQL in one-shot mode) and by tools on the tool contract (`output.format: sarif`) converts with the SDK's `core.SARIFParser`, which now runs on the ctis importer, the conversion the platform uses. The findings, their asset and the report branch are unchanged; the input gets the importer's hostile-input limits, and a user and password in a SARIF `versionControlProvenance` URL no longer reach the asset.
