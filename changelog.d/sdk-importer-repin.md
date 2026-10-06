### Changed: built against the sdk-go importer release candidate

- The sensor builds against sdk-go `main` with `pkg/importtool` (the file importer as a parser-class tool) and the tool adapters running on `ctis/importer`. The sensor does not register the import tool yet: no runtime delivers task input files, so a registered parser would be inert.
