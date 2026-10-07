### Fixed: pin sdk-go v0.18.0

- go.mod pointed at an sdk-go branch commit that is not on sdk-go main (the SARIF importer change, squash-merged as sdk-go #187). It now requires the released sdk-go v0.18.0, which contains that change; behaviour is unchanged.
