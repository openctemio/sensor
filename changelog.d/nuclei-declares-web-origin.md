### Fixed: nuclei declares the web origin assets it reports

- The nuclei tool descriptor now lists `asset:web_origin` in `produces`. Its reports carry web origins, so a platform that checks a report against the declared contract held every nuclei match (the assets and the findings on them) for review instead of filing it as a finding. Upgrade the sensor; matches already held can be approved in the results quarantine.
