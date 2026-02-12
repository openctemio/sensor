package output

import (
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ToJSON converts CTIS reports to JSON format.
func ToJSON(reports []*ctis.Report) ([]byte, error) {
	var output interface{}
	if len(reports) == 1 {
		output = reports[0]
	} else {
		output = map[string]interface{}{
			"reports": reports,
			"total_findings": func() int {
				count := 0
				for _, r := range reports {
					count += len(r.Findings)
				}
				return count
			}(),
		}
	}

	return json.MarshalIndent(output, "", "  ")
}
