package report

import (
	_ "embed"
	"encoding/json"
	"strings"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

//go:embed assets/template.html
var templateHTML string

type htmlPayload struct {
	Comparison  *model.ComparisonReport `json:"comparison"`
	Explanation *ai.ExplanationReport   `json:"explanation"`
}

// GenerateHTML generates a standalone, interactive, self-contained HTML report.
// It embeds the comparison report, diagnostic explanation, and markdown post-mortem
// directly into the HTML document, enabling offline viewing via file:// without
// any web server or external runtime dependencies.
func GenerateHTML(comp *model.ComparisonReport, exp *ai.ExplanationReport) string {
	payload := htmlPayload{
		Comparison:  comp,
		Explanation: exp,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		payloadJSON = []byte("{}")
	}

	mdReport := GenerateMarkdown(comp, exp)
	mdJSON, err := json.Marshal(mdReport)
	if err != nil {
		mdJSON = []byte(`""`)
	}

	injection := "<script>\n" +
		"  window.__NETDIFF_DATA__ = " + string(payloadJSON) + ";\n" +
		"  window.__NETDIFF_MD__ = " + string(mdJSON) + ";\n" +
		"</script>\n"

	// Inject right before the closing </head> tag
	if strings.Contains(templateHTML, "</head>") {
		return strings.Replace(templateHTML, "</head>", injection+"</head>", 1)
	}

	return injection + templateHTML
}
