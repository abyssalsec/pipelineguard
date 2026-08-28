package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"pipelineguard/internal/model"
)

const htmlReportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PipelineGuard Security Report</title>

<style>
:root {
  color-scheme: dark;
  --bg: #070b09;
  --panel: #0d1511;
  --panel2: #111c16;
  --border: #20352a;
  --text: #dce7df;
  --muted: #82958a;
  --green: #67f59a;
  --green2: #35ca70;
  --yellow: #e8cd69;
  --red: #ff6b72;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, sans-serif;
}

main {
  max-width: 1400px;
  margin: 0 auto;
  padding: 48px 32px 80px;
}

.brand {
  color: var(--green);
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-weight: 800;
  letter-spacing: .12em;
  margin-bottom: 8px;
}

h1 {
  margin: 0;
  font-size: 44px;
}

.subtitle {
  color: var(--muted);
  margin-top: 10px;
}

.cards {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 14px;
  margin: 36px 0;
}

.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 20px;
}

.label {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: .1em;
}

.value {
  font-size: 30px;
  font-weight: 700;
  margin-top: 7px;
}

.allow {
  color: var(--green);
}

.warn {
  color: var(--yellow);
}

.block {
  color: var(--red);
}

table {
  width: 100%;
  border-collapse: collapse;
  overflow: hidden;
  background: var(--panel);
  border: 1px solid var(--border);
}

th,
td {
  text-align: left;
  padding: 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}

th {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
}

code {
  font-family: ui-monospace, SFMono-Regular, monospace;
  color: var(--green);
}

.path {
  color: var(--muted);
}

.message {
  margin-top: 4px;
  color: var(--muted);
}

footer {
  margin-top: 32px;
  color: var(--muted);
  font-size: 13px;
}
</style>
</head>

<body>
<main>

<div class="brand">#ABSL SECURITY</div>
<h1>PipelineGuard</h1>
<div class="subtitle">
DevSecOps security gate report · generated {{.Generated}}
</div>

<div class="cards">

<div class="card">
<div class="label">Policy result</div>
<div class="value {{lower .Result.Decision}}">
{{.Result.Decision}}
</div>
</div>

<div class="card">
<div class="label">Risk score</div>
<div class="value">{{.Result.RiskScore}}/100</div>
</div>

<div class="card">
<div class="label">Findings</div>
<div class="value">{{.Result.Summary.Findings}}</div>
</div>

<div class="card">
<div class="label">Blocked</div>
<div class="value block">{{.Result.Summary.Blocked}}</div>
</div>

<div class="card">
<div class="label">Warnings</div>
<div class="value warn">{{.Result.Summary.Warnings}}</div>
</div>

</div>

<table>
<thead>
<tr>
<th>Action</th>
<th>Severity</th>
<th>Finding</th>
<th>Location</th>
<th>Analyzer</th>
</tr>
</thead>

<tbody>
{{range .Result.Findings}}
<tr>

<td class="{{lower .Action}}">
<strong>{{upper .Action}}</strong>
</td>

<td>
{{upper .Finding.Severity}}
</td>

<td>
<code>{{.Finding.ID}}</code>
<div>{{.Finding.Title}}</div>
<div class="message">{{.Finding.Message}}</div>
{{if .Finding.Evidence}}
<div class="message">Evidence: {{.Finding.Evidence}}</div>
{{end}}
</td>

<td class="path">
{{.Finding.Path}}{{if .Finding.Line}}:{{.Finding.Line}}{{end}}
</td>

<td>
{{.Finding.Analyzer}}
</td>

</tr>
{{end}}
</tbody>
</table>

<footer>
PipelineGuard {{.Result.Version}} · #ABSL Security Development
</footer>

</main>
</body>
</html>
`

type htmlReportData struct {
	Result    model.Result
	Generated string
}

func templateLower(value any) string {
	return strings.ToLower(fmt.Sprint(value))
}

func templateUpper(value any) string {
	return strings.ToUpper(fmt.Sprint(value))
}

func HTML(w io.Writer, result model.Result) error {
	tmpl, err := template.New("pipelineguard-report").
		Funcs(template.FuncMap{
			"lower": templateLower,
			"upper": templateUpper,
		}).
		Parse(htmlReportTemplate)

	if err != nil {
		return fmt.Errorf("parse HTML template: %w", err)
	}

	data := htmlReportData{
		Result: result,
		Generated: time.Now().
			UTC().
			Format(time.RFC3339),
	}

	return tmpl.Execute(w, data)
}
