package report

import (
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

type inventoryView struct {
	BOM             model.AgentBOM
	Assets          []model.Asset
	AssetCounts     []countView
	CapabilityCount int
	CredentialCount int
	OwnerCount      int
	Owners          []string
}

type countView struct {
	Name  string
	Count int
}

func WriteInventoryHTML(w io.Writer, bom model.AgentBOM) error {
	view := inventoryView{BOM: bom, Assets: append([]model.Asset(nil), bom.Assets...)}
	types := map[string]int{}
	owners := map[string]struct{}{}
	for _, asset := range view.Assets {
		types[asset.Type]++
		view.CapabilityCount += len(asset.Capabilities)
		view.CredentialCount += len(asset.Credentials)
		for _, owner := range asset.Owners {
			owners[owner] = struct{}{}
		}
	}
	for name, count := range types {
		view.AssetCounts = append(view.AssetCounts, countView{Name: name, Count: count})
	}
	for owner := range owners {
		view.Owners = append(view.Owners, owner)
	}
	view.OwnerCount = len(view.Owners)
	sort.Slice(view.Assets, func(i, j int) bool {
		return view.Assets[i].Type+view.Assets[i].Name < view.Assets[j].Type+view.Assets[j].Name
	})
	sort.Slice(view.AssetCounts, func(i, j int) bool { return view.AssetCounts[i].Name < view.AssetCounts[j].Name })
	sort.Strings(view.Owners)
	funcs := template.FuncMap{
		"join":  strings.Join,
		"upper": strings.ToUpper,
		"effectClass": func(effect string) string {
			switch effect {
			case "admin", "delete":
				return "danger"
			case "write", "execute":
				return "warning"
			default:
				return "safe"
			}
		},
	}
	tmpl, err := template.New("inventory").Funcs(funcs).Parse(inventoryHTML)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, view)
}

const inventoryHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpsCustodian Inventory</title><style>
:root{color-scheme:dark;--bg:#0a0f1c;--panel:#121a2b;--line:#26324a;--text:#e8edf7;--muted:#98a6bd;--brand:#58d5c9;--danger:#ff7272;--warning:#ffc857;--safe:#73d99f}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#172548 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.5 Inter,system-ui,sans-serif}.shell{max-width:1240px;margin:auto;padding:40px 24px 72px}header{display:flex;justify-content:space-between;gap:24px;align-items:end;margin-bottom:28px}h1{font-size:34px;margin:0;letter-spacing:-1px}.eyebrow{color:var(--brand);font-weight:700;text-transform:uppercase;letter-spacing:.12em}.meta,.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat,.panel,.asset{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:14px}.stat{padding:18px}.stat strong{display:block;font-size:28px}.section{margin-top:30px}.section h2{font-size:18px}.assets{display:grid;gap:14px}.asset{padding:20px}.asset-head{display:flex;justify-content:space-between;gap:18px}.asset h3{margin:0;font-size:18px}.badge,.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 9px;font-size:12px}.badge{color:var(--brand)}.details{display:grid;grid-template-columns:1fr 2fr;gap:20px;margin-top:18px}.caps{display:grid;gap:8px}.cap{border-left:3px solid var(--safe);background:#0d1423;padding:10px 12px;border-radius:4px 9px 9px 4px}.cap.danger{border-color:var(--danger)}.cap.warning{border-color:var(--warning)}.cap code{color:var(--text)}table{width:100%;border-collapse:collapse}.panel{padding:8px 18px}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase}.empty{color:var(--muted);padding:18px;border:1px dashed var(--line);border-radius:12px}footer{margin-top:36px;color:var(--muted)}@media(max-width:800px){.grid{grid-template-columns:repeat(2,1fr)}header,.asset-head{align-items:start;flex-direction:column}.details{grid-template-columns:1fr}}@media print{body{background:white;color:#111}.stat,.panel,.asset{background:white;border-color:#ccc}.muted,.meta,footer{color:#555}.cap{background:#f7f7f7}.cap code{color:#111}}
</style></head><body><main class="shell">
<header><div><div class="eyebrow">Agentic DevOps control plane</div><h1>OpsCustodian Inventory</h1><div class="meta">{{.BOM.Metadata.Source}} · revision {{.BOM.Metadata.Revision}}</div></div><div class="meta">Normalization {{.BOM.Metadata.NormalizationVersion}}</div></header>
<section class="grid"><div class="stat"><span class="muted">Assets</span><strong>{{len .Assets}}</strong></div><div class="stat"><span class="muted">Capabilities</span><strong>{{.CapabilityCount}}</strong></div><div class="stat"><span class="muted">Relationships</span><strong>{{len .BOM.Relationships}}</strong></div><div class="stat"><span class="muted">Owners</span><strong>{{.OwnerCount}}</strong></div></section>
<section class="section"><h2>Asset coverage</h2><div class="grid">{{range .AssetCounts}}<div class="stat"><span class="muted">{{.Name}}</span><strong>{{.Count}}</strong></div>{{end}}</div></section>
<section class="section"><h2>Agentic assets</h2><div class="assets">{{range .Assets}}<article class="asset"><div class="asset-head"><div><span class="badge">{{upper .Type}}</span><h3>{{.Name}}</h3><div class="muted">{{.ID}}</div></div><div><span class="pill">{{if .Owners}}{{join .Owners ", "}}{{else}}unowned{{end}}</span></div></div><div class="details"><div><div><b>Source</b><br><span class="muted">{{.Source.Path}}</span></div>{{if .Runtime}}<p><b>Runtime</b><br><span class="muted">{{.Runtime.Type}} {{.Runtime.Reference}}</span></p>{{end}}<p><b>Credentials</b><br><span class="muted">{{len .Credentials}} reference(s)</span></p><p><b>Evidence</b><br><span class="muted">{{len .Evidence}} observation(s)</span></p></div><div><b>Capabilities</b><div class="caps">{{range .Capabilities}}<div class="cap {{effectClass .Effect}}"><code>{{.Action}}</code><br><span class="muted">{{.Effect}} · {{.Resource}}{{if .Environment}} · {{.Environment}}{{end}}</span></div>{{else}}<div class="empty">No capabilities discovered.</div>{{end}}</div></div></div></article>{{else}}<div class="empty">No agentic assets discovered.</div>{{end}}</div></section>
<section class="section"><h2>Access graph</h2>{{if .BOM.Relationships}}<div class="panel"><table><thead><tr><th>From</th><th>Relationship</th><th>To</th><th>Confidence</th></tr></thead><tbody>{{range .BOM.Relationships}}<tr><td>{{.From}}</td><td>{{.Type}}</td><td>{{.To}}</td><td>{{.Confidence}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No relationships were correlated.</div>{{end}}</section>
<section class="section"><h2>Diagnostics</h2>{{if .BOM.Diagnostics}}<div class="panel"><table><thead><tr><th>Severity</th><th>Parser</th><th>Path</th><th>Message</th></tr></thead><tbody>{{range .BOM.Diagnostics}}<tr><td>{{.Severity}}</td><td>{{.Parser}}</td><td>{{.Path}}</td><td>{{.Message}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No parser diagnostics.</div>{{end}}</section>
<footer>Generated locally by OpsCustodian. This report is read-only and contains no external scripts or network resources.</footer></main></body></html>`
