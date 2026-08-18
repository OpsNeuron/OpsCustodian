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
	AccessPaths     []accessPathView
	AssetCounts     []countView
	CapabilityCount int
	CredentialCount int
	OwnerCount      int
	Owners          []string
}

type accessPathView struct {
	ID, Origin, OriginName, Effect, Action, Resource, Environment string
	Steps                                                         []accessPathStepView
	Escalation                                                    bool
}

type accessPathStepView struct {
	Kind, AssetID, Name, Type string
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
	assetsByID := map[string]model.Asset{}
	for _, asset := range view.Assets {
		assetsByID[asset.ID] = asset
	}
	for _, path := range bom.AccessPaths {
		origin := assetsByID[path.Origin]
		item := accessPathView{
			ID: path.ID, Origin: path.Origin, OriginName: origin.Name, Effect: path.Capability.Effect,
			Action: path.Capability.Action, Resource: path.Capability.Resource, Environment: path.Capability.Environment,
			Escalation: accessPathEscalation(path.Capability),
		}
		for _, step := range path.Steps {
			asset := assetsByID[step.AssetID]
			item.Steps = append(item.Steps, accessPathStepView{Kind: step.Kind, AssetID: step.AssetID, Name: asset.Name, Type: asset.Type})
		}
		view.AccessPaths = append(view.AccessPaths, item)
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
	sort.Slice(view.AccessPaths, func(i, j int) bool { return view.AccessPaths[i].ID < view.AccessPaths[j].ID })
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
		"severityClass": func(severity string) string {
			switch severity {
			case "critical", "high":
				return "danger"
			case "medium":
				return "warning"
			default:
				return "safe"
			}
		},
	}
	htmlSource := strings.ReplaceAll(inventoryHTML,
		`data-action="{{.Action}} {{.Resource}}"`,
		`data-query="{{.Origin}} {{.OriginName}} {{.Action}} {{.Resource}}"`)
	htmlSource = strings.ReplaceAll(htmlSource,
		`card.dataset.origin+' '+card.dataset.action`, `card.dataset.query`)
	// Keep the embedded template portable across Windows code pages. Strip
	// non-ASCII presentation characters from the static template, then restore
	// them from stable ASCII context. Dynamic inventory values are rendered
	// later and are not modified.
	htmlSource = strings.Map(func(value rune) rune {
		if value > 127 {
			return -1
		}
		return value
	}, htmlSource)
	htmlSource = strings.ReplaceAll(htmlSource, `<span class="arrow"></span>`, `<span class="arrow">&rarr;</span>`)
	htmlSource = strings.ReplaceAll(htmlSource, `{{.BOM.Metadata.Source}}  revision`, `{{.BOM.Metadata.Source}} &middot; revision`)
	htmlSource = strings.ReplaceAll(htmlSource, `{{.Effect}}  {{.Resource}}`, `{{.Effect}} &middot; {{.Resource}}`)
	htmlSource = strings.ReplaceAll(htmlSource, `{{.Resource}}{{if .Environment}}  {{.Environment}}`, `{{.Resource}}{{if .Environment}} &middot; {{.Environment}}`)
	htmlSource = strings.ReplaceAll(htmlSource, `{{$path.Effect}}  {{$path.Resource}}`, `{{$path.Effect}} &middot; {{$path.Resource}}`)
	htmlSource = strings.ReplaceAll(htmlSource, `{{$path.Resource}}{{if $path.Environment}}  {{$path.Environment}}`, `{{$path.Resource}}{{if $path.Environment}} &middot; {{$path.Environment}}`)
	tmpl, err := template.New("inventory").Funcs(funcs).Parse(htmlSource)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, view)
}

func accessPathEscalation(capability model.Capability) bool {
	resourceWildcard := strings.Contains(strings.TrimSuffix(capability.Resource, "/*"), "*")
	if strings.HasPrefix(capability.Action, "kubernetes.non_resource_url.") {
		resourceWildcard = strings.Contains(capability.Resource, "*")
	}
	if capability.Effect == "admin" || strings.Contains(capability.Action, "*") || resourceWildcard {
		return true
	}
	for _, suffix := range []string{".bind", ".escalate", ".impersonate"} {
		if strings.HasSuffix(capability.Action, suffix) {
			return true
		}
	}
	return false
}

const inventoryHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpsCustodian Inventory</title><style>
:root{color-scheme:dark;--bg:#0a0f1c;--panel:#121a2b;--line:#26324a;--text:#e8edf7;--muted:#98a6bd;--brand:#58d5c9;--danger:#ff7272;--warning:#ffc857;--safe:#73d99f}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#172548 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.5 Inter,system-ui,sans-serif}.shell{max-width:1240px;margin:auto;padding:40px 24px 72px}header{display:flex;justify-content:space-between;gap:24px;align-items:end;margin-bottom:28px}h1{font-size:34px;margin:0;letter-spacing:-1px}.eyebrow{color:var(--brand);font-weight:700;text-transform:uppercase;letter-spacing:.12em}.meta,.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat,.panel,.asset{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:14px}.stat{padding:18px}.stat strong{display:block;font-size:28px}.section{margin-top:30px}.section h2{font-size:18px}.assets{display:grid;gap:14px}.asset{padding:20px}.asset-head{display:flex;justify-content:space-between;gap:18px}.asset h3{margin:0;font-size:18px}.badge,.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 9px;font-size:12px}.badge{color:var(--brand)}.details{display:grid;grid-template-columns:1fr 2fr;gap:20px;margin-top:18px}.caps{display:grid;gap:8px}.cap{border-left:3px solid var(--safe);background:#0d1423;padding:10px 12px;border-radius:4px 9px 9px 4px}.cap.danger{border-color:var(--danger)}.cap.warning{border-color:var(--warning)}.cap code{color:var(--text)}table{width:100%;border-collapse:collapse}.panel{padding:8px 18px}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase}.empty{color:var(--muted);padding:18px;border:1px dashed var(--line);border-radius:12px}footer{margin-top:36px;color:var(--muted)}@media(max-width:800px){.grid{grid-template-columns:repeat(2,1fr)}header,.asset-head{align-items:start;flex-direction:column}.details{grid-template-columns:1fr}}@media print{body{background:white;color:#111}.stat,.panel,.asset{background:white;border-color:#ccc}.muted,.meta,footer{color:#555}.cap{background:#f7f7f7}.cap code{color:#111}}
.access-paths{display:grid;gap:14px}.access-path{padding:20px;background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:14px}.path-head{display:flex;justify-content:space-between;gap:18px}.path-head h3{margin:0;font-size:18px}.pill.danger{border-color:var(--danger);color:var(--danger)}.pill.warning{border-color:var(--warning);color:var(--warning)}.pill.safe{border-color:var(--safe);color:var(--safe)}.filters{display:grid;grid-template-columns:2fr 1fr auto;gap:12px;margin-bottom:14px}.filters input,.filters select{width:100%;background:#0d1423;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:10px}.check{display:flex;align-items:center;gap:8px;white-space:nowrap}.path-chain{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:16px}.path-step{background:#0d1423;border:1px solid var(--line);border-radius:9px;padding:8px 10px}.path-step small{display:block;color:var(--brand);text-transform:uppercase}.arrow{color:var(--muted)}.path-capability{border-left:3px solid var(--safe);padding-left:12px}.path-capability.danger{border-color:var(--danger)}.hidden{display:none!important}@media(max-width:800px){.filters{grid-template-columns:1fr}.path-head{align-items:start;flex-direction:column}}@media print{.filters{display:none}.access-path,.path-step{background:white;border-color:#ccc}}
</style></head><body><main class="shell">
<header><div><div class="eyebrow">Agentic DevOps control plane</div><h1>OpsCustodian Inventory</h1><div class="meta">{{.BOM.Metadata.Source}} · revision {{.BOM.Metadata.Revision}}</div></div><div class="meta">Normalization {{.BOM.Metadata.NormalizationVersion}}</div></header>
<section class="grid"><div class="stat"><span class="muted">Assets</span><strong>{{len .Assets}}</strong></div><div class="stat"><span class="muted">Capabilities</span><strong>{{.CapabilityCount}}</strong></div><div class="stat"><span class="muted">Relationships</span><strong>{{len .BOM.Relationships}}</strong></div><div class="stat"><span class="muted">Access paths</span><strong>{{len .AccessPaths}}</strong></div><div class="stat"><span class="muted">Findings</span><strong>{{len .BOM.Findings}}</strong></div><div class="stat"><span class="muted">Owners</span><strong>{{.OwnerCount}}</strong></div></section>
<section class="section"><h2>Asset coverage</h2><div class="grid">{{range .AssetCounts}}<div class="stat"><span class="muted">{{.Name}}</span><strong>{{.Count}}</strong></div>{{end}}</div></section>
<section class="section"><h2>Agentic assets</h2><div class="assets">{{range .Assets}}<article class="asset"><div class="asset-head"><div><span class="badge">{{upper .Type}}</span><h3>{{.Name}}</h3><div class="muted">{{.ID}}</div></div><div><span class="pill">{{if .Owners}}{{join .Owners ", "}}{{else}}unowned{{end}}</span></div></div><div class="details"><div>{{if .Component}}<div><b>Component</b><br><span class="muted">{{.Component}}</span></div>{{end}}<p><b>Source</b><br><span class="muted">{{.Source.Path}}</span></p>{{if .Runtime}}<p><b>Runtime</b><br><span class="muted">{{.Runtime.Type}} {{.Runtime.Reference}}</span></p>{{end}}<p><b>Credentials</b><br><span class="muted">{{len .Credentials}} reference(s)</span></p><p><b>Evidence</b><br><span class="muted">{{len .Evidence}} observation(s)</span></p></div><div><b>Capabilities</b><div class="caps">{{range .Capabilities}}<div class="cap {{effectClass .Effect}}"><code>{{.Action}}</code><br><span class="muted">{{.Effect}} · {{.Resource}}{{if .Environment}} · {{.Environment}}{{end}}</span></div>{{else}}<div class="empty">No capabilities discovered.</div>{{end}}</div></div></div></article>{{else}}<div class="empty">No agentic assets discovered.</div>{{end}}</div></section>
<section class="section"><h2>Effective access paths</h2>{{if .AccessPaths}}<div class="filters"><label><span class="muted">Origin or capability</span><input id="path-search" type="search" placeholder="Filter by workload, identity, action, or resource"></label><label><span class="muted">Effect</span><select id="path-effect"><option value="">All effects</option><option>read</option><option>execute</option><option>write</option><option>delete</option><option>admin</option></select></label><label class="check"><input id="path-escalation" type="checkbox"> Escalation only</label></div><div id="path-empty" class="empty hidden">No access paths match the current filters.</div><div class="access-paths">{{range .AccessPaths}}{{$path := .}}<article class="access-path" data-origin="{{.Origin}} {{.OriginName}}" data-action="{{.Action}} {{.Resource}}" data-effect="{{.Effect}}" data-escalation="{{.Escalation}}"><div class="path-head"><div><span class="badge">ACCESS PATH</span><h3>{{.OriginName}}</h3><div class="muted">{{.ID}}</div></div><span class="pill {{if .Escalation}}danger{{end}}">{{if .Escalation}}escalation{{else}}{{.Effect}}{{end}}</span></div><div class="path-chain">{{range $index, $step := .Steps}}{{if $index}}<span class="arrow">→</span>{{end}}<div class="path-step"><small>{{$step.Kind}}</small><b>{{if $step.Name}}{{$step.Name}}{{else}}{{$step.AssetID}}{{end}}</b><div class="muted">{{$step.Type}}</div></div>{{end}}<span class="arrow">→</span><div class="path-capability {{if $path.Escalation}}danger{{end}}"><small class="muted">capability</small><br><code>{{$path.Action}}</code><div class="muted">{{$path.Effect}} · {{$path.Resource}}{{if $path.Environment}} · {{$path.Environment}}{{end}}</div></div></div></article>{{end}}</div><noscript><div class="empty">Filtering requires JavaScript; all access paths remain visible.</div></noscript>{{else}}<div class="empty">No effective access paths were correlated.</div>{{end}}</section>
<section class="section"><h2>Access graph</h2>{{if .BOM.Relationships}}<div class="panel"><table><thead><tr><th>From</th><th>Relationship</th><th>To</th><th>Confidence</th></tr></thead><tbody>{{range .BOM.Relationships}}<tr><td>{{.From}}</td><td>{{.Type}}</td><td>{{.To}}</td><td>{{.Confidence}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No relationships were correlated.</div>{{end}}</section>
<section class="section"><h2>Current-state findings</h2>{{if .BOM.Findings}}<div class="panel"><table><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Reason</th><th>Remediation</th></tr></thead><tbody>{{range .BOM.Findings}}<tr><td><span class="pill {{severityClass .Severity}}">{{upper .Severity}}</span></td><td><b>{{.Title}}</b><br><span class="muted">{{.Type}} &middot; {{.ID}}</span></td><td>{{.AssetID}}</td><td>{{.Reason}}</td><td>{{.Remediation}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No current-state findings.</div>{{end}}</section>
<section class="section"><h2>Diagnostics</h2>{{if .BOM.Diagnostics}}<div class="panel"><table><thead><tr><th>Severity</th><th>Parser</th><th>Path</th><th>Message</th></tr></thead><tbody>{{range .BOM.Diagnostics}}<tr><td>{{.Severity}}</td><td>{{.Parser}}</td><td>{{.Path}}</td><td>{{.Message}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No parser diagnostics.</div>{{end}}</section>
<footer>Generated locally by OpsCustodian. This report is read-only and contains no external scripts or network resources.</footer></main><script>(()=>{const cards=[...document.querySelectorAll('.access-path')],search=document.getElementById('path-search'),effect=document.getElementById('path-effect'),escalation=document.getElementById('path-escalation'),empty=document.getElementById('path-empty');if(!search)return;const apply=()=>{const query=search.value.trim().toLowerCase();let visible=0;cards.forEach(card=>{const text=(card.dataset.origin+' '+card.dataset.action).toLowerCase(),show=(!query||text.includes(query))&&(!effect.value||card.dataset.effect===effect.value)&&(!escalation.checked||card.dataset.escalation==='true');card.classList.toggle('hidden',!show);if(show)visible++});empty.classList.toggle('hidden',visible!==0)};search.addEventListener('input',apply);effect.addEventListener('change',apply);escalation.addEventListener('change',apply)})();</script></body></html>`
