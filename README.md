## Go library: orgloader

A small Go library that loads organizations, engagements, and reports from JSON fixtures for a bug bounty and pentest-as-a-service platform.

### What it loads
- **organizations**: name, description, invoice email, url, slug, address, and inline SVG logos (`logo_svg`)
- **engagements**: per-organization list with `id`, `type` (Bug Bounty, Vulnerability Disclosure, Pentest), `access` (Public, Invite Only, Request Access), `title`, `briefing_markdown`, scope lists, and optional rewards
- **reports**: per-engagement arrays grouped by roles (reporter, triager, program manager) with realistic timelines and content

### Expected fixture layout
- `fixtures/organizations.json` — array of organizations
- `fixtures/engagements.json` — array where each item contains `organization_slug` and its `engagements`
- `fixtures/reports/*.json` — arrays of report entries with `engagement_id`, `reporter`, `triager`, and `program_manager`

### Import and usage
Use the module path `github.com/vuln-fixtures/fixtures` and import the loader:

```go
import (
    "github.com/vuln-fixtures/fixtures/pkg/loader"
)

func main() {
    // The JSON fixtures are embedded in the module; the argument is ignored
    // and kept only for compatibility. Use any string, e.g. "fixtures".
    orgs, err := loader.LoadAll("fixtures")
    if err != nil {
        panic(err)
    }
    // orgs is []Organization with linked engagements and reports
}
```

To try the included example program from the repo root:

```bash
go build -o orgloader . && ./orgloader
```

This prints a concise JSON summary of each organization, its engagements, and the number of linked reports.

### Data model (overview)
- `pkg/models.Organization` — organization metadata and `Engagements []Engagement`
- `pkg/models.Engagement` — details plus `Reports []ReportGroup`
- `pkg/models.ReportGroup` — `{ Reporter, Triager, ProgramMgr }` role sections

The structs match the JSON keys in the fixtures; adding fields to the fixtures is generally safe as unknown keys are ignored by Go’s JSON unmarshaller unless additional struct fields are later added.
