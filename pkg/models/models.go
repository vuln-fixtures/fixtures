package models

type Organization struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	InvoiceEmail string      `json:"invoice_email"`
	URL         string       `json:"url"`
	Slug        string       `json:"slug"`
	Address     string       `json:"address"`
	LogoSVG     string       `json:"logo_svg"`
	Engagements []Engagement `json:"engagements"`
}

type Engagement struct {
	ID               string        `json:"id"`
	Type             string        `json:"type"`
	Access           string        `json:"access"`
	Title            string        `json:"title"`
	BriefingMarkdown string        `json:"briefing_markdown"`
    InScope          []Scope       `json:"in_scope"`
    OutOfScope       []Scope       `json:"out_of_scope"`
    Rewards          []RewardTier  `json:"rewards"`
	Reports          []ReportGroup `json:"reports"`
    Abstract         string        `json:"abstract"`
}

// Scope represents a single asset or endpoint with CIA impact hints
type Scope struct {
    URL              string `json:"url"`
    Name             string `json:"name"`
    Description      string `json:"description"`
    Confidentiality  string `json:"confidentiality"`
    Integrity        string `json:"integrity"`
    Availability     string `json:"availability"`
}

type RewardTier struct {
    Severity string  `json:"severity"`
    From     float64 `json:"from"`
    To       float64 `json:"to"`
}

type ReportsFile struct {
	EngagementID string       `json:"engagement_id"`
	Reporter     ReporterPart `json:"reporter"`
	Triager      TriagerPart  `json:"triager"`
	ProgramMgr   ProgramPart  `json:"program_manager"`
}

type ReportGroup struct {
	Reporter   ReporterPart `json:"reporter"`
	Triager    TriagerPart  `json:"triager"`
	ProgramMgr ProgramPart  `json:"program_manager"`
}

type ReporterPart struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Summary     string                 `json:"summary"`
	Context     map[string]any         `json:"context"`
	Affected    []string               `json:"affected_assets"`
	Steps       []string               `json:"steps_to_reproduce"`
	PoC         map[string]any         `json:"proof_of_concept"`
    Impact      Impact                 `json:"impact"`
	Mitigation  []string               `json:"mitigation"`
	Comments    []TimedComment         `json:"comments"`
}

type TriagerPart struct {
	Status   string         `json:"status"`
    Impact   Impact         `json:"impact"`
	Timeline []TimedEvent   `json:"timeline"`
	Comments []TimedComment `json:"comments"`
}

type ProgramPart struct {
    Impact   Impact         `json:"impact"`
	Feedback []string       `json:"feedback"`
	Comments []TimedComment `json:"comments"`
}

// Impact captures standardized fields commonly present in reports
type Impact struct {
    Description      string   `json:"description,omitempty"`
    PotentialExploits []string `json:"potential_exploits,omitempty"`
    CVSSVector       string   `json:"cvss_vector,omitempty"`
    CVSSSeverity     string   `json:"cvss_seeverity,omitempty"`
    CVSSScore        float64  `json:"cvss_score,omitempty"`
    OWASP25Category  string   `json:"owasp25_category,omitempty"`
}

type TimedComment struct {
	Offset  string `json:"offset"`
	Message string `json:"message"`
}

type TimedEvent struct {
	Offset string `json:"offset"`
	Event  string `json:"event"`
}

type EngagementsFile struct {
	OrganizationSlug string           `json:"organization_slug"`
	Engagements      []EngagementLite `json:"engagements"`
}

type EngagementLite struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	Access           string   `json:"access"`
	Title            string   `json:"title"`
	BriefingMarkdown string   `json:"briefing_markdown"`
    InScope          []Scope  `json:"in_scope"`
    OutOfScope       []Scope  `json:"out_of_scope"`
    Rewards          []RewardTier `json:"rewards"`
    Abstract         string   `json:"abstract"`
}

// EngagementAbstract represents a concise description for each engagement,
// generated from fixtures/engagements.json and organizations.json
type EngagementAbstract struct {
    OrganizationSlug string `json:"organization_slug"`
    OrganizationName string `json:"organization_name"`
    EngagementID     string `json:"engagement_id"`
    Title            string `json:"title"`
    Type             string `json:"type"`
    Access           string `json:"access"`
    Abstract         string `json:"abstract"`
}
