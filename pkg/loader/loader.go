package loader

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/vuln-fixtures/fixtures/pkg/models"
)

// LoadAll loads organizations, their engagements, and reports from fixturesDir.
// fixturesDir should contain organizations.json, engagements.json, and a reports/ directory.
func LoadAll(fixturesDir string) ([]models.Organization, error) {
	// Always prefer the embedded fixtures bundled with this module so consumers
	// do not need to download or vendor JSON files locally. The fixturesDir
	// argument is accepted for API compatibility but ignored when using the
	// embedded filesystem.
	fixturesFS := getFixturesFS(fixturesDir)

	orgs, err := loadOrganizationsFS(fixturesFS, "organizations.json")
	if err != nil {
		return nil, err
	}

	engByOrg, err := loadEngagementsFS(fixturesFS, "engagements.json")
	if err != nil {
		return nil, err
	}

	reportsByEng, err := loadReportsFS(fixturesFS, "reports")
	if err != nil {
		return nil, err
	}

	// Abstracts are now embedded directly in engagements.json

	// Link engagements and reports into organizations by matching slug and engagement id
	for i := range orgs {
		org := &orgs[i]
		liteList := engByOrg[org.Slug]
		org.Engagements = make([]models.Engagement, 0, len(liteList))
		for _, lite := range liteList {
			eng := models.Engagement{
				ID:               lite.ID,
				Type:             lite.Type,
				Access:           lite.Access,
				Title:            lite.Title,
				BriefingMarkdown: lite.BriefingMarkdown,
				InScope:          lite.InScope,
				OutOfScope:       lite.OutOfScope,
				Rewards:          lite.Rewards,
				Abstract:         lite.Abstract,
			}
			if groups, ok := reportsByEng[lite.ID]; ok {
				eng.Reports = groups
			}
			org.Engagements = append(org.Engagements, eng)
		}
	}

	return orgs, nil
}

func loadOrganizationsFS(fsys fs.FS, path string) ([]models.Organization, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read organizations: %w", err)
	}
	var orgs []models.Organization
	if err := json.Unmarshal(data, &orgs); err != nil {
		return nil, fmt.Errorf("parse organizations: %w", err)
	}
	return orgs, nil
}

func loadEngagementsFS(fsys fs.FS, path string) (map[string][]models.EngagementLite, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read engagements: %w", err)
	}
	var entries []models.EngagementsFile
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse engagements: %w", err)
	}
	byOrg := make(map[string][]models.EngagementLite, len(entries))
	for _, e := range entries {
		byOrg[e.OrganizationSlug] = append(byOrg[e.OrganizationSlug], e.Engagements...)
	}
	return byOrg, nil
}

func loadReportsFS(fsys fs.FS, dir string) (map[string][]models.ReportGroup, error) {
	reportsByEng := make(map[string][]models.ReportGroup)
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".json" {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read reports %s: %w", path, err)
		}
		var items []models.ReportsFile
		if err := json.Unmarshal(data, &items); err != nil {
			return fmt.Errorf("parse reports %s: %w", path, err)
		}
		for _, it := range items {
			grp := models.ReportGroup{Reporter: it.Reporter, Triager: it.Triager, ProgramMgr: it.ProgramMgr}
			reportsByEng[it.EngagementID] = append(reportsByEng[it.EngagementID], grp)
		}
		return nil
	}
	if err := fs.WalkDir(fsys, dir, walkFn); err != nil {
		return nil, err
	}
	return reportsByEng, nil
}
