package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/vuln-fixtures/fixtures/pkg/loader"
)

func main() {
	orgs, err := loader.LoadAll("fixtures")
	if err != nil {
		log.Fatalf("load error: %v", err)
	}
	// Print a concise summary as JSON
	summary := make([]map[string]any, 0, len(orgs))
	for _, org := range orgs {
		engSummary := make([]map[string]any, 0, len(org.Engagements))
		for _, e := range org.Engagements {
			engSummary = append(engSummary, map[string]any{
				"id":          e.ID,
				"type":        e.Type,
				"access":      e.Access,
				"title":       e.Title,
				"hasAbstract": len(e.Abstract) > 0,
				"reports":     len(e.Reports),
			})
		}
		summary = append(summary, map[string]any{
			"slug":        org.Slug,
			"name":        org.Name,
			"engagements": engSummary,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(summary); err != nil {
		fmt.Println("[]")
	}
}
