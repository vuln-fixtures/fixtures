package loader

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// getFixturesFS returns an fs.FS rooted at the fixtures directory.
// Order of resolution:
// 1) Use the provided fixturesDir if it exists relative to the current working directory
// 2) Use the repo/module fixtures directory relative to this source file (../../fixtures)
// 3) Fallback to fixturesDir (may fail later during reads, surfacing a helpful error)
func getFixturesFS(fixturesDir string) fs.FS {
	if fixturesDir != "" {
		if info, err := os.Stat(fixturesDir); err == nil && info.IsDir() {
			return os.DirFS(fixturesDir)
		}
	}

	if _, thisFile, _, ok := runtime.Caller(0); ok {
		loaderDir := filepath.Dir(thisFile)
		moduleRoot := filepath.Clean(filepath.Join(loaderDir, "..", ".."))
		repoFixtures := filepath.Join(moduleRoot, "fixtures")
		if info, err := os.Stat(repoFixtures); err == nil && info.IsDir() {
			return os.DirFS(repoFixtures)
		}
	}

	return os.DirFS(fixturesDir)
}
