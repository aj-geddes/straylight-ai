// Package web embeds the compiled React SPA into the Go binary and serves it
// at the root HTTP path. During development, a placeholder dist/index.html is
// served; during Docker builds the real Vite output replaces it.
package web

import (
	"embed"
	"io/fs"
	"log/slog"
)

// distDir is the embedded filesystem containing the compiled React SPA.
// The dist/ directory is populated by `npm run build` during the Docker build.
// For local development a placeholder index.html lives at web/dist/index.html.
//
//go:embed all:dist
var distDir embed.FS

// DistFS returns the sub-filesystem rooted at "dist/" within the embedded FS.
// Callers receive an fs.FS whose root contains index.html and assets/.
func DistFS() fs.FS {
	sub, err := fs.Sub(distDir, "dist")
	if err != nil {
		// This should never happen because the embed directive guarantees the
		// "dist" directory exists (at minimum with the placeholder index.html).
		slog.Error("web: failed to create dist sub-filesystem", "error", err)
		return distDir
	}
	return sub
}
