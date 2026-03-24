package web

import (
	"io/fs"
	"net/http"
	"path/filepath"
	"regexp"
)

// hashedFilePattern matches Vite-style hashed filenames, e.g. "index-AbCdEfGh.js".
// Vite appends an 8-character hex/base62 hash between the last "-" and the extension.
var hashedFilePattern = regexp.MustCompile(`-[A-Za-z0-9]{8,}\.[a-z]+$`)

// noCacheValue is the Cache-Control header value for files that must not be cached.
const noCacheValue = "no-cache, no-store, must-revalidate"

// longCacheValue is the Cache-Control header value for immutable hashed assets.
// One year (31536000 seconds) is the conventional maximum for versioned static files.
const longCacheValue = "public, max-age=31536000, immutable"

// mimeTypes maps file extensions to their MIME type strings.
// These supplement the standard library's defaults for types common in SPA builds.
var mimeTypes = map[string]string{
	".js":    "application/javascript",
	".mjs":   "application/javascript",
	".css":   "text/css; charset=utf-8",
	".html":  "text/html; charset=utf-8",
	".json":  "application/json",
	".svg":   "image/svg+xml",
	".ico":   "image/x-icon",
	".png":   "image/png",
	".webp":  "image/webp",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
}

// Handler serves the embedded React SPA with:
//   - Correct MIME types for .js, .css, .html, .json, .svg
//   - Long-cache headers for hashed Vite assets (e.g. index-AbCd1234.js)
//   - No-cache headers for index.html and non-hashed assets
//   - SPA fallback: any path that does not match a real file returns index.html
type Handler struct {
	fsys fs.FS
}

// NewHandler creates a new Handler that serves files from fsys.
// fsys should be the FS rooted at the dist/ directory (i.e., index.html is at the root).
func NewHandler(fsys fs.FS) *Handler {
	return &Handler{fsys: fsys}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip the leading slash to get a relative path into the embedded FS.
	urlPath := r.URL.Path
	if urlPath == "/" {
		urlPath = "index.html"
	} else if len(urlPath) > 0 && urlPath[0] == '/' {
		urlPath = urlPath[1:]
	}

	// Check whether the file actually exists in the embedded FS.
	if fileExists(h.fsys, urlPath) {
		h.serveFile(w, r, urlPath)
		return
	}

	// SPA fallback: return index.html for all unrecognised paths so that
	// React Router (or any other client-side router) can take over.
	h.serveIndexHTML(w, r)
}

// serveFile serves a specific file from the embedded FS with appropriate headers.
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, path string) {
	setCacheHeader(w, path)
	setContentType(w, path)
	http.ServeFileFS(w, r, h.fsys, path)
}

// serveIndexHTML serves index.html with no-cache headers.
func (h *Handler) serveIndexHTML(w http.ResponseWriter, r *http.Request) {
	setCacheHeader(w, "index.html")
	setContentType(w, "index.html")
	http.ServeFileFS(w, r, h.fsys, "index.html")
}

// fileExists reports whether the given path names a regular file in the FS.
func fileExists(fsys fs.FS, path string) bool {
	if path == "" || path == "." {
		return false
	}
	f, err := fsys.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// setCacheHeader sets Cache-Control based on whether the path contains a content hash.
func setCacheHeader(w http.ResponseWriter, path string) {
	base := filepath.Base(path)
	if hashedFilePattern.MatchString(base) {
		w.Header().Set("Cache-Control", longCacheValue)
	} else {
		w.Header().Set("Cache-Control", noCacheValue)
	}
}

// setContentType sets the Content-Type header based on the file extension.
// It overrides the stdlib's sniffing to guarantee correct types for common SPA assets.
func setContentType(w http.ResponseWriter, path string) {
	ext := filepath.Ext(path)
	if mime, ok := mimeTypes[ext]; ok {
		w.Header().Set("Content-Type", mime)
	}
}
