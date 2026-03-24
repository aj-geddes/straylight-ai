package web_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/straylight-ai/straylight/internal/web"
)

// testFS builds an in-memory filesystem that mimics a Vite build output.
// It contains:
//   - index.html (the SPA shell, no-cache)
//   - assets/index-AbCdEfGh.js  (hashed static asset, long-cache)
//   - assets/index-XyZw1234.css (hashed static asset, long-cache)
func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {
			Data: []byte(`<!doctype html><html><head><title>Test</title></head><body><div id="root"></div></body></html>`),
		},
		"assets/index-AbCdEfGh.js": {
			Data: []byte(`console.log("app")`),
		},
		"assets/index-XyZw1234.css": {
			Data: []byte(`body { margin: 0; }`),
		},
		"assets/logo-Aa1Bb2Cc.svg": {
			Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`),
		},
		"manifest.json": {
			Data: []byte(`{"version":"1"}`),
		},
	}
}

// TestNewHandler_NotNil verifies that NewHandler returns a non-nil handler.
func TestNewHandler_NotNil(t *testing.T) {
	h := web.NewHandler(testFS())
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
}

// TestServeIndexHTML_ReturnsOK verifies the root path serves index.html with 200.
func TestServeIndexHTML_ReturnsOK(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestServeIndexHTML_ContentTypeHTML verifies index.html is served with text/html MIME type.
func TestServeIndexHTML_ContentTypeHTML(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct == "" {
		t.Fatal("expected Content-Type header, got empty")
	}
	// Should start with text/html
	if len(ct) < 9 || ct[:9] != "text/html" {
		t.Errorf("expected Content-Type to start with text/html, got %q", ct)
	}
}

// TestServeIndexHTML_NoCacheHeader verifies index.html is served with no-cache headers.
func TestServeIndexHTML_NoCacheHeader(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if cc != "no-cache, no-store, must-revalidate" {
		t.Errorf("expected no-cache Cache-Control for index.html, got %q", cc)
	}
}

// TestSPAFallback_UnknownPathReturnsIndexHTML verifies that a path that does not
// match any file returns index.html (SPA client-side routing support).
func TestSPAFallback_UnknownPathReturnsIndexHTML(t *testing.T) {
	h := web.NewHandler(testFS())

	paths := []string{
		"/dashboard",
		"/services/github",
		"/settings/keys",
		"/deep/nested/route",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("path %q: expected 200 (SPA fallback), got %d", path, w.Code)
			}

			body := w.Body.String()
			if body == "" {
				t.Errorf("path %q: expected non-empty body (index.html), got empty", path)
			}
		})
	}
}

// TestSPAFallback_NoCacheOnFallback verifies that the SPA fallback also sets no-cache headers.
func TestSPAFallback_NoCacheOnFallback(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/nonexistent-page", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if cc != "no-cache, no-store, must-revalidate" {
		t.Errorf("expected no-cache Cache-Control for SPA fallback, got %q", cc)
	}
}

// TestStaticAssetJS_ContentTypeJS verifies .js files are served with application/javascript MIME type.
func TestStaticAssetJS_ContentTypeJS(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/assets/index-AbCdEfGh.js", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for .js asset, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct == "" {
		t.Fatal("expected Content-Type header for .js, got empty")
	}
	// Must contain application/javascript or text/javascript
	if ct != "application/javascript" && ct != "text/javascript; charset=utf-8" && ct != "text/javascript" {
		// Also accept with charset appended
		isJS := len(ct) >= 22 && (ct[:22] == "application/javascript" || ct[:16] == "text/javascript;")
		if !isJS {
			t.Errorf("expected JavaScript Content-Type for .js, got %q", ct)
		}
	}
}

// TestStaticAssetCSS_ContentTypeCSS verifies .css files are served with text/css MIME type.
func TestStaticAssetCSS_ContentTypeCSS(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/assets/index-XyZw1234.css", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for .css asset, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if len(ct) < 8 || ct[:8] != "text/css" {
		t.Errorf("expected Content-Type text/css for .css asset, got %q", ct)
	}
}

// TestStaticAssetSVG_ContentTypeSVG verifies .svg files are served with image/svg+xml MIME type.
func TestStaticAssetSVG_ContentTypeSVG(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/assets/logo-Aa1Bb2Cc.svg", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for .svg asset, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if len(ct) < 13 || ct[:13] != "image/svg+xml" {
		t.Errorf("expected Content-Type image/svg+xml for .svg asset, got %q", ct)
	}
}

// TestStaticAssetJSON_ContentTypeJSON verifies .json files are served with application/json MIME type.
func TestStaticAssetJSON_ContentTypeJSON(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for .json file, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if len(ct) < 16 || ct[:16] != "application/json" {
		t.Errorf("expected Content-Type application/json for .json, got %q", ct)
	}
}

// TestHashedAsset_LongCacheHeader verifies that assets with a hash in the filename
// receive an immutable long-cache Cache-Control header.
func TestHashedAsset_LongCacheHeader(t *testing.T) {
	h := web.NewHandler(testFS())

	hashedAssets := []string{
		"/assets/index-AbCdEfGh.js",
		"/assets/index-XyZw1234.css",
		"/assets/logo-Aa1Bb2Cc.svg",
	}

	for _, path := range hashedAssets {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			cc := w.Header().Get("Cache-Control")
			if cc != "public, max-age=31536000, immutable" {
				t.Errorf("path %q: expected long-cache Cache-Control, got %q", path, cc)
			}
		})
	}
}

// TestNonHashedAsset_NoCacheHeader verifies that assets without a hash in the filename
// (e.g., manifest.json) receive no-cache headers.
func TestNonHashedAsset_NoCacheHeader(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if cc != "no-cache, no-store, must-revalidate" {
		t.Errorf("expected no-cache for non-hashed asset, got %q", cc)
	}
}

// TestServeAsset_BodyContents verifies that the correct file content is returned.
func TestServeAsset_BodyContents(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/assets/index-AbCdEfGh.js", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	expected := `console.log("app")`
	if body != expected {
		t.Errorf("expected body %q, got %q", expected, body)
	}
}

// TestSPAFallback_ReturnsIndexHTMLContent verifies the SPA fallback returns the index.html content.
func TestSPAFallback_ReturnsIndexHTMLContent(t *testing.T) {
	h := web.NewHandler(testFS())
	req := httptest.NewRequest(http.MethodGet, "/some/spa/route", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	if len(body) == 0 {
		t.Fatal("expected non-empty body for SPA fallback")
	}
	// Should contain the root div
	if len(body) < 9 || !containsStr(body, `id="root"`) {
		t.Errorf("SPA fallback body should contain the root div, got: %q", body)
	}
}

// containsStr is a helper to check substring without importing strings package in test.
func containsStr(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
