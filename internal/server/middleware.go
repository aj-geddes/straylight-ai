package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"golang.org/x/time/rate"
)

// defaultAllowedOrigins is the set of origins permitted by the CORS middleware.
var defaultAllowedOrigins = []string{
	"http://localhost:9470",
	"http://localhost:5173",
	"http://127.0.0.1:9470",
}

// defaultMaxBodyBytes is the maximum allowed request body size (1 MB).
const defaultMaxBodyBytes int64 = 1 << 20

// defaultRateLimit is the default requests-per-second for the rate limiter.
const defaultRateLimit = 100

// defaultBurst is the default burst size for the rate limiter.
const defaultBurst = 200

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	// requestIDKey is the context key for the request ID.
	requestIDKey contextKey = iota
)

// requestIDLength is the number of random bytes used to generate a request ID.
// 8 bytes = 16 hex chars, sufficient for practical uniqueness in a local process.
const requestIDLength = 8

// responseWriter wraps http.ResponseWriter to capture the status code after
// WriteHeader is called by the handler.
type responseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code and delegates to the underlying writer.
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write delegates to the underlying writer. If WriteHeader has not been called
// yet, it implicitly records 200 OK (matching the default net/http behaviour).
func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	return rw.ResponseWriter.Write(b)
}

// generateRequestID returns a short random hex string suitable for use as a
// per-request trace identifier. It does not guarantee global uniqueness but
// is sufficient for local process request tracing.
func generateRequestID() string {
	b := make([]byte, requestIDLength)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use timestamp nanoseconds in hex.
		return hex.EncodeToString([]byte(time.Now().Format("15040500000000")))
	}
	return hex.EncodeToString(b)
}

// RequestIDFromContext retrieves the request ID stored in ctx by RequestLogging.
// Returns an empty string if no request ID is present.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// RequestLogging returns an http.Handler that wraps next with structured
// request/response logging. For every request it:
//   - Generates a unique request ID
//   - Stores the ID in the request context (retrievable via RequestIDFromContext)
//   - Calls next
//   - Logs method, path, status code, duration_ms, and request_id at INFO level
func RequestLogging(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := generateRequestID()

		// Inject request ID into context so handlers can attach it to error logs.
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		r = r.WithContext(ctx)

		// Wrap the writer to capture the status code.
		wrapped := &responseWriter{ResponseWriter: w, status: 0}

		next.ServeHTTP(wrapped, r)

		status := wrapped.status
		if status == 0 {
			status = http.StatusOK
		}

		logger.InfoContext(ctx, "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", int64(status),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", requestID,
		)
	})
}

// AuditLog emits a structured audit log entry for credential lifecycle events.
// The logger should be the application logger configured with JSON format so
// audit entries can be filtered using the "audit=true" field.
//
// event is one of: "credential_accessed", "credential_stored",
// "credential_deleted", "credential_refreshed".
func AuditLog(logger *slog.Logger, event, serviceName, tool, requestID string) {
	logger.Info("audit",
		"audit", true,
		"event", event,
		"service", serviceName,
		"tool", tool,
		"request_id", requestID,
	)
}

// ---------------------------------------------------------------------------
// Security Middleware (WP-2.6)
// ---------------------------------------------------------------------------

// SecurityHeaders sets defensive HTTP response headers on every response.
// Headers set: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy,
// X-XSS-Protection, Referrer-Policy, and (on TLS connections) Strict-Transport-Security.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' https://*.githubusercontent.com https://*.gravatar.com https://*.gitlab.com https://avatars.slack-edge.com https://lh3.googleusercontent.com")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Only set HSTS if the request came over TLS.
		// Personal tier runs on localhost HTTP, so HSTS must not be sent over plain HTTP.
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware restricts cross-origin requests to the provided list of allowed
// origins. Requests from unlisted origins receive no Access-Control-Allow-Origin
// header. OPTIONS preflight requests from allowed origins are served directly
// with a 200 response so the browser can proceed.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && originSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
				w.Header().Set("Vary", "Origin")
			}

			// Handle OPTIONS preflight — respond immediately without calling downstream.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimiter returns a middleware that enforces a global token-bucket rate
// limit using golang.org/x/time/rate. Requests that exceed the limit receive
// HTTP 429 Too Many Requests.
func RateLimiter(requestsPerSecond int, burst int) func(http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(requestsPerSecond), burst)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				WriteError(w, http.StatusTooManyRequests, ErrCodeInternalError, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBodySize returns a middleware that limits the size of incoming request
// bodies to maxBytes. Requests with bodies larger than the limit receive
// HTTP 413 Request Entity Too Large.
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				WriteError(w, http.StatusRequestEntityTooLarge, ErrCodeValidationFailed, "request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// SanitizeInput strips null bytes and non-printable control characters from
// the input string. Newlines (\n), carriage returns (\r), and horizontal tabs
// (\t) are preserved as they are legitimate in text fields.
func SanitizeInput(s string) string {
	return strings.Map(func(r rune) rune {
		// Keep safe whitespace characters.
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		// Drop null bytes and other ASCII control characters.
		if r == 0 || (unicode.IsControl(r) && r < 0x80) {
			return -1
		}
		return r
	}, s)
}

// applyMiddlewareChain wraps the given handler with the security middleware
// stack in order: SecurityHeaders -> CORS -> RateLimit -> MaxBodySize.
func applyMiddlewareChain(h http.Handler, opts Options) http.Handler {
	rps := opts.RateLimit
	if rps == 0 {
		rps = defaultRateLimit
	}
	burst := opts.Burst
	if burst == 0 {
		burst = defaultBurst
	}

	h = MaxBodySize(defaultMaxBodyBytes)(h)
	h = RateLimiter(rps, burst)(h)
	h = CORSMiddleware(defaultAllowedOrigins)(h)
	h = SecurityHeaders(h)
	return h
}
