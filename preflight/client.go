package preflight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// maxBodyBytes caps a single response body so a hostile/huge CP cannot OOM us.
	maxBodyBytes = 64 << 20 // 64 MiB
	// maxPages backstops the pagination loop against a runaway cursor.
	maxPages = 100_000
)

type requestErrorKind uint8

const (
	requestErrBuild requestErrorKind = iota
	requestErrTransport
	requestErrNilResponse
	requestErrStatus
	requestErrDecode
)

type requestError struct {
	kind   requestErrorKind
	status int
	detail string
	err    error
}

func (e *requestError) Error() string { return e.detail }

func (e *requestError) Unwrap() error { return e.err }

type listErrorKind uint8

const (
	listErrCursorLoop listErrorKind = iota
	listErrPageLimit
	listErrCursorParse
)

type listError struct {
	kind   listErrorKind
	detail string
	err    error
}

func (e *listError) Error() string { return e.detail }

func (e *listError) Unwrap() error { return e.err }

type client struct {
	base    *url.URL
	token   string
	http    *http.Client
	headers http.Header
}

// newClientWithHTTP builds a client against an already-constructed *http.Client,
// so a caller (e.g. Audit, via Options.HTTPClient) can supply its own transport,
// timeout, or proxy settings instead of a fresh one derived from a timeout alone.
func newClientWithHTTP(addr, token string, hc *http.Client, headers http.Header) (*client, error) {
	base, err := url.Parse(strings.TrimRight(addr, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid --address %q: %w", addr, err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid --address %q: need scheme and host, e.g. http://localhost:5681", addr)
	}
	return &client{base: base, token: token, http: hc, headers: headers.Clone()}, nil
}

// list fetches every item of a resource collection, following pagination.
// The bool return is false when the collection endpoint returned 404 ("type not
// registered" / not reachable) so the caller can record a coverage gap rather
// than silently treating it as empty.
func (c *client) list(ctx context.Context, path string) ([]resourceItem, bool, error) {
	if !strings.Contains(path, "?") {
		path += "?size=1000"
	}
	var items []resourceItem
	visited := map[string]bool{}
	pages := 0
	next := path
	for next != "" {
		if visited[next] {
			return nil, false, &listError{
				kind:   listErrCursorLoop,
				detail: fmt.Sprintf("pagination cursor repeated (%s); aborting to avoid an infinite loop", next),
			}
		}
		visited[next] = true
		pages++
		if pages > maxPages {
			return nil, false, &listError{
				kind:   listErrPageLimit,
				detail: fmt.Sprintf("pagination exceeded %d pages; aborting", maxPages),
			}
		}
		var page resourceList
		status, err := c.getJSON(ctx, next, &page)
		if err != nil {
			return nil, false, err
		}
		if status == http.StatusNotFound {
			return nil, false, nil
		}
		items = append(items, page.Items...)
		if page.Next != nil && *page.Next != "" {
			u, err := url.Parse(*page.Next)
			if err != nil {
				return nil, false, &listError{
					kind:   listErrCursorParse,
					detail: fmt.Sprintf("parsing next cursor: %v", err),
					err:    err,
				}
			}
			next = u.RequestURI() // reuse our own host; the cursor only matters for path+query
		} else {
			next = ""
		}
	}
	return items, true, nil
}

// getJSON GETs path (absolute path with leading slash) and decodes the body into
// v unless the status is 404. It returns the HTTP status code. Response bodies are
// never echoed into errors (they may reflect the bearer token).
func (c *client) getJSON(ctx context.Context, path string, v any) (int, error) {
	full := *c.base
	reqPath := path
	if before, after, ok := strings.Cut(path, "?"); ok {
		reqPath = before
		full.RawQuery = after
	}
	full.Path = c.prefixed(reqPath) // honor a path prefix in --address (e.g. behind an ingress)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full.String(), http.NoBody)
	if err != nil {
		return 0, &requestError{kind: requestErrBuild, detail: err.Error(), err: err}
	}
	for k, vs := range c.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, &requestError{
			kind:   requestErrTransport,
			detail: fmt.Sprintf("GET %s: %v", full.String(), err),
			err:    err,
		}
	}
	if resp == nil { // unreachable per net/http (resp non-nil when err == nil); guards the deref for static analysis
		return 0, &requestError{
			kind:   requestErrNilResponse,
			detail: fmt.Sprintf("GET %s: nil response", full.String()),
		}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return resp.StatusCode, &requestError{
			kind:   requestErrStatus,
			status: resp.StatusCode,
			detail: fmt.Sprintf("GET %s: status %d (authentication failed; check --token)", full.String(), resp.StatusCode),
		}
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, &requestError{
			kind:   requestErrStatus,
			status: resp.StatusCode,
			detail: fmt.Sprintf("GET %s: status %d", full.String(), resp.StatusCode),
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(v); err != nil {
		return resp.StatusCode, &requestError{
			kind:   requestErrDecode,
			status: resp.StatusCode,
			detail: fmt.Sprintf("decoding %s: %v", full.String(), err),
			err:    err,
		}
	}
	return resp.StatusCode, nil
}

// prefixed prepends any base-URL path prefix to a server-relative request path,
// unless the path already carries it (e.g. a server-generated pagination cursor).
func (c *client) prefixed(reqPath string) string {
	prefix := strings.TrimRight(c.base.Path, "/")
	if prefix == "" || reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/") {
		return reqPath
	}
	return prefix + reqPath
}

// index queries GET / for CP metadata (product + version).
func (c *client) index(ctx context.Context) (cpIndex, error) {
	var idx cpIndex
	status, err := c.getJSON(ctx, "/", &idx)
	if err != nil {
		// A 200 whose body is not a JSON control-plane index (an HTML login/ingress
		// page sharing the host, a wrong subpath like /gui, or an empty body) is not a
		// transport failure: return an empty index so audit() reports the friendly
		// "does not look like a Kuma control plane" rather than "invalid character
		// '<'". Narrow this to genuine JSON-shape / empty-body errors so a real
		// transport problem surfacing AFTER the 200 headers — a --timeout firing or
		// context cancellation mid-read — still propagates with its own message.
		var syntaxErr *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		if status == http.StatusOK && (errors.As(err, &syntaxErr) || errors.As(err, &typeErr) || errors.Is(err, io.EOF)) {
			return cpIndex{}, nil
		}
		return idx, err
	}
	if status != http.StatusOK {
		return idx, fmt.Errorf("GET /: status %d", status)
	}
	return idx, nil
}

type cpIndex struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

type resourceList struct {
	Total uint32         `json:"total"`
	Items []resourceItem `json:"items"`
	Next  *string        `json:"next"`
}

type resourceItem struct {
	Type   string
	Mesh   string
	Name   string
	Labels map[string]string
	Spec   json.RawMessage
	raw    json.RawMessage
}

// UnmarshalJSON captures the meta envelope, the nested spec (new policies), and
// the full raw object. Core/legacy resources inline their spec fields at the top
// level with no "spec" key, so specBytes() falls back to the whole object.
func (i *resourceItem) UnmarshalJSON(b []byte) error {
	var env struct {
		Type   string            `json:"type"`
		Mesh   string            `json:"mesh"`
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
		Spec   json.RawMessage   `json:"spec"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	i.Type, i.Mesh, i.Name, i.Labels, i.Spec = env.Type, env.Mesh, env.Name, env.Labels, env.Spec
	i.raw = append(json.RawMessage(nil), b...)
	return nil
}

// specBytes returns the JSON to inspect for spec fields: the nested "spec"
// envelope when present, otherwise the whole object (inlined core resources).
func (i resourceItem) specBytes() json.RawMessage {
	if len(i.Spec) > 0 {
		return i.Spec
	}
	return i.raw
}
