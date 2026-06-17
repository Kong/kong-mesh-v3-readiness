package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// maxBodyBytes caps a single response body so a hostile/huge CP cannot OOM us.
	maxBodyBytes = 64 << 20 // 64 MiB
	// maxPages backstops the pagination loop against a runaway cursor.
	maxPages = 100_000
)

type client struct {
	base  *url.URL
	token string
	http  *http.Client
}

func newClient(addr, token string, timeout time.Duration) (*client, error) {
	base, err := url.Parse(strings.TrimRight(addr, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid --address %q: %w", addr, err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid --address %q: need scheme and host, e.g. http://localhost:5681", addr)
	}
	return &client{
		base:  base,
		token: token,
		// Derive the per-request timeout from the overall budget so --timeout stays
		// authoritative (no hidden shorter cap).
		http: &http.Client{Timeout: timeout},
	}, nil
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
			return nil, false, fmt.Errorf("pagination cursor repeated (%s); aborting to avoid an infinite loop", next)
		}
		visited[next] = true
		pages++
		if pages > maxPages {
			return nil, false, fmt.Errorf("pagination exceeded %d pages; aborting", maxPages)
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
				return nil, false, fmt.Errorf("parsing next cursor: %w", err)
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
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", full.String(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return resp.StatusCode, fmt.Errorf("GET %s: status %d (authentication failed; check --token)", full.String(), resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("GET %s: status %d", full.String(), resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(v); err != nil {
		return resp.StatusCode, fmt.Errorf("decoding %s: %w", full.String(), err)
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
