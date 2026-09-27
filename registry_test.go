package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServer(t *testing.T, readAuth bool, scopes ...string) *httptest.Server {
	return testServerAt(t, filepath.Join(t.TempDir(), "data"), readAuth, scopes...)
}

func testServerAt(t *testing.T, dataDir string, readAuth bool, scopes ...string) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256([]byte("secret"))
	h, err := NewHandler(Config{
		DataDir:  dataDir,
		ReadAuth: readAuth,
		Tokens: []Token{{
			Hash:   hex.EncodeToString(sum[:]),
			User:   "alice",
			Scopes: scopes,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(h)
}

func publish(t *testing.T, server *httptest.Server, name, version string, tarball []byte) *http.Response {
	t.Helper()
	canonicalName, err := url.PathUnescape(name)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"_id":       canonicalName,
		"name":      canonicalName,
		"dist-tags": map[string]string{"latest": version},
		"versions": map[string]any{version: map[string]any{
			"name": canonicalName, "version": version,
		}},
		"_attachments": map[string]any{name + "-" + version + ".tgz": map[string]string{
			"data": base64.StdEncoding.EncodeToString(tarball),
		}},
	}
	return publishDocument(t, server, name, doc)
}

func publishAttachment(t *testing.T, server *httptest.Server, name, version, attachment string, tarball []byte) *http.Response {
	t.Helper()
	canonicalName, err := url.PathUnescape(name)
	if err != nil {
		t.Fatal(err)
	}
	return publishDocument(t, server, name, map[string]any{
		"_id":          canonicalName,
		"name":         canonicalName,
		"dist-tags":    map[string]string{"latest": version},
		"versions":     map[string]any{version: map[string]any{"name": canonicalName, "version": version}},
		"_attachments": map[string]any{attachment: map[string]string{"data": base64.StdEncoding.EncodeToString(tarball)}},
	})
}

func publishDocument(t *testing.T, server *httptest.Server, name string, doc any) *http.Response {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, server.URL+"/"+name, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func packument(t *testing.T, server *httptest.Server, name string) map[string]struct {
	Dist struct {
		Tarball   string `json:"tarball"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
} {
	t.Helper()
	resp, err := http.Get(server.URL + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("packument status = %d", resp.StatusCode)
	}
	var response struct {
		Versions map[string]struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response.Versions
}

func TestPublishReadPackumentAndTarball(t *testing.T) {
	server := testServer(t, false, "*")
	defer server.Close()
	tarball := []byte("tarball contents")
	resp := publish(t, server, "widget", "1.0.0", tarball)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publish status = %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/widget", nil)
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("packument status = %d", resp.StatusCode)
	}
	var packument struct {
		Versions map[string]struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&packument); err != nil {
		t.Fatal(err)
	}
	dist := packument.Versions["1.0.0"].Dist
	if !strings.HasPrefix(dist.Tarball, "/widget/-/") || dist.Tarball == "/widget/-/widget-1.0.0.tgz" || dist.Integrity == "" {
		t.Fatalf("generated dist = %#v", dist)
	}
	resp, err = http.Get(server.URL + dist.Tarball)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, tarball) {
		t.Fatalf("tarball response = %d, %q", resp.StatusCode, got)
	}
	if resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("cache control = %q", resp.Header.Get("Cache-Control"))
	}
}

func TestPublicURLProducesAbsoluteTarballURLWithBasePath(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	sum := sha256.Sum256([]byte("secret"))
	h, err := NewHandler(Config{
		DataDir:   dataDir,
		PublicURL: "https://packages.example/registry/npm/",
		Tokens:    []Token{{Hash: hex.EncodeToString(sum[:]), User: "alice", Scopes: []string{"*"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	defer server.Close()

	resp := publish(t, server, "widget", "1.0.0", []byte("tarball"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publish status = %d", resp.StatusCode)
	}
	got := packument(t, server, "widget")["1.0.0"].Dist.Tarball
	if !strings.HasPrefix(got, "https://packages.example/registry/npm/widget/-/") {
		t.Fatalf("tarball URL = %q", got)
	}
}

func TestMigrateTarballsRewritesLegacyRelativeURLsIdempotently(t *testing.T) {
	dataDir := t.TempDir()
	s := store{dir: dataDir, syncDir: syncDirectory}
	if err := s.publish("tar", "0.1.0", []byte("tarball"), map[string]any{"name": "tar", "version": "0.1.0"}, map[string]string{"latest": "0.1.0"}); err != nil {
		t.Fatal(err)
	}
	config := Config{DataDir: dataDir, PublicURL: "https://registry.example/npm/"}
	changed, err := MigrateTarballs(config)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("changed = %d, want 1", changed)
	}
	meta, err := s.load("tar")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(meta.Versions["0.1.0"], &manifest); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(manifest.Dist.Tarball, "https://registry.example/npm/tar/-/") {
		t.Fatalf("tarball URL = %q", manifest.Dist.Tarball)
	}
	changed, err = MigrateTarballs(config)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Fatalf("second migration changed = %d, want 0", changed)
	}
}

func TestWriteRequiresBearerToken(t *testing.T) {
	server := testServer(t, false, "*")
	defer server.Close()
	req, err := http.NewRequest(http.MethodPut, server.URL+"/widget", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestVersionIsImmutable(t *testing.T) {
	server := testServer(t, false, "*")
	defer server.Close()
	first := publish(t, server, "widget", "1.0.0", []byte("first"))
	first.Body.Close()
	second := publish(t, server, "widget", "1.0.0", []byte("second"))
	defer second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d", second.StatusCode)
	}
}

func TestPublishRejectsTagsForAbsentVersionsAndKeepsValidTags(t *testing.T) {
	server := testServer(t, false, "*")
	defer server.Close()
	first := publish(t, server, "widget", "1.0.0", []byte("first"))
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first publish status = %d", first.StatusCode)
	}
	invalid := publishDocument(t, server, "widget", map[string]any{
		"_id":          "widget",
		"name":         "widget",
		"dist-tags":    map[string]string{"latest": "9.9.9"},
		"versions":     map[string]any{"1.0.1": map[string]any{"name": "widget", "version": "1.0.1"}},
		"_attachments": map[string]any{"widget-1.0.1.tgz": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("invalid"))}},
	})
	invalid.Body.Close()
	if invalid.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid tag publish status = %d", invalid.StatusCode)
	}
	if _, exists := packument(t, server, "widget")["1.0.1"]; exists {
		t.Fatal("rejected publish added a version")
	}
	valid := publishDocument(t, server, "widget", map[string]any{
		"_id":          "widget",
		"name":         "widget",
		"dist-tags":    map[string]string{"previous": "1.0.0"},
		"versions":     map[string]any{"1.0.1": map[string]any{"name": "widget", "version": "1.0.1"}},
		"_attachments": map[string]any{"widget-1.0.1.tgz": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("valid"))}},
	})
	valid.Body.Close()
	if valid.StatusCode != http.StatusCreated {
		t.Fatalf("valid tag publish status = %d", valid.StatusCode)
	}
	resp, err := http.Get(server.URL + "/widget")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.DistTags["previous"] != "1.0.0" {
		t.Fatalf("valid tag = %q", result.DistTags["previous"])
	}
}

func TestContentAddressedTarballsPreserveVersionsWithSameAttachmentName(t *testing.T) {
	server := testServer(t, false, "*")
	defer server.Close()
	first := publishAttachment(t, server, "widget", "1.0.0", "package.tgz", []byte("first bytes"))
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first publish status = %d", first.StatusCode)
	}
	second := publishAttachment(t, server, "widget", "1.0.1", "package.tgz", []byte("second bytes"))
	second.Body.Close()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("second publish status = %d", second.StatusCode)
	}
	versions := packument(t, server, "widget")
	oldDist, newDist := versions["1.0.0"].Dist, versions["1.0.1"].Dist
	if oldDist.Tarball == newDist.Tarball || oldDist.Integrity == newDist.Integrity {
		t.Fatalf("versions share mutable tarball metadata: %#v %#v", oldDist, newDist)
	}
	for _, check := range []struct {
		url  string
		want []byte
	}{{oldDist.Tarball, []byte("first bytes")}, {newDist.Tarball, []byte("second bytes")}} {
		resp, err := http.Get(server.URL + check.url)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !bytes.Equal(got, check.want) {
			t.Fatalf("tarball %s = %d, %q", check.url, resp.StatusCode, got)
		}
	}
}

func TestInvalidPublishDoesNotWriteTarball(t *testing.T) {
	cases := []struct {
		name string
		doc  any
	}{
		{"null document", nil},
		{"mismatched document id", map[string]any{"_id": "other", "name": "widget", "versions": map[string]any{"1.0.0": map[string]any{"name": "widget", "version": "1.0.0"}}, "_attachments": map[string]any{"widget.tgz": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("bytes"))}}}},
		{"null version manifest", map[string]any{"_id": "widget", "name": "widget", "versions": map[string]any{"1.0.0": nil}, "_attachments": map[string]any{"widget.tgz": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("bytes"))}}}},
		{"mismatched embedded manifest", map[string]any{"_id": "widget", "name": "widget", "versions": map[string]any{"1.0.0": map[string]any{"name": "widget", "version": "2.0.0"}}, "_attachments": map[string]any{"widget.tgz": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("bytes"))}}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data")
			server := testServerAt(t, dataDir, false, "*")
			defer server.Close()
			resp := publishDocument(t, server, "widget", test.doc)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			entries, err := os.ReadDir(filepath.Join(dataDir, "tarballs"))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("invalid publish left tarballs: %v", entries)
			}
		})
	}
}

func TestPostRenameMetadataSyncFailureKeepsReferencedTarball(t *testing.T) {
	dataDir := t.TempDir()
	syncCalls := 0
	s := store{
		dir: dataDir,
		syncDir: func(string) error {
			syncCalls++
			if syncCalls == 2 {
				return errors.New("metadata directory sync failed")
			}
			return nil
		},
	}
	err := s.publish("widget", "1.0.0", []byte("contents"), map[string]any{
		"name": "widget", "version": "1.0.0",
	}, nil)
	if err == nil {
		t.Fatal("publish succeeded despite metadata directory sync failure")
	}
	meta, err := s.load("widget")
	if err != nil {
		t.Fatalf("committed metadata is unreadable: %v", err)
	}
	var manifest struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(meta.Versions["1.0.0"], &manifest); err != nil {
		t.Fatal(err)
	}
	digest, ok := contentAddressedTarball(strings.TrimPrefix(manifest.Dist.Tarball, "/widget/-/"))
	if !ok {
		t.Fatalf("invalid committed tarball URL %q", manifest.Dist.Tarball)
	}
	contents, err := os.ReadFile(filepath.Join(dataDir, "tarballs", digest+".tgz"))
	if err != nil {
		t.Fatalf("committed metadata references missing tarball: %v", err)
	}
	if !bytes.Equal(contents, []byte("contents")) {
		t.Fatalf("tarball contents = %q", contents)
	}
}

func TestScopedTokenCanPublishOnlyItsScope(t *testing.T) {
	server := testServer(t, false, "@acme/*")
	defer server.Close()
	allowed := publish(t, server, "@acme%2fwidget", "1.0.0", []byte("ok"))
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusCreated {
		t.Fatalf("allowed status = %d", allowed.StatusCode)
	}
	forbidden := publish(t, server, "@other%2fwidget", "1.0.0", []byte("no"))
	defer forbidden.Body.Close()
	if forbidden.StatusCode != http.StatusForbidden {
		t.Fatalf("forbidden status = %d", forbidden.StatusCode)
	}
}

func TestTraversalIsRejected(t *testing.T) {
	server := testServer(t, false, "*")
	defer server.Close()
	resp, err := http.Get(server.URL + "/%2e%2e%2fsecret")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPackageValidationRejectsNullByte(t *testing.T) {
	if err := validPackage("widget\x00"); err == nil {
		t.Fatal("NUL-containing package name was accepted")
	}
}

func TestPingWhoamiAndReadAuth(t *testing.T) {
	server := testServer(t, true, "*")
	defer server.Close()
	resp, err := http.Get(server.URL + "/-/ping")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ping status = %d", resp.StatusCode)
	}
	resp, err = http.Get(server.URL + "/-/whoami")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("whoami unauthenticated status = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/-/whoami", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("whoami status = %d", resp.StatusCode)
	}
}

func TestSearchEnumeratesPackagesWithStablePagination(t *testing.T) {
	server := testServer(t, false, "*")
	defer server.Close()
	for _, pkg := range []struct {
		name, version, description string
	}{
		{"zebra", "1.0.0", "Zebra tools"},
		{"@acme%2fwidget", "2.0.0", "Useful widget"},
		{"alpha", "1.2.3", "Alpha tools"},
	} {
		resp := publishDocument(t, server, pkg.name, map[string]any{
			"_id":          strings.ReplaceAll(pkg.name, "%2f", "/"),
			"name":         strings.ReplaceAll(pkg.name, "%2f", "/"),
			"dist-tags":    map[string]string{"latest": pkg.version},
			"versions":     map[string]any{pkg.version: map[string]any{"name": strings.ReplaceAll(pkg.name, "%2f", "/"), "version": pkg.version, "description": pkg.description}},
			"_attachments": map[string]any{"package.tgz": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(pkg.name))}},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("publish %s status = %d", pkg.name, resp.StatusCode)
		}
	}

	resp, err := http.Get(server.URL + "/-/v1/search?q=tools&from=1&size=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search status = %d", resp.StatusCode)
	}
	var result struct {
		Objects []struct {
			Package struct {
				Name        string            `json:"name"`
				Description string            `json:"description"`
				Version     string            `json:"version"`
				DistTags    map[string]string `json:"dist-tags"`
			} `json:"package"`
		} `json:"objects"`
		Total int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 || len(result.Objects) != 1 {
		t.Fatalf("search result = %#v", result)
	}
	pkg := result.Objects[0].Package
	if pkg.Name != "zebra" || pkg.Description != "Zebra tools" || pkg.Version != "1.0.0" || pkg.DistTags["latest"] != "1.0.0" {
		t.Fatalf("package = %#v", pkg)
	}
}

func TestSearchFindsMetadataWhenIndexIsMissing(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	server := testServerAt(t, dataDir, false, "*")
	resp := publish(t, server, "widget", "1.0.0", []byte("tarball"))
	resp.Body.Close()
	server.Close()
	if err := os.Remove(filepath.Join(dataDir, "index.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	server = testServerAt(t, dataDir, false, "*")
	defer server.Close()

	resp, err := http.Get(server.URL + "/-/v1/search?q=widget")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		Objects []json.RawMessage `json:"objects"`
		Total   int               `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || result.Total != 1 || len(result.Objects) != 1 {
		t.Fatalf("search status = %d, result = %#v", resp.StatusCode, result)
	}
}

func TestCatalogIsPublicAndUsesSearchAndInstallCommands(t *testing.T) {
	server := testServer(t, true, "*")
	defer server.Close()
	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") || !strings.Contains(page, "/-/v1/search") || !strings.Contains(page, "dpm install") {
		t.Fatalf("catalog status = %d, content-type = %q, body = %q", resp.StatusCode, resp.Header.Get("Content-Type"), page)
	}
}
