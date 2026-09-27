// Package registry implements a small filesystem-backed npm registry.
package registry

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxPublishBytes = 32 << 20

// Config is the JSON-serializable server configuration.
type Config struct {
	DataDir   string  `json:"data_dir"`
	PublicURL string  `json:"public_url"`
	ReadAuth  bool    `json:"read_auth"`
	Tokens    []Token `json:"tokens"`
}

// Token holds a SHA-256 hash of a bearer token and the package scopes it may publish.
type Token struct {
	Hash   string   `json:"hash"`
	User   string   `json:"user"`
	Scopes []string `json:"scopes"`
}

type store struct {
	dir       string
	publicURL string
	mu        sync.Mutex
	syncDir   func(string) error
}

type metadata struct {
	Name     string                     `json:"name"`
	DistTags map[string]string          `json:"dist-tags"`
	Versions map[string]json.RawMessage `json:"versions"`
}

type packageIndex struct {
	Packages []string `json:"packages"`
}

// NewHandler constructs a registry HTTP handler.
func NewHandler(config Config) (http.Handler, error) {
	if config.DataDir == "" {
		return nil, errors.New("data_dir is required")
	}
	publicURL, err := normalizePublicURL(config.PublicURL)
	if err != nil {
		return nil, err
	}
	for _, token := range config.Tokens {
		if _, err := hex.DecodeString(token.Hash); err != nil || len(token.Hash) != sha256.Size*2 {
			return nil, fmt.Errorf("invalid token hash for %q", token.User)
		}
	}
	if err := os.MkdirAll(filepath.Join(config.DataDir, "packages"), 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(config.DataDir, "tarballs"), 0700); err != nil {
		return nil, err
	}
	config.PublicURL = publicURL
	r := &registry{config: config, store: store{dir: config.DataDir, publicURL: publicURL, syncDir: syncDirectory}}
	return http.TimeoutHandler(r, 30*time.Second, `{"error":"request timed out"}`), nil
}

type registry struct {
	config Config
	store  store
}

func (r *registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet && req.URL.Path == "/" {
		r.catalog(w)
		return
	}
	if req.Method == http.MethodGet && req.URL.Path == "/-/v1/search" {
		r.search(w, req)
		return
	}
	if req.Method == http.MethodGet && req.URL.Path == "/-/ping" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if req.Method == http.MethodGet && req.URL.Path == "/-/whoami" {
		token, ok := r.authenticate(req)
		if !ok {
			unauthorized(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"username": token.User})
		return
	}

	name, tail, err := requestPackage(req.URL)
	if err != nil {
		http.Error(w, "invalid package path", http.StatusBadRequest)
		return
	}
	if req.Method == http.MethodPut && tail == "" {
		token, ok := r.authenticate(req)
		if !ok {
			unauthorized(w)
			return
		}
		if !canPublish(token, name) {
			http.Error(w, "token is not authorized for this package", http.StatusForbidden)
			return
		}
		r.publish(w, req, name)
		return
	}
	if req.Method == http.MethodGet && tail == "" {
		if r.config.ReadAuth {
			if _, ok := r.authenticate(req); !ok {
				unauthorized(w)
				return
			}
		}
		r.packument(w, req, name)
		return
	}
	if req.Method == http.MethodGet && strings.HasPrefix(tail, "-/") {
		if r.config.ReadAuth {
			if _, ok := r.authenticate(req); !ok {
				unauthorized(w)
				return
			}
		}
		r.tarball(w, name, strings.TrimPrefix(tail, "-/"))
		return
	}
	http.NotFound(w, req)
}

func (r *registry) search(w http.ResponseWriter, req *http.Request) {
	from, size, err := searchPaging(req.URL.Query())
	if err != nil {
		http.Error(w, "invalid search pagination", http.StatusBadRequest)
		return
	}
	query := strings.ToLower(strings.TrimSpace(req.URL.Query().Get("q")))
	names, err := r.store.packages()
	if err != nil {
		http.Error(w, "unable to read package index", http.StatusInternalServerError)
		return
	}
	objects := make([]map[string]any, 0)
	for _, name := range names {
		meta, err := r.store.load(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			http.Error(w, "unable to read package", http.StatusInternalServerError)
			return
		}
		version := meta.DistTags["latest"]
		var manifest struct {
			Description string `json:"description"`
		}
		if version != "" {
			json.Unmarshal(meta.Versions[version], &manifest)
		}
		if query != "" && !strings.Contains(strings.ToLower(name), query) && !strings.Contains(strings.ToLower(manifest.Description), query) {
			continue
		}
		objects = append(objects, map[string]any{"package": map[string]any{
			"name": name, "description": manifest.Description, "version": version, "dist-tags": meta.DistTags,
		}})
	}
	total := len(objects)
	if from > total {
		from = total
	}
	end := from + size
	if end > total {
		end = total
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": objects[from:end], "total": total})
}

func searchPaging(query url.Values) (int, int, error) {
	from, size := 0, 20
	var err error
	if value := query.Get("from"); value != "" {
		from, err = strconv.Atoi(value)
		if err != nil || from < 0 {
			return 0, 0, errors.New("invalid from")
		}
	}
	if value := query.Get("size"); value != "" {
		size, err = strconv.Atoi(value)
		if err != nil || size < 0 || size > 250 {
			return 0, 0, errors.New("invalid size")
		}
	}
	return from, size, nil
}

func (r *registry) catalog(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, catalogHTML)
}

const catalogHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DPM Registry</title><style>body{font:16px system-ui,sans-serif;max-width:48rem;margin:3rem auto;padding:0 1rem;color:#171717}input{width:100%;box-sizing:border-box;padding:.7rem;font:inherit}article{border-bottom:1px solid #ddd;padding:1rem 0}code{display:block;background:#f4f4f4;padding:.5rem;overflow:auto}</style><h1>DPM Registry</h1><p>Browse public packages and install directly from this registry.</p><label>Search packages <input id="q" autofocus></label><main></main><script>const q=document.querySelector('#q'),main=document.querySelector('main');async function search(){const r=await fetch('/-/v1/search?q='+encodeURIComponent(q.value));const d=await r.json();main.replaceChildren(...d.objects.map(({package:p})=>{const a=document.createElement('article'),h=document.createElement('strong'),x=document.createElement('p'),c=document.createElement('code');h.textContent=p.name+' '+p.version;x.textContent=p.description||'No description.';c.textContent='dpm install '+p.name+' --registry '+location.origin;a.append(h,x,c);return a}))}q.addEventListener('input',search);search()</script></html>`

func (r *registry) publish(w http.ResponseWriter, req *http.Request, name string) {
	req.Body = http.MaxBytesReader(w, req.Body, maxPublishBytes)
	defer req.Body.Close()
	var document struct {
		ID          string                     `json:"_id"`
		Name        string                     `json:"name"`
		DistTags    map[string]string          `json:"dist-tags"`
		Versions    map[string]json.RawMessage `json:"versions"`
		Attachments map[string]struct {
			Data string `json:"data"`
		} `json:"_attachments"`
	}
	if err := json.NewDecoder(req.Body).Decode(&document); err != nil {
		http.Error(w, "invalid publish document", http.StatusBadRequest)
		return
	}
	if document.ID != name || document.Name != name {
		http.Error(w, "package name does not match path", http.StatusBadRequest)
		return
	}
	if len(document.Versions) != 1 || len(document.Attachments) != 1 {
		http.Error(w, "one version and one attachment are required", http.StatusBadRequest)
		return
	}
	var version string
	var versionData json.RawMessage
	for version, versionData = range document.Versions {
	}
	if !validVersion(version) {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return
	}
	manifest, err := validateManifest(versionData, name, version)
	if err != nil {
		http.Error(w, "invalid version manifest", http.StatusBadRequest)
		return
	}
	var attachmentData string
	for _, attachment := range document.Attachments {
		attachmentData = attachment.Data
	}
	data, err := base64.StdEncoding.DecodeString(attachmentData)
	if err != nil || len(data) == 0 {
		http.Error(w, "invalid tarball attachment", http.StatusBadRequest)
		return
	}
	if len(data) > maxPublishBytes {
		http.Error(w, "tarball is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := r.store.publish(name, version, data, manifest, document.DistTags); err != nil {
		if errors.Is(err, errImmutable) {
			http.Error(w, "version already exists", http.StatusConflict)
			return
		}
		if errors.Is(err, errInvalidTag) {
			http.Error(w, "dist-tag references an absent version", http.StatusBadRequest)
			return
		}
		http.Error(w, "unable to publish package", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (r *registry) packument(w http.ResponseWriter, req *http.Request, name string) {
	meta, err := r.store.load(name)
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, req)
		return
	}
	if err != nil {
		http.Error(w, "unable to read package", http.StatusInternalServerError)
		return
	}
	if strings.Contains(req.Header.Get("Accept"), "application/vnd.npm.install-v1+json") {
		w.Header().Set("Content-Type", "application/vnd.npm.install-v1+json")
	}
	writeJSON(w, http.StatusOK, meta)
}

func (r *registry) tarball(w http.ResponseWriter, name, filename string) {
	digest, ok := contentAddressedTarball(filename)
	if !ok {
		http.Error(w, "invalid tarball path", http.StatusBadRequest)
		return
	}
	f, err := os.Open(filepath.Join(r.store.dir, "tarballs", digest+".tgz"))
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, nil)
		return
	}
	if err != nil {
		http.Error(w, "unable to read tarball", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	io.Copy(w, f)
}

var errImmutable = errors.New("immutable version")
var errInvalidTag = errors.New("dist-tag references an absent version")

func (s *store) publish(name, version string, contents []byte, manifest map[string]any, tags map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	meta, err := s.load(name)
	if errors.Is(err, os.ErrNotExist) {
		meta = metadata{Name: name, Versions: map[string]json.RawMessage{}, DistTags: map[string]string{}}
	} else if err != nil {
		return err
	}
	if _, exists := meta.Versions[version]; exists {
		return errImmutable
	}
	for _, target := range tags {
		if target == version {
			continue
		}
		if _, exists := meta.Versions[target]; !exists {
			return errInvalidTag
		}
	}
	digest := sha256.Sum256(contents)
	digestText := hex.EncodeToString(digest[:])
	tarballPath := filepath.Join(s.dir, "tarballs", digestText+".tgz")
	_, err = os.Stat(tarballPath)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !existed {
		if _, err := s.atomicWrite(tarballPath, contents, 0600); err != nil {
			return err
		}
	}
	sha := sha512.Sum512(contents)
	manifest["dist"] = map[string]string{
		"tarball":   s.tarballURL(name, digestText),
		"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sha[:]),
	}
	updatedVersion, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	meta.Versions[version] = updatedVersion
	for tag, value := range tags {
		meta.DistTags[tag] = value
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	metadataCommitted, err := s.atomicWrite(filepath.Join(s.packageDir(name), "metadata.json"), encoded, 0600)
	if err != nil {
		if !metadataCommitted && !existed {
			os.Remove(tarballPath)
		}
		return err
	}
	return s.addPackage(name)
}

func (s *store) tarballURL(name, digest string) string {
	path := url.PathEscape(name) + "/-/" + digest + ".tgz"
	if s.publicURL == "" {
		return "/" + path
	}
	return strings.TrimRight(s.publicURL, "/") + "/" + path
}

func normalizePublicURL(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("public_url must be an absolute HTTP(S) URL without query or fragment")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

// MigrateTarballs rewrites legacy root-relative tarball URLs using public_url.
// It atomically updates only metadata that needs a change and is idempotent.
func MigrateTarballs(config Config) (int, error) {
	if config.DataDir == "" {
		return 0, errors.New("data_dir is required")
	}
	publicURL, err := normalizePublicURL(config.PublicURL)
	if err != nil {
		return 0, err
	}
	if publicURL == "" {
		return 0, errors.New("public_url is required for tarball migration")
	}
	s := store{dir: config.DataDir, publicURL: publicURL, syncDir: syncDirectory}
	names, err := s.packages()
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, name := range names {
		meta, err := s.load(name)
		if err != nil {
			return changed, err
		}
		updated := false
		for version, raw := range meta.Versions {
			var manifest map[string]any
			if err := json.Unmarshal(raw, &manifest); err != nil {
				return changed, fmt.Errorf("decode %s@%s: %w", name, version, err)
			}
			dist, ok := manifest["dist"].(map[string]any)
			tarball, ok := dist["tarball"].(string)
			if !ok || !strings.HasPrefix(tarball, "/") {
				continue
			}
			dist["tarball"] = strings.TrimRight(publicURL, "/") + tarball
			encoded, err := json.Marshal(manifest)
			if err != nil {
				return changed, fmt.Errorf("encode %s@%s: %w", name, version, err)
			}
			meta.Versions[version] = encoded
			updated = true
			changed++
		}
		if !updated {
			continue
		}
		encoded, err := json.Marshal(meta)
		if err != nil {
			return changed, err
		}
		if _, err := s.atomicWrite(filepath.Join(s.packageDir(name), "metadata.json"), encoded, 0600); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func (s *store) load(name string) (metadata, error) {
	data, err := os.ReadFile(filepath.Join(s.packageDir(name), "metadata.json"))
	if err != nil {
		return metadata{}, err
	}
	var meta metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return metadata{}, err
	}
	return meta, nil
}

func (s *store) packageDir(name string) string {
	hash := sha256.Sum256([]byte(name))
	return filepath.Join(s.dir, "packages", hex.EncodeToString(hash[:]))
}

func (s *store) addPackage(name string) error {
	index, err := s.loadIndex()
	if errors.Is(err, os.ErrNotExist) {
		index = packageIndex{}
	} else if err != nil {
		return err
	}
	for _, existing := range index.Packages {
		if existing == name {
			return nil
		}
	}
	index.Packages = append(index.Packages, name)
	sort.Strings(index.Packages)
	data, err := json.Marshal(index)
	if err != nil {
		return err
	}
	_, err = s.atomicWrite(filepath.Join(s.dir, "index.json"), data, 0600)
	return err
}

func (s *store) loadIndex() (packageIndex, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, "index.json"))
	if err != nil {
		return packageIndex{}, err
	}
	var index packageIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return packageIndex{}, err
	}
	return index, nil
}

// packages merges the durable index with filesystem metadata written before indexing existed.
func (s *store) packages() ([]string, error) {
	index, err := s.loadIndex()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	names := make(map[string]struct{}, len(index.Packages))
	for _, name := range index.Packages {
		names[name] = struct{}{}
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "packages"))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, "packages", entry.Name(), "metadata.json"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var meta metadata
		if err := json.Unmarshal(data, &meta); err != nil {
			return nil, err
		}
		if err := validPackage(meta.Name); err != nil {
			return nil, err
		}
		names[meta.Name] = struct{}{}
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func (s *store) atomicWrite(path string, data []byte, mode os.FileMode) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return false, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return false, err
	}
	if s.syncDir == nil {
		return true, nil
	}
	if err := s.syncDir(filepath.Dir(path)); err != nil {
		return true, err
	}
	return true, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func validVersion(version string) bool {
	return versionPattern.MatchString(version)
}

func validateManifest(data json.RawMessage, name, version string) (map[string]any, error) {
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil || manifest == nil {
		return nil, errors.New("manifest must be an object")
	}
	manifestName, nameOK := manifest["name"].(string)
	manifestVersion, versionOK := manifest["version"].(string)
	if !nameOK || !versionOK || manifestName != name || manifestVersion != version {
		return nil, errors.New("manifest does not match package version")
	}
	return manifest, nil
}

func contentAddressedTarball(filename string) (string, bool) {
	if !strings.HasSuffix(filename, ".tgz") || len(filename) != sha256.Size*2+len(".tgz") {
		return "", false
	}
	digest := strings.TrimSuffix(filename, ".tgz")
	decoded, err := hex.DecodeString(digest)
	return digest, err == nil && len(decoded) == sha256.Size && digest == strings.ToLower(digest)
}

func requestPackage(raw *url.URL) (string, string, error) {
	path, err := url.PathUnescape(strings.TrimPrefix(raw.EscapedPath(), "/"))
	if err != nil || path == "" {
		return "", "", errors.New("invalid path")
	}
	parts := strings.SplitN(path, "/-/", 2)
	name := parts[0]
	if err := validPackage(name); err != nil {
		return "", "", err
	}
	if len(parts) == 2 {
		return name, "-/" + parts[1], nil
	}
	return name, "", nil
}

func validPackage(name string) error {
	if name == "." || name == ".." || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return errors.New("invalid package")
	}
	if strings.HasPrefix(name, "@") {
		if strings.Count(name, "/") != 1 || strings.HasPrefix(name, "@/") || strings.HasSuffix(name, "/") {
			return errors.New("invalid scoped package")
		}
	} else if strings.Contains(name, "/") {
		return errors.New("invalid unscoped package")
	}
	return nil
}

func (r *registry) authenticate(req *http.Request) (Token, bool) {
	value := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if value == "" || !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") {
		return Token{}, false
	}
	sum := sha256.Sum256([]byte(value))
	for _, token := range r.config.Tokens {
		stored, err := hex.DecodeString(token.Hash)
		if err == nil && subtle.ConstantTimeCompare(stored, sum[:]) == 1 {
			return token, true
		}
	}
	return Token{}, false
}

func canPublish(token Token, name string) bool {
	for _, scope := range token.Scopes {
		if scope == "*" || (strings.HasSuffix(scope, "/*") && strings.HasPrefix(name, strings.TrimSuffix(scope, "*"))) {
			return true
		}
	}
	return false
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
