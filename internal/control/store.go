package control

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Store struct {
	controls []Control
	byID     map[string][]Control
}

func LoadDefaultStore() (*Store, ValidationResult) {
	dir := os.Getenv("TRISOC_CONTROL_DIR")
	if dir == "" {
		dir = "controls"
	}
	return LoadStore(dir)
}

func LoadStore(paths ...string) (*Store, ValidationResult) {
	controls, result := LoadPaths(paths...)
	store := &Store{controls: controls, byID: make(map[string][]Control)}
	for _, c := range controls {
		store.byID[c.Metadata.ID] = append(store.byID[c.Metadata.ID], c)
	}
	return store, result
}

func (s *Store) List() []Control { return append([]Control(nil), s.controls...) }

func (s *Store) LatestByVendor(vendor string) []Control {
	latest := make(map[string]Control)
	for _, c := range s.controls {
		if c.Metadata.Vendor != vendor || c.Metadata.Status != "active" {
			continue
		}
		previous, ok := latest[c.Metadata.ID]
		if !ok || compareVersions(c.Metadata.Version, previous.Metadata.Version) > 0 {
			latest[c.Metadata.ID] = c
		}
	}
	out := make([]Control, 0, len(latest))
	for _, c := range latest {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata.ID < out[j].Metadata.ID })
	return out
}

func compareVersions(a, b string) int {
	parse := func(v string) [3]int {
		core := strings.SplitN(v, "-", 2)[0]
		parts := strings.Split(core, ".")
		var out [3]int
		for i := 0; i < len(parts) && i < 3; i++ {
			out[i], _ = strconv.Atoi(parts[i])
		}
		return out
	}
	av, bv := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return strings.Compare(a, b)
}

func (s *Store) Get(id, version string) (Control, error) {
	versions := s.byID[id]
	if len(versions) == 0 {
		return Control{}, fmt.Errorf("control %q not found", id)
	}
	if version == "" {
		if len(versions) > 1 {
			return Control{}, fmt.Errorf("control %q has multiple versions; specify version", id)
		}
		return versions[0], nil
	}
	for _, c := range versions {
		if c.Metadata.Version == version {
			return c, nil
		}
	}
	return Control{}, fmt.Errorf("control %q version %q not found", id, version)
}
