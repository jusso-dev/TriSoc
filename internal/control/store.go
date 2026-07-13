package control

import (
	"fmt"
	"os"
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
