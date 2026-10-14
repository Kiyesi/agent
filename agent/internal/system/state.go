package system

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// FileState keeps the scan's facts in one YAML file that only its owner can read.
type FileState struct{ Path string }

// Load returns the saved facts, or none on a first scan.
func (s FileState) Load() (map[string]string, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return map[string]string{}, nil //nolint:nilerr // a damaged state file is started again
	}
	return m, nil
}

// Save writes the facts, replacing the file in one step.
func (s FileState) Save(m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// MemState keeps facts in memory, for tests.
type MemState struct{ M map[string]string }

// Load returns a copy of the facts.
func (s *MemState) Load() (map[string]string, error) {
	out := map[string]string{}
	for k, v := range s.M {
		out[k] = v
	}
	return out, nil
}

// Save replaces the facts.
func (s *MemState) Save(m map[string]string) error { s.M = m; return nil }
