package ioc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

const storeFile = "records.json"

// load reads all records from the store directory.
func (s *Store) load() error {
	data, err := os.ReadFile(filepath.Join(s.dir, storeFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var records []*Record
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	for _, r := range records {
		s.records[r.ID] = r
	}
	return nil
}

// save writes all records to the store directory atomically.
func (s *Store) save() error {
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	records := make([]*Record, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.records[id])
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".records-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(s.dir, storeFile))
}
