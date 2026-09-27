package ioc

import (
	"errors"
	"os"
)

// ErrNotFound is returned when an id is absent from the store.
var ErrNotFound = errors.New("ioc: record not found")

// MaxBatch is the largest number of items accepted by Ingest.
const MaxBatch = 1000

// ErrBatchTooLarge is returned by Ingest when a batch exceeds MaxBatch;
// in that case the whole batch is rejected.
var ErrBatchTooLarge = errors.New("ioc: batch exceeds 1000 items")

// Record is one canonical indicator with its merged provenance.
type Record struct {
	ID      string   `json:"id"`
	Type    string   `json:"type"`
	Value   string   `json:"value"`
	Sources []string `json:"sources"`
}

// Store persists indicators in a local directory.
type Store struct {
	dir     string
	records map[string]*Record
}

// Open opens or creates the store rooted at dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, records: map[string]*Record{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Get returns the record with the given id and whether it exists.
func (s *Store) Get(id string) (Record, bool) {
	r, ok := s.records[id]
	if !ok {
		return Record{}, false
	}
	return *r, true
}

// Len returns the number of stored records.
func (s *Store) Len() int {
	return len(s.records)
}
