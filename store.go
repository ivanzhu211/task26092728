package iocstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// MaxBatch is the maximum number of items accepted in one Ingest call.
const MaxBatch = 1000

// ErrTooManyItems is returned when a batch exceeds MaxBatch; the whole
// batch is rejected and nothing is ingested.
var ErrTooManyItems = errors.New("iocstore: batch exceeds 1000 items")

const storeFile = "store.json"

type diskState struct {
	NextID  int      `json:"next_id"`
	Records []Record `json:"records"`
}

// Open opens or creates a store rooted at dir. Records persist across
// reopen.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:    dir,
		byNorm: make(map[string]*Record),
		byID:   make(map[string]*Record),
		nextID: 1,
	}
	data, err := os.ReadFile(filepath.Join(dir, storeFile))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var st diskState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("iocstore: corrupt store file: %w", err)
	}
	s.nextID = st.NextID
	if s.nextID < 1 {
		s.nextID = 1
	}
	for i := range st.Records {
		r := st.Records[i]
		rec := r // copy
		s.records = append(s.records, &rec)
		s.byNorm[normKey(rec.Kind, rec.Normalized)] = &rec
		s.byID[rec.ID] = &rec
	}
	return s, nil
}

func normKey(k Kind, norm string) string {
	return k.String() + "|" + norm
}

func (s *Store) save() error {
	st := diskState{NextID: s.nextID}
	for _, r := range s.records {
		st.Records = append(st.Records, *r)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, storeFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, storeFile))
}

func mergeSource(rec *Record, source string) {
	if source == "" {
		return
	}
	for _, existing := range rec.Sources {
		if existing == source {
			return
		}
	}
	rec.Sources = append(rec.Sources, source)
}

// Ingest ingests a batch of items in input order. Batches larger than
// MaxBatch are rejected wholesale with ErrTooManyItems. A rejected item
// does not affect the rest of the batch.
func (s *Store) Ingest(items []Item) ([]Result, error) {
	if len(items) > MaxBatch {
		return nil, ErrTooManyItems
	}
	results := make([]Result, len(items))
	batchIdx := make(map[string]int) // normKey -> index of first batch entry
	for i, it := range items {
		nr := Normalize(it.Raw)
		if !nr.OK {
			results[i] = Result{Status: StatusRejected, Reason: nr.Reason}
			continue
		}
		key := normKey(nr.Kind, nr.Normalized)
		if rec, ok := s.byNorm[key]; ok {
			mergeSource(rec, it.Source)
			if j, seen := batchIdx[key]; seen {
				results[i] = Result{Status: StatusBatchDup, ID: rec.ID, DupOf: j}
			} else {
				batchIdx[key] = i
				results[i] = Result{Status: StatusExisting, ID: rec.ID}
			}
			continue
		}
		rec := &Record{
			ID:         fmt.Sprintf("ioc-%06d", s.nextID),
			Kind:       nr.Kind,
			Normalized: nr.Normalized,
		}
		s.nextID++
		mergeSource(rec, it.Source)
		s.records = append(s.records, rec)
		s.byNorm[key] = rec
		s.byID[rec.ID] = rec
		batchIdx[key] = i
		results[i] = Result{Status: StatusCreated, ID: rec.ID}
	}
	if err := s.save(); err != nil {
		return results, err
	}
	return results, nil
}

// Records returns all stored records in insertion order.
func (s *Store) Records() []Record {
	out := make([]Record, len(s.records))
	for i, r := range s.records {
		out[i] = *r
	}
	return out
}

// Lookup returns the record with the given id.
func (s *Store) Lookup(id string) (Record, bool) {
	if rec, ok := s.byID[id]; ok {
		return *rec, true
	}
	return Record{}, false
}
