package ioc

import "sort"

// Outcome kinds returned per item by Ingest.
const (
	OutcomeCreated    = "created"
	OutcomeExisting   = "existing"
	OutcomeDupInBatch = "dup_in_batch"
	OutcomeRejected   = "rejected"
)

// Item is one raw indicator plus its source label.
type Item struct {
	Raw    string
	Source string
}

// Outcome is the per-item ingest result.
type Outcome struct {
	Kind   string
	ID     string
	Reason string
	// DupIndex is the 0-based index of the first equivalent item in the batch.
	DupIndex int
}

// Ingest processes one batch of at most MaxBatch items.
func (s *Store) Ingest(items []Item) ([]Outcome, error) {
	if len(items) > MaxBatch {
		return nil, ErrBatchTooLarge
	}
	outcomes := make([]Outcome, len(items))
	// canonical -> first index within this batch that produced it
	firstIndex := map[string]int{}
	changed := false

	for i, item := range items {
		kind, canonical, reason := Normalize(item.Raw)
		if reason != "" {
			outcomes[i] = Outcome{Kind: OutcomeRejected, Reason: reason}
			continue
		}
		if first, ok := firstIndex[canonical]; ok {
			mergeSource(s.records[canonical], item.Source)
			outcomes[i] = Outcome{
				Kind:     OutcomeDupInBatch,
				ID:       canonical,
				DupIndex: first,
			}
			changed = true
			continue
		}
		firstIndex[canonical] = i

		if rec, ok := s.records[canonical]; ok {
			mergeSource(rec, item.Source)
			outcomes[i] = Outcome{Kind: OutcomeExisting, ID: canonical}
			changed = true
			continue
		}

		rec := &Record{ID: canonical, Type: kind, Value: canonical}
		mergeSource(rec, item.Source)
		s.records[canonical] = rec
		outcomes[i] = Outcome{Kind: OutcomeCreated, ID: canonical}
		changed = true
	}

	if changed {
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return outcomes, nil
}

// mergeSource appends a source label unless already present, then sorts.
func mergeSource(rec *Record, source string) {
	if source == "" {
		return
	}
	for _, ex := range rec.Sources {
		if ex == source {
			return
		}
	}
	rec.Sources = append(rec.Sources, source)
	sort.Strings(rec.Sources)
}
