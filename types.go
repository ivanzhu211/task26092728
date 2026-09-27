// Package iocstore implements a threat-intelligence IOC ingestion
// component using only the Go standard library.
package iocstore

// Kind is the type of an indicator.
type Kind int

const (
	KindSHA256 Kind = iota
	KindIPv4
	KindIPv6
	KindDomain
)

func (k Kind) String() string {
	switch k {
	case KindSHA256:
		return "sha256"
	case KindIPv4:
		return "ipv4"
	case KindIPv6:
		return "ipv6"
	case KindDomain:
		return "domain"
	}
	return "unknown"
}

// RejectReason distinguishes why an input was refused.
type RejectReason string

const (
	RejectEmpty         RejectReason = "empty"
	RejectInternalSpace RejectReason = "internal-whitespace"
	RejectURLParts      RejectReason = "url-parts" // scheme, port, path, CIDR
	RejectBadSHA256     RejectReason = "bad-sha256"
	RejectBadIPv4       RejectReason = "bad-ipv4"
	RejectBadIPv6       RejectReason = "bad-ipv6"
	RejectBadDomain     RejectReason = "bad-domain"
)

// NormResult is the outcome of Normalize.
type NormResult struct {
	OK         bool
	Kind       Kind
	Normalized string
	Reason     RejectReason
}

// Item is one ingestion entry.
type Item struct {
	Raw    string
	Source string
}

// Status is the per-item ingestion outcome.
type Status int

const (
	StatusCreated Status = iota
	StatusExisting
	StatusBatchDup
	StatusRejected
)

// Result is the per-item ingestion result.
type Result struct {
	Status Status
	ID     string // set for Created / Existing
	DupOf  int    // 0-based index of the earlier batch entry, for BatchDup
	Reason RejectReason
}

// Record is a stored indicator.
type Record struct {
	ID         string   `json:"id"`
	Kind       Kind     `json:"kind"`
	Normalized string   `json:"normalized"`
	Sources    []string `json:"sources"`
}

// Store persists records under a directory.
type Store struct {
	dir     string
	byNorm  map[string]*Record
	byID    map[string]*Record
	records []*Record
	nextID  int
}
