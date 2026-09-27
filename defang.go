package iocstore

import (
	"errors"
	"strings"
)

// ErrUnknownID is returned by Defang for an id not present in the store.
var ErrUnknownID = errors.New("iocstore: unknown id")

// Defang renders the record with the given id in defanged form: dots in
// domains and IPv4 addresses become "[.]", colons in IPv6 addresses
// become "[:]", hashes are emitted as-is.
func (s *Store) Defang(id string) (string, error) {
	rec, ok := s.byID[id]
	if !ok {
		return "", ErrUnknownID
	}
	switch rec.Kind {
	case KindDomain, KindIPv4:
		return strings.ReplaceAll(rec.Normalized, ".", "[.]"), nil
	case KindIPv6:
		return strings.ReplaceAll(rec.Normalized, ":", "[:]"), nil
	default:
		return rec.Normalized, nil
	}
}
