package ioc

import "strings"

// Defang rewrites dots and colons of a stored indicator into defensive form.
func (s *Store) Defang(id string) (string, error) {
	rec, ok := s.records[id]
	if !ok {
		return "", ErrNotFound
	}
	switch rec.Type {
	case TypeDomain, TypeIPv4:
		return strings.ReplaceAll(rec.Value, ".", "[.]"), nil
	case TypeIPv6:
		return strings.ReplaceAll(rec.Value, ":", "[:]"), nil
	default:
		return rec.Value, nil
	}
}
