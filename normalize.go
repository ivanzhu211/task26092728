package iocstore

import (
	"net/netip"
	"strconv"
	"strings"
)

// refangReplacer undoes common defang spellings.
var refangReplacer = strings.NewReplacer(
	"[.]", ".",
	"(.)", ".",
	"{.}", ".",
	"[:]", ":",
)

// refangDot handles the case-insensitive [dot] / (dot) forms.
func refangDot(s string) string {
	for _, full := range []string{"[dot]", "(dot)"} {
		for {
			i := strings.Index(strings.ToLower(s), full)
			if i < 0 {
				break
			}
			s = s[:i] + "." + s[i+len(full):]
		}
	}
	return s
}

func refang(s string) string {
	return refangDot(refangReplacer.Replace(s))
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// parseIPv4Strict parses a strict dotted-quad: four decimal parts, each
// 0-255, no leading zeros, no other radixes or shorthand.
func parseIPv4Strict(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return netip.Addr{}, false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return netip.Addr{}, false
			}
		}
		if len(p) > 1 && p[0] == '0' {
			return netip.Addr{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return netip.Addr{}, false
		}
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// looksIPv4 reports whether s consists only of digits and dots.
func looksIPv4(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// normalizeIPv6 parses and canonicalizes an IPv6 address per RFC 5952
// section 4 (pure hex). IPv4-mapped addresses (::ffff:0:0/96) are
// returned as their IPv4 record instead.
func normalizeIPv6(s string) NormResult {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	if strings.Contains(s, "%") {
		return NormResult{Reason: RejectBadIPv6} // zone id
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Is4() {
		return NormResult{Reason: RejectBadIPv6}
	}
	if addr.Is4In6() {
		v4 := netip.AddrFrom4(addr.As4())
		return NormResult{OK: true, Kind: KindIPv4, Normalized: v4.String()}
	}
	return NormResult{OK: true, Kind: KindIPv6, Normalized: addr.String()}
}

// looksLikeHostPort reports whether s is shaped like host:port.
func looksLikeHostPort(s string) bool {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return false
	}
	if strings.Contains(s[:i], ":") {
		return false
	}
	return isAllDigits(s[i+1:]) && !looksIPv4(s)
}

func validASCIILabel(l string) bool {
	if len(l) < 1 || len(l) > 63 {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// normalizeDomain canonicalizes a domain name: lowercase, IDN labels
// punycode-encoded, single trailing root dot stripped.
func normalizeDomain(s string) NormResult {
	bad := NormResult{Reason: RejectBadDomain}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return bad
	}
	s = strings.ToLower(s)
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return bad
	}
	out := make([]string, len(labels))
	for i, l := range labels {
		if hasNonASCII(l) {
			l = "xn--" + encodePunycode(l)
		}
		if !validASCIILabel(l) {
			return bad
		}
		out[i] = l
	}
	if isAllDigits(out[len(out)-1]) {
		return bad
	}
	norm := strings.Join(out, ".")
	if len(norm) > 253 {
		return bad
	}
	return NormResult{OK: true, Kind: KindDomain, Normalized: norm}
}

// Normalize is a pure function mapping a raw analyst-pasted indicator to
// its kind and canonical form, or a rejection reason.
func Normalize(raw string) NormResult {
	s := strings.TrimSpace(raw)
	if s == "" {
		return NormResult{Reason: RejectEmpty}
	}
	s = refang(s)
	if s == "" {
		return NormResult{Reason: RejectEmpty}
	}
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' {
			return NormResult{Reason: RejectInternalSpace}
		}
	}
	if strings.Contains(s, "://") || strings.Contains(s, "/") || strings.Contains(s, "@") {
		return NormResult{Reason: RejectURLParts}
	}
	// SHA-256: exactly 64 hex chars.
	if len(s) == 64 {
		if isHex(s) {
			return NormResult{OK: true, Kind: KindSHA256, Normalized: strings.ToLower(s)}
		}
		// 64 chars, not hex: cannot be anything else (single label too
		// long for a domain, no dots/colons handling needed).
		if !strings.ContainsAny(s, ".:") {
			return NormResult{Reason: RejectBadSHA256}
		}
	}
	// IPv6: contains a colon, or is bracket-wrapped.
	if strings.Contains(s, ":") || (strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")) {
		if looksLikeHostPort(s) {
			return NormResult{Reason: RejectURLParts}
		}
		return normalizeIPv6(s)
	}
	// IPv4: digits and dots only.
	if looksIPv4(s) {
		if addr, ok := parseIPv4Strict(s); ok {
			return NormResult{OK: true, Kind: KindIPv4, Normalized: addr.String()}
		}
		return NormResult{Reason: RejectBadIPv4}
	}
	return normalizeDomain(s)
}
