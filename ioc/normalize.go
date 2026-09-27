package ioc

import (
	"net/netip"
	"strings"
	"unicode"
)

// Indicator type tags.
const (
	TypeSHA256 = "sha256"
	TypeIPv4   = "ipv4"
	TypeIPv6   = "ipv6"
	TypeDomain = "domain"
)

// Reject reasons reported by Normalize.
const (
	ReasonEmpty         = "empty"
	ReasonInternalSpace = "internal_space"
	ReasonScheme        = "scheme"
	ReasonPort          = "port"
	ReasonPath          = "path"
	ReasonCIDR          = "cidr"
	ReasonBracket       = "bracket"
	ReasonZone          = "zone"
	ReasonInvalidHex    = "invalid_hex"
	ReasonInvalidIPv4   = "invalid_ipv4"
	ReasonInvalidIPv6   = "invalid_ipv6"
	ReasonInvalidDomain = "invalid_domain"
	ReasonUnrecognized  = "unrecognized"
)

func reject(reason string) (string, string, string) {
	return "", "", reason
}

// refang rewrites known defensive notations back to literal separators.
// Recognized tokens (dot case-insensitive): [.] (.) {.} [dot] (dot) and [:].
func refang(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if i+3 <= len(s) {
			tri := s[i : i+3]
			if tri == "[.]" || tri == "(.)" || tri == "{.}" || tri == "[:]" {
				b.WriteByte(tri[1])
				i += 3
				continue
			}
		}
		if i+5 <= len(s) {
			lower := strings.ToLower(s[i : i+5])
			if lower == "[dot]" || lower == "(dot)" {
				b.WriteByte('.')
				i += 5
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func hasInternalSpace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// parseIPv4 strictly accepts four decimal octets, each 0-255, with no
// leading zeros, octal/hex, integer or abbreviated forms.
func parseIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			c := p[i]
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func looksIPv4ish(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// rfc5952 renders an IPv6 address per RFC 5952 section 4: lower-case hex,
// no leading zeros, maximal compression of the longest zero run, and pure
// hexadecimal groups (no embedded dotted IPv4 tail).
func rfc5952(addr netip.Addr) string {
	a16 := addr.As16()
	groups := make([]uint16, 8)
	for i := 0; i < 8; i++ {
		groups[i] = uint16(a16[2*i])<<8 | uint16(a16[2*i+1])
	}

	bestStart, bestLen := -1, 0
	runStart := -1
	closeRun := func(end int) {
		if runStart >= 0 {
			if l := end - runStart; l > bestLen {
				bestStart, bestLen = runStart, l
			}
			runStart = -1
		}
	}
	for i, g := range groups {
		if g == 0 {
			if runStart < 0 {
				runStart = i
			}
		} else {
			closeRun(i)
		}
	}
	closeRun(8)
	// RFC 5952 4.2.3: a single 16-bit zero field is never compressed;
	// ties between equal-length runs are broken toward the first run.
	if bestLen < 2 {
		bestStart, bestLen = -1, 0
	}

	const hex = "0123456789abcdef"
	hexGroup := func(g uint16) string {
		var sb strings.Builder
		started := false
		for sh := 12; sh >= 0; sh -= 4 {
			d := int(g>>uint(sh)) & 0xf
			if d != 0 || started {
				started = true
				sb.WriteByte(hex[d])
			}
		}
		if !started {
			sb.WriteByte('0')
		}
		return sb.String()
	}

	tokens := make([]string, 0, 9)
	for i := 0; i < 8; i++ {
		if i == bestStart {
			tokens = append(tokens, "")
			i += bestLen - 1
			continue
		}
		tokens = append(tokens, hexGroup(groups[i]))
	}
	out := strings.Join(tokens, ":")
	if bestStart == 0 {
		out = ":" + out
	}
	if bestStart+bestLen == 8 {
		out += ":"
	}
	return out
}

// normalizeDomain validates and canonicalizes a refanged domain.
func normalizeDomain(d string) (string, bool) {
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", false
	}
	// A single trailing root dot is permitted; drop it. Anything that
	// leaves fewer than two labels or an empty label is rejected.
	if labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1]
	}
	if len(labels) < 2 {
		return "", false
	}

	encoded := make([]string, len(labels))
	total := 0
	for i, label := range labels {
		if label == "" {
			return "", false
		}
		lower := strings.ToLower(label)
		if lower[0] == '-' || lower[len(lower)-1] == '-' {
			return "", false
		}
		enc, err := punycodeEncodeLabel(lower)
		if err != nil {
			return "", false
		}
		if !isASCIILabel(lower) {
			enc = "xn--" + enc
		}
		if !strings.HasPrefix(enc, "xn--") {
			for j := 0; j < len(enc); j++ {
				c := enc[j]
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
					return "", false
				}
			}
		}
		if len(enc) > 63 || enc[0] == '-' || enc[len(enc)-1] == '-' {
			return "", false
		}
		encoded[i] = enc
		total += len(enc) + 1
	}
	if total > 253 {
		return "", false
	}
	tld := encoded[len(encoded)-1]
	tldAllDigits := true
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			tldAllDigits = false
			break
		}
	}
	if tldAllDigits {
		return "", false
	}
	return strings.Join(encoded, "."), true
}

func isASCIILabel(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// isBarePort reports whether a colon-bearing string is plausibly host:port
// with a single decimal port suffix rather than an IPv6 address.
func isBarePort(s string) bool {
	if strings.Count(s, ":") != 1 {
		return false
	}
	port := s[strings.LastIndex(s, ":")+1:]
	if port == "" {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	return true
}

// Normalize trims, refangs, classifies and canonicalizes a raw indicator.
func Normalize(raw string) (kind, canonical string, reason string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return reject(ReasonEmpty)
	}
	if hasInternalSpace(s) {
		return reject(ReasonInternalSpace)
	}
	if i := strings.Index(s, "://"); i >= 0 {
		if i > 0 {
			return reject(ReasonScheme)
		}
		return reject(ReasonUnrecognized)
	}

	s = refang(s)

	// Slash means CIDR prefix (numeric suffix) or a path component.
	if i := strings.IndexByte(s, '/'); i >= 0 {
		suffix := s[i+1:]
		isCIDR := suffix != ""
		for j := 0; j < len(suffix); j++ {
			if suffix[j] < '0' || suffix[j] > '9' {
				isCIDR = false
				break
			}
		}
		if isCIDR {
			return reject(ReasonCIDR)
		}
		return reject(ReasonPath)
	}
	if strings.ContainsRune(s, '\\') {
		return reject(ReasonPath)
	}

	// Optional overall square brackets around an IPv6 literal, possibly
	// followed by a :port, which is itself a rejected form.
	bracketed := false
	if len(s) >= 2 && s[0] == '[' {
		if end := strings.IndexByte(s, ']'); end >= 0 {
			if end == len(s)-1 {
				bracketed = true
				s = s[1:end]
			} else if s[end+1] == ':' {
				return reject(ReasonPort)
			}
		}
	}
	if strings.ContainsAny(s, "[](){}") {
		return reject(ReasonBracket)
	}

	if strings.Contains(s, "%") {
		return reject(ReasonZone)
	}

	if isHex64(s) {
		return TypeSHA256, strings.ToLower(s), ""
	}

	if strings.Contains(s, ":") {
		if !bracketed && isBarePort(s) {
			return reject(ReasonPort)
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return reject(ReasonInvalidIPv6)
		}
		addr = addr.Unmap()
		if addr.Is4() {
			return TypeIPv4, addr.String(), ""
		}
		return TypeIPv6, rfc5952(addr), ""
	}

	if strings.Contains(s, ".") {
		if looksIPv4ish(s) {
			if parseIPv4(s) {
				return TypeIPv4, s, ""
			}
			return reject(ReasonInvalidIPv4)
		}
		if d, ok := normalizeDomain(s); ok {
			return TypeDomain, d, ""
		}
		return reject(ReasonInvalidDomain)
	}

	return reject(ReasonUnrecognized)
}
