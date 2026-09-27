package iocstore

import "strings"

// Punycode encoder, RFC 3492. Only encoding (to ASCII) is needed.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func pcAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

// encodePunycode encodes a label (already lowercased) per RFC 3492.
// Pure-ASCII labels are returned unchanged.
func encodePunycode(label string) string {
	runes := []rune(label)
	var out strings.Builder
	basic := 0
	for _, r := range runes {
		if r < 0x80 {
			out.WriteByte(byte(r))
			basic++
		}
	}
	h := basic
	if basic > 0 && h < len(runes) {
		out.WriteByte('-')
	}
	n := pcInitialN
	delta := 0
	bias := pcInitialBias
	for h < len(runes) {
		m := int(^uint(0) >> 1)
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			c := int(r)
			if c < n {
				delta++
			}
			if c == n {
				q := delta
				for k := pcBase; ; k += pcBase {
					var t int
					switch {
					case k <= bias:
						t = pcTMin
					case k >= bias+pcTMax:
						t = pcTMax
					default:
						t = k - bias
					}
					if q < t {
						break
					}
					out.WriteByte(pcDigit(t + (q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				out.WriteByte(pcDigit(q))
				bias = pcAdapt(delta, h+1, h == basic)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return out.String()
}
