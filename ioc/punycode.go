package ioc

import (
	"errors"
	"strings"
)

// RFC 3492 parameters.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

var errPunycodeOverflow = errors.New("ioc: punycode overflow")

// punycodeAdapt is the bias adaptation function from RFC 3492 section 3.4.
func punycodeAdapt(delta, numPoints int, firstTime bool) int {
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
	return k + ((pcBase-pcTMin+1)*delta)/(delta+pcSkew)
}

func punycodeDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + (d - 26))
}

// punycodeEncodeLabel implements the Punycode encoding of RFC 3492 for one
// already-lowercased label. Pure-ASCII labels are returned unchanged.
func punycodeEncodeLabel(label string) (string, error) {
	runes := []rune(label)
	var basic strings.Builder
	for _, r := range runes {
		if r < pcInitialN {
			basic.WriteRune(r)
		}
	}
	b := basic.Len()
	if b == len(runes) {
		return label, nil
	}

	out := make([]byte, 0, len(label)+4)
	out = append(out, basic.String()...)
	if b > 0 {
		out = append(out, '-')
	}

	n, delta, bias := pcInitialN, 0, pcInitialBias
	h := b
	for h < len(runes) {
		m := 0x110000
		for _, c := range runes {
			if int(c) >= n && int(c) < m {
				m = int(c)
			}
		}
		delta += (m - n) * (h + 1)
		if delta < 0 {
			return "", errPunycodeOverflow
		}
		n = m
		for _, c := range runes {
			ic := int(c)
			if ic < n {
				delta++
				if delta < 0 {
					return "", errPunycodeOverflow
				}
			}
			if ic == n {
				q := delta
				for k := pcBase; ; k += pcBase {
					t := pcTMin
					if k-bias > pcTMin {
						t = k - bias
					}
					if k-bias >= pcTMax {
						t = pcTMax
					}
					if q < t {
						break
					}
					out = append(out, punycodeDigit(t+(q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				out = append(out, punycodeDigit(q))
				bias = punycodeAdapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return string(out), nil
}
