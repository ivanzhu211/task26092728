package iocstore

import (
	"fmt"
	"strings"
	"testing"
)

const testHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// equivalence groups: every variant in a group must land on one record.
var groups = map[string][]string{
	"sha256": {
		testHash,
		strings.ToUpper(testHash),
		"  " + testHash + "\t",
	},
	"ipv6": {
		"[2001:db8::1]",
		"2001[:]db8[:][:]1",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"2001:DB8::1",
	},
	"ipv4-mapped": {
		"::ffff:c000:201",
		"::ffff:192.0.2.1",
		"[::ffff:c000:0201]",
		"192.0.2.1",
		"192[.]0[.]2[.]1",
		"192[dot]0(DOT)2{.}1",
	},
	"domain": {
		"Bücher.DE.",
		"xn--bcher-kva.de",
		"bücher.de",
		"XN--BCHER-KVA.DE",
		"bücher[dot]de",
	},
}

var wantNorm = map[string]struct {
	kind Kind
	norm string
}{
	"sha256":      {KindSHA256, testHash},
	"ipv6":        {KindIPv6, "2001:db8::1"},
	"ipv4-mapped": {KindIPv4, "192.0.2.1"},
	"domain":      {KindDomain, "xn--bcher-kva.de"},
}

func TestEquivalenceGroups(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Interleave variants of all groups into one batch.
	var items []Item
	var want []Result
	groupFirstIdx := map[string]int{}
	maxLen := 0
	for _, variants := range groups {
		if len(variants) > maxLen {
			maxLen = len(variants)
		}
	}
	names := []string{"sha256", "ipv6", "ipv4-mapped", "domain"}
	for round := 0; round < maxLen; round++ {
		for _, g := range names {
			variants := groups[g]
			if round >= len(variants) {
				continue
			}
			items = append(items, Item{Raw: variants[round], Source: fmt.Sprintf("src-%d", round)})
			if round == 0 {
				groupFirstIdx[g] = len(items) - 1
				want = append(want, Result{Status: StatusCreated})
			} else {
				want = append(want, Result{Status: StatusBatchDup, DupOf: groupFirstIdx[g]})
			}
		}
	}

	results, err := st.Ingest(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(items) {
		t.Fatalf("got %d results for %d items", len(results), len(items))
	}

	// Per-group record ids must be identical across all variants.
	groupID := map[string]string{}
	for i, res := range results {
		w := want[i]
		if res.Status != w.Status {
			t.Errorf("item %d (%q): status %v, want %v", i, items[i].Raw, res.Status, w.Status)
		}
		if res.Status == StatusBatchDup && res.DupOf != w.DupOf {
			t.Errorf("item %d (%q): DupOf %d, want %d", i, items[i].Raw, res.DupOf, w.DupOf)
		}
		if res.Status == StatusCreated || res.Status == StatusBatchDup {
			// find group by first index
			for g, first := range groupFirstIdx {
				idx := i
				if res.Status == StatusBatchDup {
					idx = res.DupOf
				}
				if idx == first {
					if groupID[g] == "" {
						groupID[g] = res.ID
					} else if groupID[g] != res.ID {
						t.Errorf("group %s: variant %q got id %s, want %s", g, items[i].Raw, res.ID, groupID[g])
					}
				}
			}
		}
	}

	// Exactly one record per group, with the expected canonical form and
	// every variant's source merged in.
	records := st.Records()
	if len(records) != len(groups) {
		t.Fatalf("got %d records, want %d: %+v", len(records), len(groups), records)
	}
	seen := map[string]bool{}
	for _, rec := range records {
		for g, w := range wantNorm {
			if rec.Kind == w.kind && rec.Normalized == w.norm {
				if seen[g] {
					t.Errorf("group %s: duplicate record %+v", g, rec)
				}
				seen[g] = true
				if len(rec.Sources) != len(groups[g]) {
					t.Errorf("group %s: sources %v, want %d entries", g, rec.Sources, len(groups[g]))
				}
			}
		}
	}
	for g := range groups {
		if !seen[g] {
			t.Errorf("group %s: no matching record; records=%+v", g, records)
		}
	}

	// A second batch with one more variant per group must hit the
	// existing records and merge the new source.
	var items2 []Item
	for _, g := range names {
		switch g {
		case "sha256":
			items2 = append(items2, Item{Raw: strings.ToUpper(testHash), Source: "second-pass"})
		case "ipv6":
			items2 = append(items2, Item{Raw: "2001:db8:0:0:0:0:0:1", Source: "second-pass"})
		case "ipv4-mapped":
			items2 = append(items2, Item{Raw: "::ffff:192[.]0[.]2[.]1", Source: "second-pass"})
		case "domain":
			items2 = append(items2, Item{Raw: "BÜCHER.DE", Source: "second-pass"})
		}
	}
	results2, err := st.Ingest(items2)
	if err != nil {
		t.Fatal(err)
	}
	for i, res := range results2 {
		if res.Status != StatusExisting {
			t.Errorf("second batch item %d (%q): status %v, want StatusExisting", i, items2[i].Raw, res.Status)
		}
	}
	for _, rec := range st.Records() {
		found := false
		for _, src := range rec.Sources {
			if src == "second-pass" {
				found = true
			}
		}
		if !found {
			t.Errorf("record %+v missing merged source second-pass", rec)
		}
	}

	// Reopen: records must survive.
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st2.Records()) != len(groups) {
		t.Fatalf("after reopen: got %d records, want %d", len(st2.Records()), len(groups))
	}
	res3, err := st2.Ingest([]Item{{Raw: "192.0.2.1", Source: "third"}})
	if err != nil {
		t.Fatal(err)
	}
	if res3[0].Status != StatusExisting {
		t.Errorf("after reopen: 192.0.2.1 status %v, want StatusExisting", res3[0].Status)
	}
}

func TestRejections(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{
		// sha256 near-misses
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("g", 64),
		// ipv4 near-misses
		"010.1.1.1",  // leading zero
		"1.2.3.256",  // out of range
		"127.1",      // omitted octets
		"2130706433", // integer form
		"0x7f.0.0.1", // hex
		"1.2.3.4.5",  // too many parts
		"1.2.3.",     // empty part
		// ipv6 near-misses
		"fe80::1%eth0",   // zone id
		"2001:db8::1/64", // CIDR
		"12345::",        // group too long
		"1:2:3:4:5:6:7:8:9",
		"::ffff:999.0.2.1",
		// url-ish
		"http://example.com",
		"example.com:8080",
		"example.com/path",
		"1.2.3.4/24",
		// domain near-misses
		"-bad.com",
		"bad-.com",
		"a..b.com",
		"localhost",
		"ex ample.com",
		strings.Repeat("a", 64) + ".com", // label too long
		"1.2.3.999",
	}
	var items []Item
	for _, b := range bad {
		items = append(items, Item{Raw: b, Source: "neg"})
	}
	// One valid item in the same batch must still be ingested.
	items = append(items, Item{Raw: "8.8.8.8", Source: "neg"})
	results, err := st.Ingest(items)
	if err != nil {
		t.Fatal(err)
	}
	for i, res := range results[:len(bad)] {
		if res.Status != StatusRejected {
			t.Errorf("bad input %q: status %v, want StatusRejected", bad[i], res.Status)
		}
		if res.Reason == "" {
			t.Errorf("bad input %q: empty reject reason", bad[i])
		}
	}
	if results[len(bad)].Status != StatusCreated {
		t.Errorf("valid item after rejects: status %v, want StatusCreated", results[len(bad)].Status)
	}
	if len(st.Records()) != 1 {
		t.Fatalf("rejected inputs leaked into store: %+v", st.Records())
	}
}

func TestDefangRoundTrip(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	items := []Item{
		{Raw: testHash, Source: "rt"},
		{Raw: "2001:db8::1", Source: "rt"},
		{Raw: "192.0.2.1", Source: "rt"},
		{Raw: "xn--bcher-kva.de", Source: "rt"},
	}
	if _, err := st.Ingest(items); err != nil {
		t.Fatal(err)
	}
	for _, rec := range st.Records() {
		defanged, err := st.Defang(rec.ID)
		if err != nil {
			t.Fatal(err)
		}
		nr := Normalize(defanged)
		if !nr.OK {
			t.Errorf("Defang output %q rejected: %s", defanged, nr.Reason)
			continue
		}
		if nr.Kind != rec.Kind || nr.Normalized != rec.Normalized {
			t.Errorf("round trip of %q (%q): got %v/%q, want %v/%q",
				rec.Normalized, defanged, nr.Kind, nr.Normalized, rec.Kind, rec.Normalized)
		}
	}
	if _, err := st.Defang("ioc-999999"); err == nil {
		t.Error("Defang with unknown id: expected error")
	}
}

func TestBatchLimit(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	items := make([]Item, MaxBatch+1)
	for i := range items {
		items[i] = Item{Raw: fmt.Sprintf("10.0.%d.%d", i/256, i%256), Source: "bulk"}
	}
	if _, err := st.Ingest(items); err != ErrTooManyItems {
		t.Fatalf("oversize batch: err %v, want ErrTooManyItems", err)
	}
	if len(st.Records()) != 0 {
		t.Fatalf("oversize batch partially ingested: %+v", st.Records())
	}
	if _, err := st.Ingest(items[:MaxBatch]); err != nil {
		t.Fatalf("exact-limit batch rejected: %v", err)
	}
	if len(st.Records()) != MaxBatch {
		t.Fatalf("got %d records, want %d", len(st.Records()), MaxBatch)
	}
}
