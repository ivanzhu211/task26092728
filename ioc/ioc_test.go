package ioc_test

import (
	"path/filepath"
	"testing"

	"ioc"
)

// variant is one raw indicator expected to normalize to the same record.
type variant struct {
	raw    string
	canon  string
	kind   string
	source string
}

// TestIngestNearMisses is scenario 2: plausible look-alikes must all be
// rejected, individually, without poisoning other items in the batch.
func TestIngestNearMisses(t *testing.T) {
	dir := t.TempDir()
	s, err := ioc.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	bad := []string{
		// hash-ish
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678",   // 63 chars
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890", // 65 chars
		"ghij0123456789abcdef0123456789abcdef0123456789abcdef0123456789",    // non-hex
		// ipv4-ish
		"010.1.1.1",
		"1.2.3.256",
		"1.2.3",
		"1.2.3.4.5",
		"1..2.3",
		"1.2.3.04",
		"0x7f.1.1.1",
		// ipv6-ish
		"2001:db8::1%eth0",
		"fe80::1%1",
		"2001:db8::g",
		"2001:db8:1",
		"gggg::1",
		// domain-ish
		"-bad.example.com",
		"bad-.example.com",
		"under_score.example.com",
		"example..com",
		".example.com",
		"example.com..",
		"example.123",
		"a..b",
		"justoneword",
		// structural
		"http://example.com",
		"https://192.0.2.1/x",
		"example.com/path",
		"192.0.2.0/24",
		"2001:db8::/64",
		"192.0.2.1:8080",
		"[2001:db8::1]:443",
		"192 0.2.1",
		"2001: db8::1",
		"",
		"   ",
		"[invalid",
		"1,2,3,4",
	}

	items := []ioc.Item{{Raw: "198.51.100.7", Source: "ok"}}
	for _, b := range bad {
		items = append(items, ioc.Item{Raw: b, Source: "bad"})
	}
	outcomes, err := s.Ingest(items)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if outcomes[0].Kind != ioc.OutcomeCreated {
		t.Fatalf("valid anchor item was not created: %+v", outcomes[0])
	}
	for i, b := range bad {
		o := outcomes[i+1]
		if o.Kind != ioc.OutcomeRejected {
			t.Errorf("bad[%d] %q accepted as %+v", i, b, o)
			continue
		}
		if o.Reason == "" {
			t.Errorf("bad[%d] %q rejected without reason", i, b)
		}
	}
	if s.Len() != 1 {
		t.Fatalf("rejected items leaked into store, len=%d", s.Len())
	}
}

// TestPersistenceAndSources verifies reopen-survival and source merging for
// both existing-record hits and within-batch duplicates.
func TestPersistenceAndSources(t *testing.T) {
	dir := t.TempDir()

	s, err := ioc.Open(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	out, err := s.Ingest([]ioc.Item{
		{Raw: "EXAMPLE.com", Source: "src-a"},
		{Raw: "example[.]com", Source: "src-a"},
		{Raw: "example.com", Source: "src-b"},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if out[0].Kind != ioc.OutcomeCreated ||
		out[1].Kind != ioc.OutcomeDupInBatch || out[1].DupIndex != 0 ||
		out[2].Kind != ioc.OutcomeDupInBatch || out[2].DupIndex != 0 {
		t.Fatalf("unexpected outcomes: %+v", out)
	}

	// Reopen: records survive.
	s2, err := ioc.Open(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	out2, err := s2.Ingest([]ioc.Item{
		{Raw: "example.com", Source: "src-c"},
		{Raw: "example.com", Source: "src-a"},
	})
	if err != nil {
		t.Fatalf("Ingest2: %v", err)
	}
	if out2[0].Kind != ioc.OutcomeExisting || out2[1].Kind != ioc.OutcomeDupInBatch {
		t.Fatalf("unexpected reopen outcomes: %+v", out2)
	}
	if out2[1].DupIndex != 0 {
		t.Fatalf("dup index = %d want 0", out2[1].DupIndex)
	}

	rec, ok := s2.Get("example.com")
	if !ok {
		t.Fatal("record lost after reopen")
	}
	wantSources := map[string]bool{"src-a": true, "src-b": true, "src-c": true}
	if len(rec.Sources) != len(wantSources) {
		t.Fatalf("sources=%v want %d unique merged", rec.Sources, len(wantSources))
	}
	for _, src := range rec.Sources {
		if !wantSources[src] {
			t.Fatalf("unexpected source %q", src)
		}
	}
}

// TestBatchTooLarge verifies the whole batch is rejected past 1000 items.
func TestBatchTooLarge(t *testing.T) {
	s, err := ioc.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	items := make([]ioc.Item, ioc.MaxBatch+1)
	for i := range items {
		items[i] = ioc.Item{Raw: "example.com", Source: "x"}
	}
	if _, err := s.Ingest(items); err != ioc.ErrBatchTooLarge {
		t.Fatalf("err=%v want ErrBatchTooLarge", err)
	}
	if s.Len() != 0 {
		t.Fatalf("oversized batch persisted %d records", s.Len())
	}

	// Exactly MaxBatch items is allowed, even with rejects mixed in.
	edge := make([]ioc.Item, ioc.MaxBatch)
	for i := range edge {
		edge[i] = ioc.Item{Raw: "example.com", Source: "x"}
	}
	out, err := s.Ingest(edge)
	if err != nil {
		t.Fatalf("max-size batch: %v", err)
	}
	if len(out) != ioc.MaxBatch || out[0].Kind != ioc.OutcomeCreated {
		t.Fatalf("max-size batch mishandled")
	}
}

// TestDefangRoundTrip is scenario 3: Defang output re-normalized must yield
// the record's own type and canonical form.
func TestDefangRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := ioc.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	values := []string{
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"192.0.2.1",
		"2001:db8::1",
		"fe80::200:5aee:feaa:20a2",
		"::1",
		"::",
		"2001:db8:1:2:3:4:5:6",
		"example.com",
		"xn--bcher-kva.de",
		"a.b-c.example",
	}
	var items []ioc.Item
	for _, v := range values {
		items = append(items, ioc.Item{Raw: v, Source: "rt"})
	}
	outcomes, err := s.Ingest(items)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	wantDefang := map[string]string{
		"192.0.2.1":                "192[.]0[.]2[.]1",
		"2001:db8::1":              "2001[:]db8[:][:]1",
		"fe80::200:5aee:feaa:20a2": "fe80[:][:]200[:]5aee[:]feaa[:]20a2",
		"::1":                      "[:][:]1",
		"::":                       "[:][:]",
		"2001:db8:1:2:3:4:5:6":     "2001[:]db8[:]1[:]2[:]3[:]4[:]5[:]6",
		"example.com":              "example[.]com",
		"xn--bcher-kva.de":         "xn--bcher-kva[.]de",
		"a.b-c.example":            "a[.]b-c[.]example",
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	for i, o := range outcomes {
		if o.Kind != ioc.OutcomeCreated {
			t.Fatalf("values[%d] not created: %+v", i, o)
		}
		defanged, err := s.Defang(o.ID)
		if err != nil {
			t.Fatalf("Defang(%q): %v", o.ID, err)
		}
		if want, ok := wantDefang[o.ID]; ok && defanged != want {
			t.Errorf("Defang(%q)=%q want %q", o.ID, defanged, want)
		}
		kind, canon, reason := ioc.Normalize(defanged)
		if reason != "" {
			t.Fatalf("Normalize(Defang(%q)) rejected: %s", o.ID, reason)
		}
		rec, _ := s.Get(o.ID)
		if kind != rec.Type || canon != rec.Value {
			t.Fatalf("roundtrip mismatch for %q: got %s %q, want %s %q",
				o.ID, kind, canon, rec.Type, rec.Value)
		}
	}
}

// TestIngestEquivalenceGroups is scenario 1: each class of indicator has a
// set of equivalent variants, all mixed into one batch; every group must
// collapse to exactly one record.
func TestIngestEquivalenceGroups(t *testing.T) {
	dir := t.TempDir()
	s, err := ioc.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	hashUpper := "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	hashLower := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	groups := [][]variant{
		{
			{hashUpper, hashLower, ioc.TypeSHA256, "vt"},
			{" " + hashLower + " ", hashLower, ioc.TypeSHA256, "misp"},
			{hashLower, hashLower, ioc.TypeSHA256, "vt"},
		},
		{
			{"192.0.2.1", "192.0.2.1", ioc.TypeIPv4, "anon"},
			{"192[.]0[.]2[.]1", "192.0.2.1", ioc.TypeIPv4, "blog"},
			{"192(DOT)0(.)2{.}1", "192.0.2.1", ioc.TypeIPv4, "paste"},
		},
		{
			{"2001:db8::1", "2001:db8::1", ioc.TypeIPv6, "c2"},
			{"[2001:db8::1]", "2001:db8::1", ioc.TypeIPv6, "c2"},
			{"2001[:]db8[:][:]1", "2001:db8::1", ioc.TypeIPv6, "c2"},
			{"2001:DB8:0:0:0:0:0:1", "2001:db8::1", ioc.TypeIPv6, "c2"},
			{"2001:0db8::1", "2001:db8::1", ioc.TypeIPv6, "c2"},
		},
		{
			// IPv4-mapped IPv6 shares the IPv4 record, across forms.
			{"::ffff:192.0.2.1", "192.0.2.1", ioc.TypeIPv4, "mapped"},
			{"::ffff:c000:201", "192.0.2.1", ioc.TypeIPv4, "mapped"},
		},
		{
			{"Bücher.DE.", "xn--bcher-kva.de", ioc.TypeDomain, "phish"},
			{"xn--bcher-kva.de", "xn--bcher-kva.de", ioc.TypeDomain, "phish"},
			{"BÜCHER(dot)DE", "xn--bcher-kva.de", ioc.TypeDomain, "phish"},
		},
		{
			{"example.com", "example.com", ioc.TypeDomain, "feed-a"},
			{"EXAMPLE.COM.", "example.com", ioc.TypeDomain, "feed-b"},
			{"example[.]com", "example.com", ioc.TypeDomain, "feed-c"},
		},
	}

	var items []ioc.Item
	for _, g := range groups {
		for _, v := range g {
			items = append(items, ioc.Item{Raw: v.raw, Source: v.source})
		}
	}

	outcomes, err := s.Ingest(items)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(outcomes) != len(items) {
		t.Fatalf("got %d outcomes, want %d", len(outcomes), len(items))
	}

	// Exactly one Created per distinct canonical value (the IPv4-mapped
	// group merges into the plain IPv4 group); everything else duplicates
	// the first occurrence of that value in the batch.
	groupOffset := 0
	firstSeen := map[string]int{}
	createdIDs := map[string]bool{}
	for gi, g := range groups {
		for j, v := range g {
			o := outcomes[groupOffset+j]
			if o.Kind != ioc.OutcomeCreated && o.Kind != ioc.OutcomeDupInBatch {
				t.Fatalf("group %d item %d unexpected outcome %+v", gi, j, o)
			}
			if o.ID != v.canon {
				t.Fatalf("group %d item %d id=%q want %q", gi, j, o.ID, v.canon)
			}
			if o.Kind == ioc.OutcomeCreated {
				if createdIDs[o.ID] {
					t.Fatalf("group %d created a second record for %q", gi, o.ID)
				}
				createdIDs[o.ID] = true
			} else {
				if want, ok := firstSeen[o.ID]; !ok || o.DupIndex != want {
					t.Fatalf("group %d item %d DupIndex=%d want %d", gi, j, o.DupIndex, want)
				}
			}
			if _, ok := firstSeen[o.ID]; !ok {
				firstSeen[o.ID] = groupOffset + j
			}
		}
		rec, ok := s.Get(g[0].canon)
		if !ok {
			t.Fatalf("group %d record %q missing", gi, g[0].canon)
		}
		if rec.Type != g[0].kind {
			t.Fatalf("group %d type=%s want %s", gi, rec.Type, g[0].kind)
		}
		groupOffset += len(g)
	}

	wantRecords := 5 // one group (IPv4-mapped) merges into the plain IPv4 record
	if got := s.Len(); got != wantRecords {
		t.Fatalf("store has %d records, want %d", got, wantRecords)
	}
}
