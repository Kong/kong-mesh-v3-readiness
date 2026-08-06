package preflight

import "testing"

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in              string
		maj, min, patch int
		ok              bool
	}{
		{"2.14.0", 2, 14, 0, true},
		{"2.9.0", 2, 9, 0, true},
		{"v2.14.1", 2, 14, 1, true},
		{"2.14.7-rc1", 2, 14, 7, true},
		{"2.14.0+build.5", 2, 14, 0, true},
		{"3.0.0", 3, 0, 0, true},
		{"2.14", 0, 0, 0, false},
		{"dev", 0, 0, 0, false},
		{"x.y.z", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	}
	for _, c := range cases {
		maj, minor, patch, ok := ParseSemver(c.in)
		if ok != c.ok || (ok && (maj != c.maj || minor != c.min || patch != c.patch)) {
			t.Errorf("ParseSemver(%q) = (%d,%d,%d,%v), want (%d,%d,%d,%v)",
				c.in, maj, minor, patch, ok, c.maj, c.min, c.patch, c.ok)
		}
	}
}

func TestBehind(t *testing.T) {
	// latest = 2.14.5
	const lMin, lPatch = 14, 5
	cases := []struct {
		maj, min, patch int
		want            bool
	}{
		{2, 14, 4, true},  // older patch
		{2, 14, 5, false}, // current
		{2, 14, 6, false}, // ahead patch
		{2, 13, 9, true},  // older minor
		{2, 11, 0, true},  // much older minor
		{2, 15, 0, false}, // newer minor
		{3, 0, 0, false},  // 3.x is beyond the 2.x upgrade source
		{1, 8, 0, true},   // 1.x must reach 2.14 first
		{0, 0, 0, true},   // pre-2.x / dev build is not a valid upgrade source
	}
	for _, c := range cases {
		if got := behind(c.maj, c.min, c.patch, lMin, lPatch); got != c.want {
			t.Errorf("behind(%d.%d.%d, latest 2.%d.%d) = %v, want %v",
				c.maj, c.min, c.patch, lMin, lPatch, got, c.want)
		}
	}
}
