package portrange

import (
	"testing"
)

func TestParseAndContains(t *testing.T) {
	cases := []struct {
		in       string
		contains []int
		excludes []int
	}{
		{"all", []int{0, 1, 5000, 65535}, nil},
		{"1-1000", []int{1, 500, 1000}, []int{0, 1001, 65535}},
		{"80,443", []int{80, 443}, []int{79, 81, 442, 444}},
		{"1-5,800-900", []int{1, 3, 5, 800, 900}, []int{0, 6, 799, 901}},
		{"", []int{0, 65535}, nil},
	}
	for _, c := range cases {
		pr, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", c.in, err)
		}
		for _, p := range c.contains {
			if !pr.Contains(p) {
				t.Errorf("Parse(%q).Contains(%d) = false, want true", c.in, p)
			}
		}
		for _, p := range c.excludes {
			if pr.Contains(p) {
				t.Errorf("Parse(%q).Contains(%d) = true, want false", c.in, p)
			}
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"abc", "5-2", "-1", "70000", "80-", "-80"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", in)
		}
	}
}
