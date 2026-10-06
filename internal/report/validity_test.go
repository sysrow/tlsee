package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestBatchNotYetValid(t *testing.T) {
	for _, color := range []bool{false, true} {
		for _, quiet := range []bool{false, true} {
			t.Run(fmt.Sprintf("color=%t/quiet=%t", color, quiet), func(t *testing.T) {
				r := fixedReport()
				r.Leaf.NotYetValid = true
				r.ChainTrusted = false
				var out bytes.Buffer
				if err := WriteBatchTable(&out, []BatchRow{{Host: "future.example", Report: r}}, color, quiet); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(stripANSI(out.String()), "NOT YET VALID") || strings.Contains(out.String(), "EXPIRED") {
					t.Fatalf("future certificate has incorrect status:\n%s", out.String())
				}
				if color && !strings.Contains(out.String(), colorRed+"NOT YET VALID"+colorReset) {
					t.Fatalf("future certificate status is not red:\n%q", out.String())
				}
			})
		}
	}
}

func TestTextExpiryWithinOneDay(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired=%t", expired), func(t *testing.T) {
			r := fixedReport()
			// Whole-day truncation produces zero on both sides of NotAfter.
			r.Leaf.DaysRemaining = 0
			r.Leaf.Expired = expired
			var out bytes.Buffer
			if err := WriteText(&out, r, false); err != nil {
				t.Fatal(err)
			}
			want := "expires today"
			if expired {
				want = "expired less than a day ago"
			}
			if !strings.Contains(out.String(), "("+want+")") {
				t.Fatalf("expiry phrase should be %q:\n%s", want, out.String())
			}
		})
	}
}
