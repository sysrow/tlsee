package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/sysrow/tlsee/tlsscan"
)

func TestTextReportsUnprobedSANs(t *testing.T) {
	for _, completed := range []bool{false, true} {
		for _, color := range []bool{false, true} {
			t.Run(fmt.Sprintf("completed=%t/color=%t", completed, color), func(t *testing.T) {
				r := fixedReport()
				r.SANsNotProbed = 3
				if completed {
					r.SANChecks = []tlsscan.SANCheck{{Name: "*.example.com", Wildcard: true}}
				}
				var out bytes.Buffer
				if err := WriteText(&out, r, color); err != nil {
					t.Fatal(err)
				}
				plain := stripANSI(out.String())
				if !strings.Contains(plain, "SAN liveness:") || !strings.Contains(plain, "3 SAN names not probed") {
					t.Fatalf("incomplete check is not visible:\n%s", plain)
				}
				if !strings.Contains(plain, "Status: VALID\n") || !r.Healthy() {
					t.Fatalf("skipped advisory changed certificate health:\n%s", plain)
				}
			})
		}
	}
}

func TestBatchReportsUnprobedSANs(t *testing.T) {
	r := fixedReport()
	r.DeadSANs = 1
	r.SANsElsewhere = 2
	r.SANsNotProbed = 3
	rows := []BatchRow{{Host: "example.com", Report: r}}
	var out bytes.Buffer
	if err := WriteBatchTable(&out, rows, false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "1 dead, 2 elsewhere, 3 not probed") {
		t.Fatalf("batch note omitted incomplete checks:\n%s", out.String())
	}
	out.Reset()
	if err := WriteBatchTable(&out, rows, false, true); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("quiet mode emitted a healthy certificate due to advisories:\n%s", out.String())
	}
}
