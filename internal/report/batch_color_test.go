package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBatchColorAppliesOnlyToStatusColumn(t *testing.T) {
	future := fixedReport()
	future.Leaf.NotYetValid = true
	rows := []BatchRow{
		{Host: "VALID", Report: fixedReport()},
		{Host: "ERROR", Err: "ERROR during lookup"},
		{Host: "m\u00fcnchen.example", Report: future},
	}
	var plain, colored bytes.Buffer
	if err := WriteBatchTable(&plain, rows, false, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteBatchTable(&colored, rows, true, false); err != nil {
		t.Fatal(err)
	}
	if stripANSI(colored.String()) != plain.String() {
		t.Fatalf("color changed the table layout:\n%s", colored.String())
	}
	lines := strings.Split(strings.TrimSuffix(colored.String(), "\n"), "\n")
	statusColumn := strings.Index(lines[0], "STATUS")
	for _, line := range lines[1:] {
		firstEscape := strings.Index(line, "\x1b[")
		if firstEscape < 0 || utf8.RuneCountInString(line[:firstEscape]) != statusColumn {
			t.Errorf("expected color at STATUS column %d, got line %q", statusColumn, line)
		}
		if strings.Count(line, colorReset) != 1 {
			t.Errorf("expected exactly one colored cell, got %q", line)
		}
	}
}
