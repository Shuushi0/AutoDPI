package logx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.log")
	r, err := Open(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	line := strings.Repeat("x", 40) + "\n"
	for i := 0; i < 5; i++ {
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	old, err := os.ReadFile(p + ".1")
	if err != nil || len(old) == 0 {
		t.Fatalf("no rotated generation: %v", err)
	}
	cur, _ := os.ReadFile(p)
	if int64(len(cur)) > 100 || int64(len(old)) > 100 {
		t.Fatalf("files exceed cap: cur=%d old=%d", len(cur), len(old))
	}
}
