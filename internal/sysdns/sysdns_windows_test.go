package sysdns

import "testing"

func TestWindowsTakeRelease(t *testing.T) {
	flushes := 0
	m := &Manager{Flush: func() { flushes++ }}
	if m.Holding() {
		t.Fatal("holding before Take")
	}
	if err := m.Take("Wi-Fi"); err != nil || !m.Holding() || flushes != 1 {
		t.Fatalf("take: err=%v holding=%v flushes=%d", err, m.Holding(), flushes)
	}
	if err := m.Release(); err != nil || m.Holding() || flushes != 2 {
		t.Fatalf("release: err=%v holding=%v flushes=%d", err, m.Holding(), flushes)
	}
	if err := m.Release(); err != nil || flushes != 2 {
		t.Fatalf("second release must be a no-op: err=%v flushes=%d", err, flushes)
	}
}
