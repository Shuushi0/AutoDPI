package daemon

import (
	"testing"
)

func TestMemoReusesAnswerUntilTheRoutesChange(t *testing.T) {
	calls := 0
	m := &memo[int]{fn: func() int { calls++; return calls }}
	// Without notifications the lifetime is short but a back-to-back call is cached.
	if a, b := m.get(), m.get(); a != 1 || b != 1 || calls != 1 {
		t.Fatalf("calls=%d a=%d b=%d, want one call", calls, a, b)
	}
	m.gen-- // as if the route-change generation had moved since
	if v := m.get(); v != 2 {
		t.Fatalf("a route change must refresh the answer, got %d", v)
	}
}
