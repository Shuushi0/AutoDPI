package hoststate

import (
	"fmt"
	"sync"
	"testing"
)

func TestThirdDirectOpensTheHost(t *testing.T) {
	c := New()
	for i := 1; i <= 2; i++ {
		if c.Direct("a.example.com") || c.Light("a.example.com") {
			t.Fatalf("open after %d direct connections", i)
		}
	}
	if !c.Direct("a.example.com") || !c.Light("a.example.com") {
		t.Fatal("not open after the third")
	}
	if c.Direct("a.example.com") {
		t.Fatal("promoted twice")
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d", c.Len())
	}
}

func TestOnlyTheExactNameIsOpen(t *testing.T) {
	c := New()
	for i := 0; i < 5; i++ {
		c.Direct("www.example.com")
	}
	if c.Light("example.com") || c.Light("cdn.example.com") || c.Light("WWW.example.com") {
		t.Fatal("openness leaked to another name")
	}
}

func TestFailedResetsTheCount(t *testing.T) {
	c := New()
	c.Direct("a.example.com")
	c.Direct("a.example.com")
	if c.Failed("a.example.com") {
		t.Fatal("a name that was not open reported as open")
	}
	if c.Direct("a.example.com") {
		t.Fatal("the count survived a failure")
	}
	c.Direct("a.example.com")
	if !c.Direct("a.example.com") { // 3 again
		t.Fatal("never promoted again")
	}
	if !c.Failed("a.example.com") || c.Light("a.example.com") {
		t.Fatal("failure did not close an open name")
	}
	if c.Failed("a.example.com") {
		t.Fatal("second failure still reported open")
	}
}

func TestResetReturnsOpenCount(t *testing.T) {
	c := New()
	for i := 0; i < 3; i++ {
		c.Direct("open.example.com")
	}
	c.Direct("warming.example.com")
	if n := c.Reset(); n != 1 {
		t.Fatalf("Reset = %d, want 1 (only open names count)", n)
	}
	if c.Light("open.example.com") || c.Len() != 0 {
		t.Fatal("not empty after Reset")
	}
}

func TestBoundedByTwoGenerations(t *testing.T) {
	c := New()
	for i := 0; i < 3*Limit; i++ {
		h := fmt.Sprintf("h%d.example.com", i)
		for j := 0; j < Promote; j++ {
			c.Direct(h)
		}
	}
	if n := c.Len(); n > 2*Limit {
		t.Fatalf("%d open names held, bound is %d", n, 2*Limit)
	}
	// The newest names survive, the oldest are forgotten.
	if !c.Light(fmt.Sprintf("h%d.example.com", 3*Limit-1)) {
		t.Fatal("newest name forgotten")
	}
	if c.Light("h0.example.com") {
		t.Fatal("oldest name kept past the bound")
	}
}

// A name that is only in the older generation survives, and using it moves it
// to the current one.
func TestOlderGenerationIsStillAnswered(t *testing.T) {
	c := New()
	for j := 0; j < Promote; j++ {
		c.Direct("old.example.com")
	}
	for i := 0; i < Limit; i++ { // fill the current generation, forcing a rotation
		c.Direct(fmt.Sprintf("x%d.example.com", i))
	}
	c.Direct("trigger.example.com")
	if !c.Light("old.example.com") {
		t.Fatal("name lost at the first rotation")
	}
	c.Direct("old.example.com") // used again: carried into the current generation
	if c.Len() < 1 {
		t.Fatal("Len lost it")
	}
}

func TestConcurrentUse(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				h := fmt.Sprintf("h%d.example.com", i%50)
				switch (i + g) % 4 {
				case 0, 1:
					c.Direct(h)
				case 2:
					c.Light(h)
				case 3:
					c.Failed(h)
				}
				if i%500 == 0 {
					c.Len()
				}
			}
		}(g)
	}
	wg.Wait()
}

func BenchmarkLight(b *testing.B) {
	c := New()
	for i := 0; i < Promote; i++ {
		c.Direct("www.example.com")
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Light("www.example.com")
		}
	})
}
