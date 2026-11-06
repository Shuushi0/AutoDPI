package hoststate

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func deadWithClock(ttl time.Duration, limit int) (*Dead, *time.Time) {
	t := time.Unix(1000, 0)
	d := NewDead(ttl, limit)
	d.now = func() time.Time { return t }
	return d, &t
}

func TestDeadExpiresAfterTTL(t *testing.T) {
	d, now := deadWithClock(10*time.Minute, 8)
	k := DeadKey{"a.example", "203.0.113.1:443"}
	if d.Has(k) {
		t.Fatal("empty cache has a key")
	}
	d.Add(k)
	if !d.Has(k) || d.Len() != 1 {
		t.Fatal("added key not remembered")
	}
	if d.Has(DeadKey{"a.example", "203.0.113.2:443"}) || d.Has(DeadKey{"b.example", "203.0.113.1:443"}) {
		t.Fatal("another address or name matched")
	}
	*now = now.Add(9*time.Minute + 59*time.Second)
	if !d.Has(k) {
		t.Fatal("expired early")
	}
	*now = now.Add(2 * time.Second)
	if d.Has(k) || d.Len() != 0 {
		t.Fatal("still remembered after the ttl")
	}
}

func TestDeadAddRenewsAndForgetRemoves(t *testing.T) {
	d, now := deadWithClock(time.Minute, 8)
	k := DeadKey{Dest: "203.0.113.1:443"} // no SNI: the address alone
	d.Add(k)
	*now = now.Add(50 * time.Second)
	d.Add(k)
	*now = now.Add(50 * time.Second)
	if !d.Has(k) {
		t.Fatal("Add did not renew")
	}
	d.Forget(k)
	if d.Has(k) {
		t.Fatal("Forget left the key")
	}
}

func TestDeadIsBounded(t *testing.T) {
	d, _ := deadWithClock(time.Hour, 4)
	for i := 0; i < 1000; i++ {
		d.Add(DeadKey{Host: fmt.Sprint("h", i), Dest: "203.0.113.1:443"})
	}
	if n := d.Len(); n > 8 {
		t.Fatalf("%d entries with limit 4 per generation", n)
	}
	if !d.Has(DeadKey{Host: "h999", Dest: "203.0.113.1:443"}) {
		t.Fatal("newest entry lost")
	}
	if d.Has(DeadKey{Host: "h0", Dest: "203.0.113.1:443"}) {
		t.Fatal("oldest entry kept")
	}
	if got := d.Reset(); got == 0 || d.Len() != 0 {
		t.Fatalf("Reset returned %d, len %d", got, d.Len())
	}
}

func TestDeadConcurrent(t *testing.T) {
	d := NewDead(time.Minute, 64)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				k := DeadKey{Host: fmt.Sprint("h", (g*31+i)%200), Dest: "x:443"}
				d.Add(k)
				d.Has(k)
				if i%7 == 0 {
					d.Forget(k)
				}
				d.Len()
			}
		}(g)
	}
	wg.Wait()
}
