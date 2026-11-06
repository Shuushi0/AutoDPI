//go:build darwin

package netx

import (
	"encoding/binary"
	"testing"
)

func TestRelevantMessages(t *testing.T) {
	msg := func(typ byte, flags uint32) []byte {
		b := make([]byte, 16)
		b[3] = typ
		binary.NativeEndian.PutUint32(b[8:], flags)
		return b
	}
	cases := []struct {
		name string
		m    []byte
		want bool
	}{
		{"route add", msg(rtmAdd, 0x1), true},
		{"route delete", msg(rtmDelete, 0x1|rtfHost), true},
		{"arp entry added", msg(rtmAdd, rtfLLInfo|rtfHost), false},
		{"cloned host route", msg(rtmDelete, rtfWasCloned|rtfHost), false},
		{"interface info", msg(rtmIfInfo, 0), true},
		{"address added", msg(rtmNewAddr, 0), true},
		{"our own route get", msg(0x4, 0x1), false},
		{"miss", msg(0x7, 0), false},
		{"short", []byte{1, 2, 3}, false},
	}
	for _, c := range cases {
		if got := relevant(c.m); got != c.want {
			t.Errorf("%s: relevant = %v, want %v", c.name, got, c.want)
		}
	}
}
