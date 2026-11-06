package main

import (
	"encoding/binary"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestTrayIconIsAValidICO(t *testing.T) {
	for state := range looks {
		b := trayIcon(state)
		le := binary.LittleEndian
		if le.Uint16(b[0:]) != 0 || le.Uint16(b[2:]) != 1 || int(le.Uint16(b[4:])) != len(iconSizes) {
			t.Fatalf("%s: bad ICO header % x", state, b[:6])
		}
		for i, n := range iconSizes {
			e := b[6+16*i:]
			size, off := int(le.Uint32(e[8:])), int(le.Uint32(e[12:]))
			if int(e[0]) != n || int(le.Uint16(e[6:])) != 32 || off+size > len(b) {
				t.Fatalf("%s: entry %d: %d px, %d bpp, %d+%d of %d", state, i, e[0], le.Uint16(e[6:]), off, size, len(b))
			}
			if want := 40 + n*n*4 + (n+31)/32*4*n; size != want {
				t.Fatalf("%s %dpx: size %d, want %d", state, n, size, want)
			}
			if h := int32(le.Uint32(b[off+8:])); h != int32(2*n) {
				t.Fatalf("%s %dpx: DIB height %d, want %d", state, n, h, 2*n)
			}
		}
	}
}

func TestShieldShape(t *testing.T) {
	img := drawShield(32, looks["active"])
	// Corners stay clear, the middle of the body is the state color, the
	// check mark is white.
	if a := img.NRGBAAt(0, 0).A; a != 0 {
		t.Errorf("corner alpha %d", a)
	}
	if c := img.NRGBAAt(16, 26); c.A != 255 || c.G < 150 || c.R > 100 {
		t.Errorf("body pixel %v", c)
	}
	if c := img.NRGBAAt(15, 19); c.R < 200 || c.G < 200 || c.B < 200 {
		t.Errorf("check pixel %v", c)
	}
	// Leave a preview for a look by hand: go test -run TestShieldShape -v
	if dir := os.Getenv("TRAY_ICON_PREVIEW"); dir != "" {
		for state, l := range looks {
			f, _ := os.Create(filepath.Join(dir, state+".png"))
			_ = png.Encode(f, drawShield(64, l))
			f.Close()
		}
	}
}
