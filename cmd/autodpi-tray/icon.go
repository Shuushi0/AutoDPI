package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"math"
)

// The tray icon is the shield of the web page's logo, filled with the state's
// color and marked with a glyph, like the macOS menu bar icon. It is drawn
// here rather than shipped as files: one shape, six colors, three sizes.

type glyph int

const (
	glyphCheck glyph = iota
	glyphHalf
	glyphPause
	glyphBang
	glyphSlash
)

type look struct {
	fill  color.NRGBA
	glyph glyph
}

// looks follows the macOS app's AppState colors and symbols.
var looks = map[string]look{
	"active":      {color.NRGBA{48, 199, 89, 255}, glyphCheck},
	"starting":    {color.NRGBA{64, 140, 250, 255}, glyphHalf},
	"standby":     {color.NRGBA{250, 176, 26, 255}, glyphHalf},
	"paused":      {color.NRGBA{140, 148, 168, 255}, glyphPause},
	"offline":     {color.NRGBA{140, 148, 168, 255}, glyphSlash},
	"error":       {color.NRGBA{242, 69, 69, 255}, glyphBang},
	"unreachable": {color.NRGBA{140, 148, 168, 255}, glyphSlash},
}

// iconSizes are the images in each .ico: Windows loads the tray icon at the
// system icon size, 32 px at 100 % scaling and 48/64 px above; the 16 px
// image serves the small-icon size when the shell asks for it directly.
var iconSizes = []int{16, 32, 48, 64}

// trayIcon returns the .ico for a daemon state ("unreachable" when the
// service does not answer).
func trayIcon(state string) []byte {
	l, ok := looks[state]
	if !ok {
		l = looks["unreachable"]
	}
	imgs := make([]*image.NRGBA, len(iconSizes))
	for i, n := range iconSizes {
		imgs[i] = drawShield(n, l)
	}
	return encodeICO(imgs)
}

// shield is the logo's outline in its 24-unit box: a straight top, sides
// down to y 11.4, and two curves meeting at the point.
var shield = func() [][2]float64 {
	pts := [][2]float64{{12, 2.5}, {20, 5.8}, {20, 11.4}}
	pts = append(pts, cubic([2]float64{20, 11.4}, [2]float64{20, 16.3}, [2]float64{16.7, 20}, [2]float64{12, 21.5})...)
	pts = append(pts, cubic([2]float64{12, 21.5}, [2]float64{7.3, 20}, [2]float64{4, 16.3}, [2]float64{4, 11.4})...)
	return append(pts, [2]float64{4, 5.8})
}()

func cubic(p0, p1, p2, p3 [2]float64) [][2]float64 {
	var out [][2]float64
	for i := 1; i <= 12; i++ {
		t := float64(i) / 12
		u := 1 - t
		a, b, c, d := u*u*u, 3*u*u*t, 3*u*t*t, t*t*t
		out = append(out, [2]float64{a*p0[0] + b*p1[0] + c*p2[0] + d*p3[0], a*p0[1] + b*p1[1] + c*p2[1] + d*p3[1]})
	}
	return out
}

func inPolygon(x, y float64, poly [][2]float64) bool {
	in := false
	for i, j := 0, len(poly)-1; i < len(poly); j, i = i, i+1 {
		xi, yi, xj, yj := poly[i][0], poly[i][1], poly[j][0], poly[j][1]
		if (yi > y) != (yj > y) && x < (xj-xi)*(y-yi)/(yj-yi)+xi {
			in = !in
		}
	}
	return in
}

// segDist is the distance from (x, y) to the segment a-b.
func segDist(x, y float64, a, b [2]float64) float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	t := ((x-a[0])*dx + (y-a[1])*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	px, py := a[0]+t*dx-x, a[1]+t*dy-y
	return math.Hypot(px, py)
}

// mark reports whether (x, y), in logo units, belongs to the white glyph.
// The half shield is not a glyph but a lighter tint; drawShield paints it.
func mark(g glyph, x, y float64) bool {
	// The strokes are a little heavier than the page's 24-unit logo: the
	// shell scales the 32 px image down to 16 px in the notification area.
	switch g {
	case glyphCheck:
		return segDist(x, y, [2]float64{8.4, 12.2}, [2]float64{10.9, 14.7}) < 1.5 ||
			segDist(x, y, [2]float64{10.9, 14.7}, [2]float64{15.6, 9.6}) < 1.5
	case glyphPause:
		return y > 8.3 && y < 15.7 && ((x > 8.7 && x < 11) || (x > 13 && x < 15.3))
	case glyphBang:
		return (x > 10.8 && x < 13.2 && y > 6.6 && y < 13.4) || math.Hypot(x-12, y-16.3) < 1.4
	case glyphSlash:
		return segDist(x, y, [2]float64{7, 6.5}, [2]float64{17, 17.5}) < 1.4
	}
	return false
}

// shrink moves every point of poly toward the shield's center by d units.
func shrink(poly [][2]float64, d float64) [][2]float64 {
	out := make([][2]float64, len(poly))
	for i, p := range poly {
		vx, vy := p[0]-12, p[1]-12
		l := math.Hypot(vx, vy)
		out[i] = [2]float64{p[0] - vx/l*d, p[1] - vy/l*d}
	}
	return out
}

var (
	halfInner = shrink(shield, 1.6)
	rimInner  = shrink(shield, 0.8) // inside this the body is flat; the rim outside is a shade darker
)

// drawShield renders one size with 4x4 supersampling: the body in the state
// color, lit a little at the top and shaded at the bottom like the macOS
// app's badge, with a darker rim so it stays legible on a light taskbar.
func drawShield(n int, l look) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	const ss = 4
	scale := 24 / float64(n)
	for py := 0; py < n; py++ {
		for px := 0; px < n; px++ {
			var cover, white, rim float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+.5)/ss) * scale
					y := (float64(py) + (float64(sy)+.5)/ss) * scale
					if !inPolygon(x, y, shield) {
						continue
					}
					cover++
					if !inPolygon(x, y, rimInner) {
						rim++
					}
					if l.glyph == glyphHalf { // the right half lightened, as in shield.lefthalf.filled
						if x > 12.6 && inPolygon(x, y, halfInner) {
							white += .55
						}
					} else if mark(l.glyph, x, y) {
						white++
					}
				}
			}
			if cover == 0 {
				continue
			}
			w := white / cover
			// Vertical shading: +8 % light at the top to -10 % at the bottom,
			// and the rim 22 % darker.
			shade := 1.08 - 0.18*(float64(py)+.5)/float64(n) - 0.22*rim/cover
			mix := func(c uint8) uint8 {
				v := float64(c)*shade*(1-w) + 255*w
				return uint8(math.Max(0, math.Min(255, v)) + .5)
			}
			img.SetNRGBA(px, py, color.NRGBA{mix(l.fill.R), mix(l.fill.G), mix(l.fill.B), uint8(255 * cover / (ss * ss))})
		}
	}
	return img
}

// encodeICO writes the images as 32-bit DIB entries (BITMAPINFOHEADER,
// bottom-up BGRA, then the 1-bit AND mask), the form every Windows version's
// LoadImage reads.
func encodeICO(imgs []*image.NRGBA) []byte {
	var hdr, body bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&hdr, le, [3]uint16{0, 1, uint16(len(imgs))})
	offset := 6 + 16*len(imgs)
	for _, img := range imgs {
		n := img.Rect.Dx()
		maskRow := (n + 31) / 32 * 4
		size := 40 + n*n*4 + maskRow*n
		dim := uint8(n)
		if n >= 256 {
			dim = 0
		}
		_ = binary.Write(&hdr, le, struct {
			W, H, Colors, Reserved uint8
			Planes, BPP            uint16
			Size, Offset           uint32
		}{dim, dim, 0, 0, 1, 32, uint32(size), uint32(offset)})
		offset += size

		_ = binary.Write(&body, le, struct {
			Size                     uint32
			W, H                     int32
			Planes, BPP              uint16
			Compression, ImageSize   uint32
			XPPM, YPPM, Used, Import int32
		}{40, int32(n), int32(2 * n), 1, 32, 0, uint32(n * n * 4), 0, 0, 0, 0})
		for y := n - 1; y >= 0; y-- {
			for x := 0; x < n; x++ {
				c := img.NRGBAAt(x, y)
				body.Write([]byte{c.B, c.G, c.R, c.A})
			}
		}
		// The alpha channel decides; an all-zero AND mask draws every pixel.
		body.Write(make([]byte, maskRow*n))
	}
	return append(hdr.Bytes(), body.Bytes()...)
}
