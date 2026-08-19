package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// The menu bar mark.
//
// Drawn here rather than embedded, for the same reason the application icon is
// drawn: a mark that is code can have states, and this one has two. It is a
// template image — macOS ignores the colour and keeps the alpha, so the shape
// follows the menu bar between light and dark and between active and inactive
// without three files that have to be kept in step.

// trayIcon renders the mark at the size the bar asks for.
//
// solid is the mesh working. Hollow — the same triangle as an outline — is
// anything else: the shape stays recognisable while saying, without colour,
// that it is not the state somebody wants.
func trayIcon(solid bool) []byte {
	// 44 pixels is a 22-point icon on a retina bar. macOS scales it down on the
	// others, which is the direction that survives.
	const px = 44
	img := image.NewNRGBA(image.Rect(0, 0, px, px))

	c := pt{px / 2, px / 2}
	r := px * 0.30
	nodes := []pt{
		{c.x, c.y - r},
		{c.x + r*0.866, c.y + r*0.5},
		{c.x - r*0.866, c.y + r*0.5},
	}
	const (
		node = 4.0
		link = 1.3
		ring = 1.3
	)

	for y := range px {
		for x := range px {
			p := pt{float64(x) + 0.5, float64(y) + 0.5}

			a := 0.0
			for i := range nodes {
				for j := i + 1; j < len(nodes); j++ {
					a = max(a, 0.75*coverage(segment(p, nodes[i], nodes[j])-link))
				}
			}
			for _, n := range nodes {
				d := hypot(p, n)
				if solid {
					a = max(a, coverage(d-node))
				} else {
					// An annulus: the distance to the circle's edge rather than
					// to its middle, which is a ring of the given thickness.
					a = max(a, coverage(math.Abs(d-node+ring/2)-ring/2))
				}
			}
			if solid {
				a = max(a, coverage(hypot(p, c)-node*1.15))
			} else {
				a = max(a, coverage(math.Abs(hypot(p, c)-node*1.15+ring/2)-ring/2))
			}

			// Black with the coverage as alpha. The colour is thrown away by
			// the system; only this alpha survives into the bar.
			img.SetNRGBA(x, y, color.NRGBA{A: uint8(math.Round(clamp01(a) * 255))})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		// Encoding an in-memory image cannot fail for any reason worth
		// handling here; an empty icon is a missing icon, not a crash.
		return nil
	}
	return buf.Bytes()
}

type pt struct{ x, y float64 }

func hypot(a, b pt) float64 { return math.Hypot(a.x-b.x, a.y-b.y) }

func segment(p, a, b pt) float64 {
	vx, vy := b.x-a.x, b.y-a.y
	wx, wy := p.x-a.x, p.y-a.y
	t := clamp01((wx*vx + wy*vy) / (vx*vx + vy*vy))
	return math.Hypot(wx-t*vx, wy-t*vy)
}

// coverage turns a distance into how much of a pixel the shape covers.
func coverage(d float64) float64 { return clamp01(0.5 - d) }

func clamp01(v float64) float64 { return math.Min(1, math.Max(0, v)) }
