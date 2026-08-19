// Command icon draws the application icon.
//
// Drawn rather than kept as a binary blob so that the mark can be changed by
// editing the shape instead of by finding whoever has the original file. It is
// a hundred lines of arithmetic and it never goes missing.
//
// Everything is a signed distance: a shape says how far a point is from its
// edge, and the coverage of a pixel follows from that distance. That is what
// gives clean edges at every size without an image library, and it is why the
// mark can be described as four points and the lines between them.
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

const (
	// size is what macOS asks for. Everything else is a fraction of it, so the
	// mark is identical at 16 pixels and at 1024.
	size = 1024
	// aa is how far outside its edge a shape still colours a pixel. One pixel
	// of softness, which is what makes a diagonal line look like a line.
	aa = 1.0
)

type rgb struct{ r, g, b float64 }

var (
	// The panel's palette, so the icon belongs to the same product.
	deep   = rgb{0.027, 0.035, 0.055} // #07090e, a shade lifted
	lift   = rgb{0.055, 0.078, 0.125}
	accent = rgb{0.204, 0.827, 0.600} // #34d399
	pale   = rgb{0.902, 0.937, 0.980} // #e6ebf3
)

func main() {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	// The mesh: three machines around one, and a line between every pair. Not
	// a star — a star would be a hub, and the whole point of this program is
	// that there is not one.
	c := vec{size / 2, size / 2}
	r := size * 0.185
	nodes := []vec{
		{c.x, c.y - r},
		{c.x + r*0.866, c.y + r*0.5},
		{c.x - r*0.866, c.y + r*0.5},
	}

	for y := range size {
		for x := range size {
			p := vec{float64(x) + 0.5, float64(y) + 0.5}

			// Outside the bundle's rounded square is transparent: macOS draws
			// the shadow and the mask around whatever is given to it.
			// 0.412 of the canvas is the half-width Apple's icon grid gives a
			// rounded square, and the margin around it is not wasted space:
			// it is where the system draws the shadow and where the Dock's
			// hover ring sits.
			d := squircle(p, size*0.5, size*0.5, size*0.412)
			if d > aa {
				continue
			}

			// A quiet vertical gradient, so a large icon is not a flat slab.
			col := mix(lift, deep, float64(y)/size)

			// The links first, so the nodes sit on top of them.
			for i := range nodes {
				for j := i + 1; j < len(nodes); j++ {
					col = over(col, accent, 0.6*cover(segment(p, nodes[i], nodes[j])-size*0.0115))
				}
			}
			for _, n := range nodes {
				col = over(col, accent, cover(dist(p, n)-size*0.05))
			}
			// The one in the middle is this machine, and it is the brightest
			// thing in the mark for the same reason it is what somebody opens
			// the window to find out about.
			col = over(col, pale, cover(dist(p, c)-size*0.068))

			a := cover(d)
			img.SetNRGBA(x, y, color.NRGBA{
				R: quant(col.r), G: quant(col.g), B: quant(col.b), A: quant(a),
			})
		}
	}

	f, err := os.Create("build/appicon.png")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println("wrote build/appicon.png")
}

type vec struct{ x, y float64 }

// cover turns a distance into how much of a pixel a shape covers: fully inside
// is 1, fully outside is 0, and the pixel-wide band between them is the edge.
func cover(d float64) float64 {
	return clamp(0.5 - d/(2*aa))
}

func dist(p, q vec) float64 {
	return math.Hypot(p.x-q.x, p.y-q.y)
}

// segment is the distance from p to the line between a and b, ends included.
func segment(p, a, b vec) float64 {
	vx, vy := b.x-a.x, b.y-a.y
	wx, wy := p.x-a.x, p.y-a.y
	t := clamp((wx*vx + wy*vy) / (vx*vx + vy*vy))
	return math.Hypot(wx-t*vx, wy-t*vy)
}

// squircle is the rounded square macOS puts an icon in. The exponent is what
// separates it from a rectangle with rounded corners: the curve starts earlier
// and never quite straightens, which is the whole look.
func squircle(p vec, cx, cy, r float64) float64 {
	const n = 4.6
	dx := math.Abs(p.x-cx) / r
	dy := math.Abs(p.y-cy) / r
	return (math.Pow(math.Pow(dx, n)+math.Pow(dy, n), 1/n) - 1) * r
}

func mix(a, b rgb, t float64) rgb {
	t = clamp(t)
	return rgb{a.r + (b.r-a.r)*t, a.g + (b.g-a.g)*t, a.b + (b.b-a.b)*t}
}

func over(base, top rgb, a float64) rgb {
	return mix(base, top, a)
}

func clamp(v float64) float64 {
	return math.Min(1, math.Max(0, v))
}

func quant(v float64) uint8 {
	return uint8(math.Round(clamp(v) * 255))
}
