// Command nfdesk is the netflow window.
//
// It shows what the agent is doing and lets somebody act on it without a
// terminal. The agent itself runs as a system service, as root, because
// creating a network interface needs that; this runs as whoever is logged in
// and talks to it over a socket. Nothing here holds a key or a credential.
//
// The window is small on purpose. It answers three questions — am I connected,
// to whom, and how — and everything else it can do is a consequence of one of
// those answers.
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "netflow",
		Width:  460,
		Height: 520,
		// Small, and allowed to be smaller. This is a thing somebody opens to
		// check on something and closes again, not a dashboard to live in.
		MinWidth:  380,
		MinHeight: 480,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// Transparent so the page decides the colour, which is how it follows
		// the system between light and dark without the frame flashing the
		// other one on the way.
		BackgroundColour: &options.RGBA{R: 0, G: 0, B: 0, A: 0},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []any{app},
		// Closing the window puts it away rather than ending the program: the
		// menu bar item is the part that stays, and quitting from a red button
		// would take away the thing somebody keeps this open for.
		HideWindowOnClose: true,
		Mac: &mac.Options{
			// The traffic lights sit inside the page rather than on a bar above
			// it: there is no menu in this window worth a strip of chrome.
			TitleBar:            mac.TitleBarHiddenInset(),
			WindowIsTranslucent: true,
			About: &mac.AboutInfo{
				Title:   "netflow",
				Message: "The mesh agent's window.",
			},
		},
		Windows: &windows.Options{
			WebviewIsTransparent: true,
			WindowIsTranslucent:  true,
		},
	})
	if err != nil {
		println("error:", err.Error())
	}
}
