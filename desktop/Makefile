# The window.
#
# macOS will not sign a bundle carrying iCloud's file-provider attributes, and
# this project lives in a synced folder — so wails' own signing step fails on
# a bundle that is otherwise finished. The build is allowed to fail there, the
# attributes are cleared, and the signing happens here instead. The check on
# the next line is what keeps a real build failure from passing silently.
WAILS ?= $(HOME)/go/bin/wails
APP   := build/bin/netflow.app
# The version the window shows in its footer. Taken from the repository, so a
# build from a tag says the tag and a build from a working tree says so too.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: app dev install icon clean

# app builds the release bundle and signs it ad hoc.
#
# Ad hoc means "signed by nobody": macOS will run it once somebody opens it
# from the Finder and confirms. That is the deal until there is a developer
# account, and it is enough for a client that is installed by the same person
# who built it.
app:
	-$(WAILS) build -clean -ldflags "-X main.version=$(VERSION)"
	@test -x $(APP)/Contents/MacOS/netflow || \
		{ echo "the build did not produce a binary; the error above is real"; exit 1; }
	xattr -cr $(APP)
	codesign --force --deep --sign - $(APP)
	@echo "built $(APP)"

# install puts the built bundle where the Finder, Spotlight and the Dock look
# for it. Replaces whatever is there, so it is also how an update is applied.
install: app
	rm -rf /Applications/netflow.app
	cp -R $(APP) /Applications/netflow.app
	@echo "installed /Applications/netflow.app"

# dev runs it with a live frontend. It signs on every rebuild, so it needs the
# bundle somewhere the sync does not reach.
dev:
	@mkdir -p $(TMPDIR)netflow-bin
	@rm -rf build/bin && ln -s $(TMPDIR)netflow-bin build/bin
	$(WAILS) dev -ldflags "-X main.version=$(VERSION)"
	@rm -f build/bin

# icon redraws build/appicon.png, which wails turns into the bundle's iconset.
# Only needed when the mark changes; the result is checked in.
icon:
	go run ./build/icon

clean:
	rm -rf build/bin frontend/dist
