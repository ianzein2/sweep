PREFIX ?= /usr/local

.PHONY: build install uninstall app install-app clean

# CLI
build:
	swift build -c release --product sweep

install: build
	install -d $(PREFIX)/bin
	install -m 755 .build/release/sweep $(PREFIX)/bin/sweep

uninstall:
	rm -f $(PREFIX)/bin/sweep

# App
app:
	swift build -c release --product SweepApp
	mkdir -p build/Sweep.app/Contents/MacOS
	mkdir -p build/Sweep.app/Contents/Resources
	cp .build/release/SweepApp build/Sweep.app/Contents/MacOS/Sweep
	cp Resources/Info.plist build/Sweep.app/Contents/
	@if [ -f Resources/AppIcon.icns ]; then \
		cp Resources/AppIcon.icns build/Sweep.app/Contents/Resources/; \
	fi
	@echo "Built: build/Sweep.app"

install-app: app
	cp -R build/Sweep.app /Applications/Sweep.app
	@echo "Installed to /Applications/Sweep.app"

clean:
	swift package clean
	rm -rf build/
