BIN      := mxghost
SRC_PATH := ./cmd/mxghost
BUILD    := build
DEBPATH  := debian/deb/
EMAIL    := decisivewaffles@gmail.com

$(eval V := $(shell ./scripts/mkversion.sh > .version && cat .version))

.PHONY: build deb clean

build:
	mkdir -p $(BUILD)
	CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$(V)" \
		-o ./$(BUILD)/$(BIN) $(SRC_PATH)

deb: build
	mkdir -p $(DEBPATH)
	dch --newversion "$(V)" --distribution stable \
	    --urgency medium
	dpkg-buildpackage -us -uc -b
	mv ../$(BIN)_$(V)_*.deb $(DEBPATH)
	rm ../$(BIN)_$(V)_*.{changes,buildinfo}

dev-deb:
	mkdir -p $(DEBPATH)
	dch --newversion "$(V)" --distribution unstable \
	    --urgency low "Automatic dev build." -M
	dpkg-buildpackage -us -uc -b
	mv ../$(BIN)_$(V)_*.deb $(DEBPATH)
	rm ../$(BIN)_$(V)_*.{changes,buildinfo}

clean:
	rm -rf $(BUILD)
	dh_clean
