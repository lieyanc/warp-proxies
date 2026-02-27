BINARY := warp-proxies
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TAGS := with_wireguard,with_gvisor,with_clash_api
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-linux build-linux-arm64 clean

build:
	CGO_ENABLED=0 go build -tags "$(TAGS)" -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "$(TAGS)" -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 .

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags "$(TAGS)" -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64 .

clean:
	rm -f $(BINARY) $(BINARY)-*
