# Requisites:
# 1. Go: https://golang.org/
# 2. xcaddy: https://github.com/caddyserver/xcaddy

default: build
# export CADDY_VERSION=v2.6.4

GO=go
GOTEST=$(GO) test
GOCOVER=$(GO) tool cover
XCADDY=xcaddy

build:
	XCADDY_GO_BUILD_FLAGS="-ldflags '-s -w'" $(XCADDY) build --with github.com/ixycoder/caddy-query-signature=$(shell pwd)

debug:
	XCADDY_DEBUG=1 $(XCADDY) build --with github.com/ixycoder/caddy-query-signature=$(shell pwd)

test: test/cover test/report

test/cover:
	$(GOTEST) -v -race -failfast -parallel 4 -cpu 4 -coverprofile main.cover.out ./...

test/report:
	$(GOCOVER) -html=main.cover.out

.PHONY: debug test test/cover test/report