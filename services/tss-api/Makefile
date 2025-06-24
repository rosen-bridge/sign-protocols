SHELL := /bin/bash
# ==============================================================================
# Modules support

deps-cleancache:
	go clean -modcache

list:
	go list -mod=mod all

build:
	go build -trimpath -o bin/rosenTss

version:
	go version
