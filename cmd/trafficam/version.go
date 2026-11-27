package main

// version is set at build time by the release workflow:
//
//	go build -ldflags "-X main.version=v0.1.0" ./cmd/trafficam
//
// A plain "go build" leaves it as "dev".
var version = "dev"
