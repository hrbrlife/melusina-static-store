package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	storelink "github.com/hrbrlife/bazaar-store-link"
)

func main() {
	configPath := flag.String("config", "", "absolute Store Link configuration path")
	flag.Parse()
	config, err := storelink.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Store Link config: %v", err)
	}
	forwarder, err := storelink.NewSidecarForwarder(config)
	if err != nil {
		log.Fatalf("Store Link sidecar identity: %v", err)
	}
	handler, err := storelink.NewHandler(config, forwarder)
	if err != nil {
		log.Fatalf("Store Link handler: %v", err)
	}
	server := &http.Server{Addr: config.ListenAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 3 * time.Minute, WriteTimeout: 3 * time.Minute, IdleTimeout: time.Minute}
	log.Printf("Bazaar Store Link listening privately on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
