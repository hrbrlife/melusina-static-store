package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	storelink "github.com/hrbrlife/bazaar-store-link"
)

func main() {
	configPath := flag.String("config", "", "absolute Store Link configuration path")
	verifyWorkers := flag.Bool("verify-workers", false, "verify the four fixed worker mTLS routes without creating a job")
	verifyControlPlane := flag.Bool("verify-control-plane", false, "verify the pinned sidecar ready status and four fixed worker routes without creating a job")
	flag.Parse()
	if *verifyWorkers && *verifyControlPlane {
		log.Fatal("Store Link preflight: choose -verify-workers or -verify-control-plane, not both")
	}
	config, err := storelink.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Store Link config: %v", err)
	}
	forwarder, err := storelink.NewSidecarForwarder(config)
	if err != nil {
		log.Fatalf("Store Link sidecar identity: %v", err)
	}
	workers, err := storelink.NewWorkerForwarder(config)
	if err != nil {
		log.Fatalf("Store Link worker boundary: %v", err)
	}
	if *verifyControlPlane {
		if err := storelink.VerifyControlPlane(context.Background(), config, forwarder, workers); err != nil {
			log.Fatalf("Store Link control-plane preflight: %v", err)
		}
		log.Printf("Store Link control-plane preflight passed: sidecar ready and all four pinned worker routes refused the reserved job")
		return
	}
	if *verifyWorkers {
		if err := storelink.VerifyFixedWorkers(context.Background(), workers); err != nil {
			log.Fatalf("Store Link worker preflight: %v", err)
		}
		log.Printf("Store Link worker preflight passed: all four pinned worker routes refused the reserved job")
		return
	}
	handler, err := storelink.NewHandlerWithWorkers(config, forwarder, workers)
	if err != nil {
		log.Fatalf("Store Link handler: %v", err)
	}
	server := &http.Server{Addr: config.ListenAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 3 * time.Minute, WriteTimeout: 3 * time.Minute, IdleTimeout: time.Minute}
	log.Printf("Bazaar Store Link listening privately on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
