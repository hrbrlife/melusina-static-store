package main

import (
	"strings"
	"testing"
)

func TestH09_3_6RootStoreHostHasNoControllerConfig(t *testing.T) {
	ordinary := newControllerRenderFixture(t)
	ordinary.writeInput(t, ordinary.input)
	if _, err := ordinary.render(); err != nil {
		t.Fatalf("3.6::title-claim: ordinary component host render: %v", err)
	}

	rootStore := newControllerRenderFixture(t)
	rootStore.writeInput(t, rootStore.input)
	plantHostPath(t, rootStore.hostRoot, storeConfigRoot, true)
	_, err := rootStore.render()
	if err == nil || !strings.Contains(err.Error(), "3.6::title-claim: "+refusalControllerRenderRootStore) {
		t.Fatalf("3.6::title-claim: root Store host was not refused by name: %v", err)
	}
	rootStore.requireNoOutput(t)
}
