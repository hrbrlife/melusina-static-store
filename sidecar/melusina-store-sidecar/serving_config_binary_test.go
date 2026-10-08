package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestServingBinaryRefusesRenderedConfigWithoutControlMTLS(t *testing.T) {
	_, profilePath, inputPath, configPath, input := newStoreConfigRenderFixture(t)
	writeStoreConfigRenderInput(t, inputPath, input)
	if _, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: configPath}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if _, ok := config["store_link_control_mtls"]; !ok {
		t.Fatal("signed-renderer-control-mtls-missing")
	}
	delete(config, "store_link_control_mtls")
	changed, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("go", "run", ".", "-config", configPath).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "store_link_control_mtls is required") {
		t.Fatalf("serving-binary-missing-control-mtls-refused: %v %s", err, output)
	}
}
