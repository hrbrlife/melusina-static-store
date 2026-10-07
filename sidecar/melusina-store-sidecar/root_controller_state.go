package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

const rootControllerStatePath = "/control/v1/root-controller-state"
const rootControllerStoreMarker = "/etc/melusina/store"
const rootControllerConfigDir = "/etc/melusina/update-controller"
const rootControllerConfigName = "config.json"
const rootControllerRegistryName = "component-registry.json"

// newRootControllerStateHandler is available only on the Store's private mTLS
// control listener. It makes the root Store host's lack of controller config
// observable without rendering a config or changing the host.
func newRootControllerStateHandler(hostRoot string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "3.6::title-claim: readback requires GET", http.StatusMethodNotAllowed)
			return
		}
		marker := filepath.Join(hostRoot, rootControllerStoreMarker)
		info, err := os.Lstat(marker)
		if err != nil || !info.IsDir() {
			http.Error(w, fmt.Sprintf("3.6::title-claim: root Store host marker unavailable: %v", err), http.StatusServiceUnavailable)
			return
		}
		for _, name := range []string{rootControllerConfigName, rootControllerRegistryName} {
			path := filepath.Join(hostRoot, rootControllerConfigDir, name)
			if _, err := os.Lstat(path); err == nil {
				http.Error(w, "3.6::title-claim: root Store host carries controller config: "+name, http.StatusConflict)
				return
			} else if !os.IsNotExist(err) {
				http.Error(w, "3.6::title-claim: controller config unreadable: "+name, http.StatusServiceUnavailable)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema": "melusina.root-controller-state.v1", "rootStoreHost": true,
			"noControllerConfig": true, "marker": rootControllerStoreMarker,
		})
	})
}
