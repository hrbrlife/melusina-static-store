package main

import (
	"context"
	"encoding/json"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	"reflect"
	"strings"
	"testing"
)

func TestPrivateOriginalSourceUsesExistingCredentialsOnlyForFixedRead(t *testing.T) {
	cmd, err := authenticatedSourceRead(context.Background(), "/home/original-operator")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Dir != "/" || !reflect.DeepEqual(cmd.Args, []string{"/usr/bin/git", "--no-replace-objects", "ls-remote", "--heads", firstRepository + ".git"}) {
		t.Fatal("private source lookup can change command, repository or refs")
	}
	if !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/bin:/bin", "HOME=/home/original-operator", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0"}) {
		t.Fatal("private source read disables existing credentials or inherits command overrides")
	}
	for _, home := range []string{"", "relative", "/home/../other", " /home/operator"} {
		if _, err := authenticatedSourceRead(context.Background(), home); err == nil {
			t.Fatal("noncanonical credential home accepted")
		}
	}
}

func TestClosedInitialSourceSelectionNeverInventsDevPublish(t *testing.T) {
	heads := firstCommit + "\trefs/heads/main\n"
	if e := selectedMain(heads, firstRepository+".git", firstTree); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.ReplaceAll(heads, "main", "dev-publish"), strings.Replace(heads, firstCommit, strings.Repeat("a", 40), 1), heads + firstCommit + "\trefs/heads/new-branch\n", ""} {
		if e := selectedMain(bad, firstRepository, firstTree); e == nil {
			t.Fatal("unreviewed or invented branch accepted")
		}
	}
	if e := selectedMain(heads, "https://github.com/example/other", firstTree); e == nil {
		t.Fatal("foreign repository accepted")
	}
	if e := selectedMain(heads, firstRepository, strings.Repeat("b", 40)); e == nil {
		t.Fatal("foreign tree accepted")
	}
	s := selection()
	if s.Kind != "initial-onboarding" || s.RequiredApproval == "" || s.Branch != "main" {
		t.Fatal("initial policy lost original approval or source")
	}
}
func TestInitialMetadataBindsSourceAndDeclaresDisconnectedScope(t *testing.T) {
	meta := metadata()
	var d map[string]any
	if e := json.Unmarshal(meta, &d); e != nil {
		t.Fatal(e)
	}
	s := d["sourceAdmission"].(map[string]any)
	if s["schema"] != firstPolicy || s["commit"] != firstCommit || s["appId"] != firstID || s["spkSha256"] != firstSHA {
		t.Fatal("AppHash metadata lost exact source/package binding")
	}
	if !strings.Contains(d["description"].(string), "disconnected") {
		t.Fatal("bootstrap claims functioning publication")
	}
	hash := strings.Repeat("a", 64)
	c := contract(hash)
	raw, _ := json.Marshal(c)
	if _, e := runtimecontract.ValidateClaim(raw, runtimecontract.Binding{Metadata: meta, AppHash: hash, Version: "0.1.0", ReleaseContractSHA256: digest(raw), ReleaseContractSchema: runtimecontract.Schema}); e != nil {
		t.Fatal(e)
	}
	if len(c.Sidecars) != 0 || c.App.AppID != firstID || !strings.Contains(c.LaunchProbe.ExpectedResult, "Publication remains unavailable") {
		t.Fatal("initial declaration invented completed worker/Store authority")
	}
}
