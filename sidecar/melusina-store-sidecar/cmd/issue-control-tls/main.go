package main

// issue-control-tls creates one fresh, local Store control transport bundle.
// The owner signs the printed client pin with sign-store-security; the
// installer checks that pin before placing the serving material.
import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/controltlsissue"
)

func run(args []string) error {
	fs := flag.NewFlagSet("issue-control-tls", flag.ContinueOnError)
	name := fs.String("server-name", "", "Store control listener DNS name or IP")
	out := fs.String("out", "", "new private bundle JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *out == "" || !filepath.IsAbs(*out) {
		return errors.New("control-tls-output-absolute-path-required")
	}
	material, pin, err := controltlsissue.Issue(*name, time.Now())
	if err != nil {
		return err
	}
	raw, err := json.Marshal(material)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Printf("store-link-client-cert-sha256=%s\n", pin)
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
