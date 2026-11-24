package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
)

func main() {
	var o Options
	flag.StringVar(&o.Module, "module", "", "new Go module path (e.g. github.com/acme/foo)")
	flag.StringVar(&o.Name, "name", "", "new project name for services, compose and dashboards (e.g. foo)")
	flag.StringVar(&o.Title, "title", "", "new human-readable title (e.g. \"Foo API\")")
	flag.Parse()

	if err := o.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprintln(os.Stderr, "usage: make rename module=github.com/acme/foo name=foo title=\"Foo API\"")
		os.Exit(2)
	}

	res, err := Run(".", o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	swagger := exec.Command("make", "swagger-gen")
	swagger.Stdout, swagger.Stderr = os.Stdout, os.Stderr
	if err := swagger.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error: make swagger-gen failed (install swag with make install-swag):", err)
		os.Exit(1)
	}

	sort.Strings(res.Changed)
	fmt.Printf("Renamed the template: %d files changed, docs/swagger regenerated.\n\nManual steps left:\n", len(res.Changed))
	for _, m := range res.Manual {
		fmt.Println("  -", m)
	}
	for _, m := range []string{
		"set PROJECT_NAME in .env",
		"update the copyright holder in LICENSE",
		"add .github/CODEOWNERS",
		"replace the placeholder contact in SECURITY.md",
		"see \"Using this template\" in README.md, including how to leave the template phase",
	} {
		fmt.Println("  -", m)
	}
}
