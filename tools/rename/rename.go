package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	templateName     = "go-net-http-auth-base"
	templateGitHub   = "yurihbm/go-net-http-auth-base"
	templateTitle    = "Go net/http Auth Base"
	templateFallback = "PROJECT_NAME:-auth-base}"
	envExample       = ".env.example"
)

var (
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

	skippedDirs  = []string{".git", ".claude/worktrees", "bin", "tmp", "docs/swagger", "tools/rename"}
	skippedFiles = []string{"go.mod", "go.sum"}
)

type Options struct {
	Module string
	Name   string
	Title  string
}

type Result struct {
	Changed []string
	Manual  []string
}

func (o Options) Validate() error {
	switch {
	case o.Module == "" || strings.ContainsAny(o.Module, " \t\n\""):
		return errors.New("module must be a non-empty module path without spaces")
	case !namePattern.MatchString(o.Name):
		return errors.New("name must be lowercase letters, digits and hyphens")
	case strings.TrimSpace(o.Title) == "":
		return errors.New("title must not be empty")
	}
	return nil
}

func ReadModule(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", errors.New("go.mod has no module directive")
}

func githubRepo(module string) (string, bool) {
	parts := strings.Split(module, "/")
	if len(parts) < 3 || parts[0] != "github.com" {
		return "", false
	}
	return parts[1] + "/" + parts[2], true
}

// Rewrite returns the content with the template strings replaced; manual reports
// GitHub references left in place because the new module is not hosted on GitHub.
func Rewrite(content, currentModule string, o Options) (out string, manual bool) {
	githubNew, onGitHub := githubRepo(o.Module)
	if !onGitHub {
		githubNew = templateGitHub
		manual = strings.Contains(content, templateGitHub)
	}

	imports := regexp.MustCompile(`"` + regexp.QuoteMeta(currentModule) + `/([A-Za-z_])`)
	content = imports.ReplaceAllString(content, `"`+o.Module+`/$1`)

	out = strings.NewReplacer(
		templateGitHub, githubNew,
		templateTitle+" API", o.Title,
		templateTitle, o.Title,
		templateFallback, "PROJECT_NAME:-"+o.Name+"}",
		templateName, o.Name,
	).Replace(content)
	return out, manual
}

// RewriteEnvExample renames the database and the pgAdmin defaults of .env.example.
func RewriteEnvExample(content, name string) string {
	return strings.NewReplacer(
		"authbase@", strings.ReplaceAll(name, "-", "")+"@",
		"auth-base", name,
	).Replace(content)
}

func skipped(rel string, d fs.DirEntry) bool {
	if d.IsDir() {
		return slices.Contains(skippedDirs, rel)
	}
	base := filepath.Base(rel)
	if strings.HasPrefix(base, ".env") && rel != envExample {
		return true
	}
	return slices.Contains(skippedFiles, rel)
}

func Run(root string, o Options) (Result, error) {
	var res Result
	if err := o.Validate(); err != nil {
		return res, err
	}
	current, err := ReadModule(root)
	if err != nil {
		return res, err
	}
	if current == o.Module {
		return res, fmt.Errorf("module is already %s, nothing to rename", current)
	}

	manualFiles := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if skipped(rel, d) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		out, manual := Rewrite(string(data), current, o)
		if rel == envExample {
			out = RewriteEnvExample(out, o.Name)
		}
		if manual {
			manualFiles[rel] = true
		}
		if out == string(data) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(out), info.Mode().Perm()); err != nil {
			return err
		}
		res.Changed = append(res.Changed, rel)
		return nil
	})
	if err != nil {
		return res, err
	}

	edit := exec.Command("go", "mod", "edit", "-module", o.Module)
	edit.Dir = root
	if out, err := edit.CombinedOutput(); err != nil {
		return res, fmt.Errorf("go mod edit: %w: %s", err, out)
	}
	res.Changed = append(res.Changed, "go.mod")

	if err := gofmtChanged(root, res.Changed); err != nil {
		return res, err
	}

	if len(manualFiles) > 0 {
		files := make([]string, 0, len(manualFiles))
		for f := range manualFiles {
			files = append(files, f)
		}
		sort.Strings(files)
		res.Manual = append(res.Manual, fmt.Sprintf("replace the GitHub repository %s manually in: %s", templateGitHub, strings.Join(files, ", ")))
	}
	return res, nil
}

func gofmtChanged(root string, changed []string) error {
	var goFiles []string
	for _, f := range changed {
		if strings.HasSuffix(f, ".go") {
			goFiles = append(goFiles, f)
		}
	}
	if len(goFiles) == 0 {
		return nil
	}
	cmd := exec.Command("gofmt", append([]string{"-w"}, goFiles...)...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gofmt: %w: %s", err, out)
	}
	return nil
}
