package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testOptions = Options{Module: "github.com/acme/foo", Name: "foo", Title: "Foo API"}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	require.NoError(t, err)
	return string(b)
}

func TestOptions_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		assert.NoError(t, testOptions.Validate())
	})

	t.Run("error - empty module", func(t *testing.T) {
		assert.Error(t, Options{Name: "foo", Title: "Foo"}.Validate())
	})

	t.Run("error - module with spaces", func(t *testing.T) {
		assert.Error(t, Options{Module: "a b", Name: "foo", Title: "Foo"}.Validate())
	})

	t.Run("error - invalid name", func(t *testing.T) {
		assert.Error(t, Options{Module: "x", Name: "Foo Bar", Title: "Foo"}.Validate())
	})

	t.Run("error - empty title", func(t *testing.T) {
		assert.Error(t, Options{Module: "x", Name: "foo"}.Validate())
	})
}

func TestReadModule(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "go.mod", "module go-net-http-auth-base\n\ngo 1.22\n")

		module, err := ReadModule(root)

		assert.NoError(t, err)
		assert.Equal(t, "go-net-http-auth-base", module)
	})

	t.Run("error - missing go.mod", func(t *testing.T) {
		_, err := ReadModule(t.TempDir())
		assert.Error(t, err)
	})

	t.Run("error - no module directive", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "go.mod", "go 1.22\n")

		_, err := ReadModule(root)
		assert.Error(t, err)
	})
}

func TestRewrite(t *testing.T) {
	t.Run("success - import paths get the module", func(t *testing.T) {
		in := "import (\n\t\"go-net-http-auth-base/internal/api\"\n\t_ \"go-net-http-auth-base/docs/swagger\"\n)\n"

		out, _ := Rewrite(in, "go-net-http-auth-base", testOptions)

		assert.Equal(t, "import (\n\t\"github.com/acme/foo/internal/api\"\n\t_ \"github.com/acme/foo/docs/swagger\"\n)\n", out)
	})

	t.Run("success - names get the name", func(t *testing.T) {
		in := "x = \"go-net-http-auth-base\"\nua = \"go-net-http-auth-base/1.0\"\n"

		out, _ := Rewrite(in, "go-net-http-auth-base", testOptions)

		assert.Equal(t, "x = \"foo\"\nua = \"foo/1.0\"\n", out)
	})

	t.Run("success - github references become owner/repo before the module replacement", func(t *testing.T) {
		in := "https://github.com/yurihbm/go-net-http-auth-base/actions"

		out, manual := Rewrite(in, "go-net-http-auth-base", testOptions)

		assert.Equal(t, "https://github.com/acme/foo/actions", out)
		assert.False(t, manual)
	})

	t.Run("success - non-github module leaves github references and flags them", func(t *testing.T) {
		in := "https://github.com/yurihbm/go-net-http-auth-base/actions go-net-http-auth-base"
		opts := Options{Module: "example.com/foo", Name: "foo", Title: "Foo API"}

		out, manual := Rewrite(in, "go-net-http-auth-base", opts)

		assert.Equal(t, "https://github.com/yurihbm/go-net-http-auth-base/actions foo", out)
		assert.True(t, manual)
	})

	t.Run("success - title and compose fallback", func(t *testing.T) {
		in := "// @title Go net/http Auth Base API\n# Go net/http Auth Base\nname: ${PROJECT_NAME:-auth-base}_edge\n"

		out, _ := Rewrite(in, "go-net-http-auth-base", testOptions)

		assert.Equal(t, "// @title Foo API\n# Foo API\nname: ${PROJECT_NAME:-foo}_edge\n", out)
	})

	t.Run("success - already renamed content is untouched", func(t *testing.T) {
		in := "\"github.com/acme/foo/internal/api\" foo ${PROJECT_NAME:-foo}"

		out, _ := Rewrite(in, "github.com/acme/foo", Options{Module: "github.com/acme/bar", Name: "bar", Title: "Bar"})

		assert.Equal(t, "\"github.com/acme/bar/internal/api\" foo ${PROJECT_NAME:-foo}", out)
	})
}

func TestRun(t *testing.T) {
	newFixture := func(t *testing.T) string {
		root := t.TempDir()
		writeFile(t, root, "go.mod", "module go-net-http-auth-base\n\ngo 1.22\n")
		writeFile(t, root, "go.sum", "go-net-http-auth-base keep\n")
		writeFile(t, root, "main.go", "package main\n\nimport _ \"go-net-http-auth-base/internal/x\"\n")
		writeFile(t, root, "internal/x/x.go", "package x\n\nconst Name = \"go-net-http-auth-base\"\n")
		writeFile(t, root, "README.md", "# Go net/http Auth Base\n[b](https://github.com/yurihbm/go-net-http-auth-base/x)\n")
		writeFile(t, root, "docs/swagger/docs.go", "go-net-http-auth-base\n")
		writeFile(t, root, ".git/config", "go-net-http-auth-base\n")
		writeFile(t, root, ".claude/worktrees/w/a.txt", "go-net-http-auth-base\n")
		writeFile(t, root, "bin/app", "go-net-http-auth-base\n")
		writeFile(t, root, "tmp/a.txt", "go-net-http-auth-base\n")
		writeFile(t, root, "tools/rename/rename.go", "go-net-http-auth-base\n")
		writeFile(t, root, ".env", "go-net-http-auth-base\n")
		writeFile(t, root, ".env.local", "go-net-http-auth-base\n")
		writeFile(t, root, ".env.example", "DATABASE_URL=\"postgresql://u:p@localhost:5432/auth-base?sslmode=disable\"\nPOSTGRES_DB=\"auth-base\"\nPGADMIN_DEFAULT_EMAIL=\"authbase@mail.com\"\nPGADMIN_DEFAULT_PASSWORD=\"auth-base123\"\n")
		writeFile(t, root, "blob.bin", "go-net-http-auth-base\x00\x01")
		return root
	}

	t.Run("success", func(t *testing.T) {
		root := newFixture(t)

		res, err := Run(root, testOptions)

		require.NoError(t, err)
		assert.Equal(t, "module github.com/acme/foo\n\ngo 1.22\n", readFile(t, root, "go.mod"))
		assert.Equal(t, "package main\n\nimport _ \"github.com/acme/foo/internal/x\"\n", readFile(t, root, "main.go"))
		assert.Contains(t, readFile(t, root, "internal/x/x.go"), "\"foo\"")
		assert.Equal(t, "# Foo API\n[b](https://github.com/acme/foo/x)\n", readFile(t, root, "README.md"))
		assert.ElementsMatch(t, []string{".env.example", "README.md", "go.mod", "internal/x/x.go", "main.go"}, res.Changed)
		assert.Empty(t, res.Manual)
	})

	t.Run("success - .env.example gets the database name and pgAdmin defaults", func(t *testing.T) {
		root := newFixture(t)

		_, err := Run(root, testOptions)

		require.NoError(t, err)
		assert.Equal(t, "DATABASE_URL=\"postgresql://u:p@localhost:5432/foo?sslmode=disable\"\nPOSTGRES_DB=\"foo\"\nPGADMIN_DEFAULT_EMAIL=\"foo@mail.com\"\nPGADMIN_DEFAULT_PASSWORD=\"foo123\"\n", readFile(t, root, ".env.example"))
	})

	t.Run("success - skipped paths are untouched", func(t *testing.T) {
		root := newFixture(t)

		_, err := Run(root, testOptions)

		require.NoError(t, err)
		for _, rel := range []string{"go.sum", "docs/swagger/docs.go", ".git/config", ".claude/worktrees/w/a.txt", "bin/app", "tmp/a.txt", "tools/rename/rename.go", ".env", ".env.local", "blob.bin"} {
			assert.Contains(t, readFile(t, root, rel), "go-net-http-auth-base", rel)
		}
	})

	t.Run("success - non-github module reports manual steps", func(t *testing.T) {
		root := newFixture(t)

		res, err := Run(root, Options{Module: "example.com/foo", Name: "foo", Title: "Foo API"})

		require.NoError(t, err)
		assert.Contains(t, readFile(t, root, "README.md"), "github.com/yurihbm/go-net-http-auth-base")
		require.Len(t, res.Manual, 1)
		assert.Contains(t, res.Manual[0], "README.md")
	})

	t.Run("error - same module is rejected and nothing changes", func(t *testing.T) {
		root := newFixture(t)
		_, err := Run(root, testOptions)
		require.NoError(t, err)
		before := readFile(t, root, "main.go")

		_, err = Run(root, testOptions)

		assert.ErrorContains(t, err, "already")
		assert.Equal(t, before, readFile(t, root, "main.go"))
	})

	t.Run("error - missing go.mod", func(t *testing.T) {
		_, err := Run(t.TempDir(), testOptions)
		assert.Error(t, err)
	})
}

func copyRepo(t *testing.T, src, dst string) {
	t.Helper()
	skip := map[string]bool{".git": true, ".claude/worktrees": true, "bin": true, "tmp": true}
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		rel = filepath.ToSlash(rel)
		if skip[rel] {
			if !d.IsDir() {
				return nil
			}
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".env") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	require.NoError(t, err)
}

func TestRun_RepositoryBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("copies the repository and builds it")
	}
	repo, err := filepath.Abs("../..")
	require.NoError(t, err)
	dst := t.TempDir()

	copyRepo(t, repo, dst)

	_, err = Run(dst, testOptions)
	require.NoError(t, err)

	build := exec.Command("go", "build", "./...")
	build.Dir = dst
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))
	assert.False(t, strings.Contains(readFile(t, dst, "cmd/api/main.go"), "Auth Base"))
}
