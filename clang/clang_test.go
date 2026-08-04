package clang

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompile(t *testing.T) {
	clangBin, ok := os.LookupEnv("CLANG")
	if !ok {
		clangBin = "/usr/bin/clang"
	}

	source := []byte(`int main() { return 0; }`)
	opts := Opts{
		Clang: clangBin,
	}

	t.Run("bare", func(t *testing.T) {
		elf, err := Compile(source, "test", opts)
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		if len(elf) == 0 {
			t.Fatal("ELF empty")
		}
	})

	t.Run("res", func(t *testing.T) {
		res, err := CompileRes(source, "test", opts)
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		if len(res.ELF) == 0 {
			t.Fatal("ELF empty")
		}
		if res.CPUTime == 0 {
			t.Fatal("CPUTime zero")
		}
	})

	t.Run("output_dir", func(t *testing.T) {
		opts := opts

		output := t.TempDir()
		opts.Output = output

		elf, err := Compile(source, "test", opts)
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		if !bytes.Equal(source, mustReadFile(t, output, "test.c")) {
			t.Fatal("source doesn't match")
		}
		if !bytes.Equal(elf, mustReadFile(t, output, "test.elf")) {
			t.Fatal("Returned ELF and filesystem ELF are different")
		}
		if build := string(mustReadFile(t, output, "build")); !strings.Contains(build, "clang") {
			t.Fatalf("bad build script: %q", build)
		}
	})
}

func mustReadFile(tb testing.TB, dir string, file string) []byte {
	val, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		tb.Fatal(err)
	}
	return val
}
