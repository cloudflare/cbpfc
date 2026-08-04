package clang

import (
	"os"
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
}
