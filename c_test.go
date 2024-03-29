package cbpfc

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/net/bpf"
)

func TestFunctionName(t *testing.T) {
	checkName := func(t *testing.T, name string, valid bool) {
		t.Helper()

		_, err := ToC([]bpf.Instruction{bpf.RetA{}}, COpts{
			FunctionName: name,
		})
		if valid && err != nil {
			t.Fatalf("valid function name %s rejected: %v", name, err)
		}
		if !valid {
			requireError(t, err, "invalid FunctionName")
		}
	}

	checkName(t, "", false)
	checkName(t, "0foo", false)
	checkName(t, "0foo\nfoo", false)
	checkName(t, "foo_bar2", true)
	checkName(t, "a2", true)
}

func TestNoInline(t *testing.T) {
	elf, err := buildC([]bpf.Instruction{
		bpf.RetConstant{Val: 1},
	}, entryPoint, COpts{
		FunctionName: "filter",
		NoInline:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		t.Fatal(err)
	}

	if res := testProg(t, spec.Programs[entryPoint], []byte{1}); res != match {
		t.Fatalf("expected match, got %v", res)
	}
}

const entryPoint = "xdp_filter"

// cBackend compiles classic BPF to C, which is compiled with clang
func cBackend(tb testing.TB, insns []bpf.Instruction, in []byte) result {
	elf, err := buildC(insns, entryPoint, COpts{FunctionName: "filter"})
	if err != nil {
		tb.Fatal(err)
	}

	// load ELF
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		tb.Fatal(err)
	}

	return testProg(tb, spec.Programs[entryPoint], in)
}
