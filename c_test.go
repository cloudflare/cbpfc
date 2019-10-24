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
		if !valid && err == nil {
			t.Fatalf("invalid function name %s not rejected", name)
		}
	}

	checkName(t, "", false)
	checkName(t, "0foo", false)
	checkName(t, "0foo\nfoo", false)
	checkName(t, "foo_bar2", true)
	checkName(t, "a2", true)
}

const entryPoint = "xdp_filter"

// loadC compiles classic BPF to C, which is compiled with clang
// XDPDrop on match, XDPPass otherwise
func loadC(tb testing.TB, insns []bpf.Instruction) *ebpf.ProgramSpec {
	tb.Helper()

	elf, err := buildC(insns, entryPoint)
	if err != nil {
		tb.Fatal(err)
	}

	// load ELF
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		tb.Fatal(err)
	}

	return spec.Programs[entryPoint]
}
