package cbpfc

import (
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/net/bpf"
)

// loadEBPF compiles classic BPF to eBPF
// XDPDrop on match, XDPPass otherwise
func loadEBPF(tb testing.TB, insns []bpf.Instruction) *ebpf.ProgramSpec {
	tb.Helper()

	prog, err := buildEBPF(insns)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Logf("\n%v", prog)

	return &ebpf.ProgramSpec{
		Name:         "ebpf_filter",
		Type:         ebpf.XDP,
		Instructions: prog,
		License:      "BSD",
	}
}
