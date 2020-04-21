package cbpfc

import (
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/net/bpf"
)

// ebpfBacked is backend that compiles classic BPF to eBPF
func ebpfBackend(tb testing.TB, insns []bpf.Instruction, in []byte) result {
	prog, err := buildEBPF(insns)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Logf("\n%v", prog)

	return testProg(tb, &ebpf.ProgramSpec{
		Name:         "ebpf_filter",
		Type:         ebpf.XDP,
		Instructions: prog,
		License:      "BSD",
	}, in)
}
