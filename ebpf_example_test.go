package cbpfc

import (
	"github.com/newtools/ebpf/asm"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

// ExampleToEBPF demonstrates how to use ToEBPF() to embded a cBPF filter
// in an eBPF assembly program.
func ExampleToEBPF() {
	// simple cBPF filter that matches all packets
	filter := []bpf.Instruction{
		bpf.RetConstant{Val: 1},
	}

	prog, err := buildEBPF(filter)
	if err != nil {
		panic(err)
	}

	// Prog can be loaded directly using newtools/ebpf,
	// or converted to a '[]struct bpf_insn' for libbpf
	_ = prog
}

// buildEBPF compiles a cBPF filter to eBPF, and embeds it an eBPF program.
// The XDP program XDP_DROP's incomming packets that match the filter.
// Returns the eBPF program instructions
func buildEBPF(filter []bpf.Instruction) (asm.Instructions, error) {
	ebpfFilter, err := ToEBPF(filter, EBPFOpts{
		// Pass packet start and end pointers in these registers
		PacketStart: asm.R2,
		PacketEnd:   asm.R3,
		// Registers used by generated code
		Working:      [4]asm.Register{asm.R4, asm.R5, asm.R6, asm.R7},
		LabelPrefix:  "filter",
		MatchLabel:   "drop",
		NoMatchLabel: "pass",
	})
	if err != nil {
		return nil, errors.Wrap(err, "converting filter to eBPF")
	}

	prog := asm.Instructions{
		// R1 holds XDP context

		// Packet start
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),

		// Packet end
		asm.LoadMem(asm.R3, asm.R1, 4, asm.Word),

		// Fall through to filter
	}

	prog = append(prog, ebpfFilter...)

	// kernel verifier does not like dead code - only include exit blocks if the prog refers to them
	refs := prog.ReferenceOffsets()

	// Packet matches, drop it
	if _, ok := refs["drop"]; ok {
		prog = append(prog,
			asm.Mov.Imm(asm.R0, 1).Sym("drop"), // XDP_DROP
			asm.Return(),
		)
	}

	// Packet doesn't match, pass it
	if _, ok := refs["pass"]; ok {
		prog = append(prog,
			asm.Mov.Imm(asm.R0, 2).Sym("pass"), // XDP_PASS
			asm.Return(),
		)
	}

	return prog, nil
}
