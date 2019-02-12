package cbpfc

import (
	"testing"

	"github.com/newtools/ebpf"
	"github.com/newtools/ebpf/asm"
	"golang.org/x/net/bpf"
)

// loadEBPF compiles classic BPF to eBPF, and loads it in the kernel
// XDPDrop on match, XDPPass otherwise
func loadEBPF(tb testing.TB, insns []bpf.Instruction) *ebpf.Program {
	tb.Helper()

	// Labels of blocks
	exit := "exit"
	match := "match"

	filter, err := ToEBPF(insns, EBPFOpts{
		PacketStart:  asm.R0,
		PacketEnd:    asm.R1,
		RegA:         asm.R2,
		RegX:         asm.R3,
		RegTmp:       asm.R4,
		RegIndirect:  asm.R5,
		LabelPrefix:  "filter",
		MatchLabel:   match,
		NoMatchLabel: exit,
	})
	if err != nil {
		tb.Fatal(err)
	}

	prog := asm.Instructions{
		// Save ctx
		asm.Mov.Reg(asm.R6, asm.R1),

		// Packet start
		asm.LoadMem(asm.R0, asm.R6, 0, asm.Word),

		// Packet end
		asm.LoadMem(asm.R1, asm.R6, 4, asm.Word),

		// Fall through to filter
	}

	prog = append(prog, filter...)

	// verifier does not like dead code - only include exit blocks if the prog refers to them
	refs := prog.ReferenceOffsets()

	// Match
	if _, ok := refs[match]; ok {
		prog = append(prog,
			asm.Mov.Imm(asm.R0, int32(XDPDrop)).Sym(match),
			asm.Return(),
		)
	}

	// Exit
	if _, ok := refs[exit]; ok {
		prog = append(prog,
			asm.Mov.Imm(asm.R0, int32(XDPPass)).Sym(exit),
			asm.Return(),
		)
	}

	tb.Logf("\n%v", prog)

	loadedProg, err := ebpf.NewProgram(
		&ebpf.ProgramSpec{
			Name:         "ebpf_filter",
			Type:         ebpf.XDP,
			Instructions: prog,
			License:      "BSD",
		},
	)
	if err != nil {
		tb.Fatal(err)
	}

	return loadedProg
}
