package cbpfc

import (
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

// requireError ensures an error is not nil, and it contains contains.
func requireError(tb testing.TB, err error, contains string) {
	tb.Helper()

	if err == nil {
		tb.Fatalf("expected error %s", contains)
	}

	if !strings.Contains(err.Error(), contains) {
		tb.Fatalf("error %v does not contain %s", err, contains)
	}
}

// Make sure we bail out with 0 instructions
func TestZero(t *testing.T) {
	_, err := compile([]bpf.Instruction{})

	requireError(t, err, "can't compile 0 instructions")
}

func TestRaw(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.RawInstruction{},
	})

	requireError(t, err, "unsupported instruction 0:")
}

// Absolute / constant loads can't use negative offsets, they're for extensions.
func TestLoadAbsoluteNegativeOffset(t *testing.T) {
	off := (^uint32(1)) + 1 // -1

	for _, insn := range []bpf.Instruction{
		bpf.LoadAbsolute{Off: off, Size: 1},
		bpf.LoadMemShift{Off: off},
	} {
		_, err := compile([]bpf.Instruction{
			insn,
			bpf.RetA{},
		})

		requireError(t, err, "negative offset -1")
	}
}

func TestExtension(t *testing.T) {
	// No extensions > 256 right now
	for i := 0; i < 256; i++ {
		ext := bpf.Extension(i)

		_, err := compile([]bpf.Instruction{
			bpf.LoadExtension{Num: ext},
			bpf.RetA{},
		})

		switch ext {
		case bpf.ExtLen:
			if err != nil {
				t.Fatal("ExtLen not accepted", err)
			}
		default:
			requireError(t, err, "unsupported BPF extension 0:")
		}
	}
}

// Test out of bound jumps
func TestJumpOut(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegX, Val: 0},
		bpf.Jump{Skip: 0},
	})

	requireError(t, err, "instruction 1: ja 0 flows past last instruction")
}

func TestJumpIfOut(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 2, SkipTrue: 0, SkipFalse: 1},
	})

	requireError(t, err, "instruction 1: jneq #2,1 flows past last instruction")
}

func TestJumpIfXOut(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 3},
		bpf.JumpIfX{Cond: bpf.JumpEqual, SkipTrue: 1, SkipFalse: 0},
	})

	requireError(t, err, "instruction 2: jeq x,1 flows past last instruction")
}

// Out of bounds fall through - last block doesn't end in return
func TestFallthroughOut(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
	})

	requireError(t, err, "instruction 0: ld #0 flows past last instruction")
}

// Jump normalization
func TestNormalizeJumps(t *testing.T) {
	insns := func(skipTrue, skipFalse uint8) []instruction {
		return toInstructions([]bpf.Instruction{
			bpf.JumpIf{Cond: bpf.JumpEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpNotEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpGreaterThan, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpGreaterThan, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpLessThan, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpLessThan, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpGreaterOrEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpLessOrEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpLessOrEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpBitsSet, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpBitsSet, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpBitsNotSet, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpBitsNotSet, SkipTrue: skipTrue, SkipFalse: skipFalse},
		})
	}

	// same insns, but with the conditions inverted
	invertedInsns := func(skipTrue, skipFalse uint8) []instruction {
		return toInstructions([]bpf.Instruction{
			bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpNotEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpLessOrEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpLessOrEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpGreaterOrEqual, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpLessThan, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpLessThan, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpGreaterThan, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpGreaterThan, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpBitsNotSet, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpBitsNotSet, SkipTrue: skipTrue, SkipFalse: skipFalse},

			bpf.JumpIf{Cond: bpf.JumpBitsSet, SkipTrue: skipTrue, SkipFalse: skipFalse},
			bpf.JumpIfX{Cond: bpf.JumpBitsSet, SkipTrue: skipTrue, SkipFalse: skipFalse},
		})
	}

	check := func(t *testing.T, input []instruction, expected []instruction) {
		normalizeJumps(input)

		if !reflect.DeepEqual(input, expected) {
			t.Fatalf("\nGot:\n%v\n\nExpected:\n%v", input, expected)
		}
	}

	// skipTrue only - no change
	check(t, insns(1, 0), insns(1, 0))

	// skipFalse & skipTrue - no change
	check(t, insns(1, 3), insns(1, 3))

	// skipFalse only - inverted
	check(t, insns(0, 3), invertedInsns(3, 0))
}

// instruction read / writes
func TestInstructionReadsRegA(t *testing.T) {
	checkMemoryStatus(t, map[bpf.Instruction]bool{
		bpf.ALUOpConstant{}: true,
		bpf.ALUOpX{}:        true,

		bpf.Jump{}:    false,
		bpf.JumpIf{}:  true,
		bpf.JumpIfX{}: true,

		bpf.LoadAbsolute{}:              false,
		bpf.LoadConstant{Dst: bpf.RegA}: false,
		bpf.LoadConstant{Dst: bpf.RegX}: false,
		bpf.LoadExtension{}:             false,
		bpf.LoadIndirect{}:              false,
		bpf.LoadMemShift{}:              false,
		bpf.LoadScratch{Dst: bpf.RegA}:  false,
		bpf.LoadScratch{Dst: bpf.RegX}:  false,

		bpf.NegateA{}: true,

		bpf.RetA{}:        true,
		bpf.RetConstant{}: false,

		bpf.StoreScratch{Src: bpf.RegA}: true,
		bpf.StoreScratch{Src: bpf.RegX}: false,

		bpf.TAX{}: true,
		bpf.TXA{}: false,
	}, func(insn bpf.Instruction) bool {
		return memReads(insn).regs[bpf.RegA]
	})
}

func TestInstructionWritesRegA(t *testing.T) {
	checkMemoryStatus(t, map[bpf.Instruction]bool{
		bpf.ALUOpConstant{}: true,
		bpf.ALUOpX{}:        true,

		bpf.Jump{}:    false,
		bpf.JumpIf{}:  false,
		bpf.JumpIfX{}: false,

		bpf.LoadAbsolute{}:              true,
		bpf.LoadConstant{Dst: bpf.RegA}: true,
		bpf.LoadConstant{Dst: bpf.RegX}: false,
		bpf.LoadExtension{}:             true,
		bpf.LoadIndirect{}:              true,
		bpf.LoadMemShift{}:              false,
		bpf.LoadScratch{Dst: bpf.RegA}:  true,
		bpf.LoadScratch{Dst: bpf.RegX}:  false,

		bpf.NegateA{}: true,

		bpf.RetA{}:        false,
		bpf.RetConstant{}: false,

		bpf.StoreScratch{Src: bpf.RegA}: false,
		bpf.StoreScratch{Src: bpf.RegX}: false,

		bpf.TAX{}: false,
		bpf.TXA{}: true,
	}, func(insn bpf.Instruction) bool {
		return memWrites(insn).regs[bpf.RegA]
	})
}

func TestInstructionReadsRegX(t *testing.T) {
	checkMemoryStatus(t, map[bpf.Instruction]bool{
		bpf.ALUOpConstant{}: false,
		bpf.ALUOpX{}:        true,

		bpf.Jump{}:    false,
		bpf.JumpIf{}:  false,
		bpf.JumpIfX{}: true,

		bpf.LoadAbsolute{}:              false,
		bpf.LoadConstant{Dst: bpf.RegA}: false,
		bpf.LoadConstant{Dst: bpf.RegX}: false,
		bpf.LoadExtension{}:             false,
		bpf.LoadIndirect{}:              true,
		bpf.LoadMemShift{}:              false,
		bpf.LoadScratch{Dst: bpf.RegA}:  false,
		bpf.LoadScratch{Dst: bpf.RegX}:  false,

		bpf.NegateA{}: false,

		bpf.RetA{}:        false,
		bpf.RetConstant{}: false,

		bpf.StoreScratch{Src: bpf.RegA}: false,
		bpf.StoreScratch{Src: bpf.RegX}: true,

		bpf.TAX{}: false,
		bpf.TXA{}: true,
	}, func(insn bpf.Instruction) bool {
		return memReads(insn).regs[bpf.RegX]
	})
}

func TestInstructionWritesRegX(t *testing.T) {
	checkMemoryStatus(t, map[bpf.Instruction]bool{
		bpf.ALUOpConstant{}: false,
		bpf.ALUOpX{}:        false,

		bpf.Jump{}:    false,
		bpf.JumpIf{}:  false,
		bpf.JumpIfX{}: false,

		bpf.LoadAbsolute{}:              false,
		bpf.LoadConstant{Dst: bpf.RegA}: false,
		bpf.LoadConstant{Dst: bpf.RegX}: true,
		bpf.LoadExtension{}:             false,
		bpf.LoadIndirect{}:              false,
		bpf.LoadMemShift{}:              true,
		bpf.LoadScratch{Dst: bpf.RegA}:  false,
		bpf.LoadScratch{Dst: bpf.RegX}:  true,

		bpf.NegateA{}: false,

		bpf.RetA{}:        false,
		bpf.RetConstant{}: false,

		bpf.StoreScratch{Src: bpf.RegA}: false,
		bpf.StoreScratch{Src: bpf.RegX}: false,

		bpf.TAX{}: true,
		bpf.TXA{}: false,
	}, func(insn bpf.Instruction) bool {
		return memWrites(insn).regs[bpf.RegX]
	})
}

func TestInstructionReadsScratch(t *testing.T) {
	checkMemoryStatus(t, map[bpf.Instruction]bool{
		bpf.ALUOpConstant{}: false,
		bpf.ALUOpX{}:        false,

		bpf.Jump{}:    false,
		bpf.JumpIf{}:  false,
		bpf.JumpIfX{}: false,

		bpf.LoadAbsolute{}:                   false,
		bpf.LoadConstant{Dst: bpf.RegA}:      false,
		bpf.LoadConstant{Dst: bpf.RegX}:      false,
		bpf.LoadExtension{}:                  false,
		bpf.LoadIndirect{}:                   false,
		bpf.LoadMemShift{}:                   false,
		bpf.LoadScratch{Dst: bpf.RegA, N: 3}: true,
		bpf.LoadScratch{Dst: bpf.RegX, N: 3}: true,

		bpf.NegateA{}: false,

		bpf.RetA{}:        false,
		bpf.RetConstant{}: false,

		bpf.StoreScratch{Src: bpf.RegA, N: 3}: false,
		bpf.StoreScratch{Src: bpf.RegX, N: 3}: false,

		bpf.TAX{}: false,
		bpf.TXA{}: false,
	}, func(insn bpf.Instruction) bool {
		return memReads(insn).scratch[3]
	})
}

func TestInstructionWritesScratch(t *testing.T) {
	checkMemoryStatus(t, map[bpf.Instruction]bool{
		bpf.ALUOpConstant{}: false,
		bpf.ALUOpX{}:        false,

		bpf.Jump{}:    false,
		bpf.JumpIf{}:  false,
		bpf.JumpIfX{}: false,

		bpf.LoadAbsolute{}:                   false,
		bpf.LoadConstant{Dst: bpf.RegA}:      false,
		bpf.LoadConstant{Dst: bpf.RegX}:      false,
		bpf.LoadExtension{}:                  false,
		bpf.LoadIndirect{}:                   false,
		bpf.LoadMemShift{}:                   false,
		bpf.LoadScratch{Dst: bpf.RegA, N: 3}: false,
		bpf.LoadScratch{Dst: bpf.RegX, N: 3}: false,

		bpf.NegateA{}: false,

		bpf.RetA{}:        false,
		bpf.RetConstant{}: false,

		bpf.StoreScratch{Src: bpf.RegA, N: 3}: true,
		bpf.StoreScratch{Src: bpf.RegX, N: 3}: true,

		bpf.TAX{}: false,
		bpf.TXA{}: false,
	}, func(insn bpf.Instruction) bool {
		return memWrites(insn).scratch[3]
	})
}

func checkMemoryStatus(t *testing.T, expected map[bpf.Instruction]bool, test func(bpf.Instruction) bool) {
	t.Helper()

	for insn, value := range expected {
		if test(insn) != value {
			t.Fatalf("Instruction %v expected %v got %v", insn, value, test(insn))
		}
	}
}

// reg uninitialized and used in one block
func TestUninitializedReg(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 1, insns)

	err := initializeMemory(blocks)
	if err != nil {
		t.Fatal(err)
	}

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: bpf.LoadConstant{Dst: bpf.RegA, Val: 0}}},
		insns,
	), nil)
}

// reg initialized in one branch, but not the other
func TestPartiallyUninitializedReg(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadConstant{Dst: bpf.RegA, Val: 3},
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.TAX{}, // initialize RegX
		// fall through to block 2

		// block 2
		/* 3 */ bpf.TXA{}, // RegX used potentially uninitialized
		/* 4 */ bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 3, insns)

	err := initializeMemory(blocks)
	if err != nil {
		t.Fatal(err)
	}

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: bpf.LoadConstant{Dst: bpf.RegX, Val: 0}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:3], nil)
	matchBlock(t, blocks[2], insns[3:], nil)
}

// scratch reg uninitialized and used in one block
func TestUninitializedScratch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadScratch{Dst: bpf.RegA, N: 2},
		/* 1 */ bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 1, insns)
	requireError(t, initializeMemory(blocks), "instruction 0: ld M[2] reads potentially uninitialized scratch register M[2]")
}

// scratch reg initialized in one branch, but not the other
func TestPartiallyUninitializedScratch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadConstant{Dst: bpf.RegA, Val: 3},
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.StoreScratch{Src: bpf.RegA, N: 5}, // initialize m[2]
		// fall through to block 2

		// block 2
		/* 3 */ bpf.LoadScratch{Dst: bpf.RegA, N: 5},
		/* 4 */ bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 3, insns)
	requireError(t, initializeMemory(blocks), "instruction 3: ld M[5] reads potentially uninitialized scratch register M[5]")
}

// Test block splitting
func TestBlocksJump(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		/* 0 */ bpf.LoadConstant{Dst: bpf.RegX, Val: 3},
		/* 1 */ bpf.Jump{Skip: 1},
		/* 2 */ bpf.RetConstant{Val: 0}, // unreachable
		/* 3 */ bpf.RetConstant{Val: 1},
	})

	blocks := mustSplitBlocks(t, 2, insns)

	// Unreachable code will never make it into a block
	matchBlock(t, blocks[0], insns[:2], map[pos]*block{3: blocks[1]})
	matchBlock(t, blocks[1], insns[3:], map[pos]*block{})
}

func TestBlocksJumpIf(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		/* 0 */ bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 1, SkipFalse: 0},
		/* 2 */ bpf.RetConstant{Val: 0},
		/* 3 */ bpf.RetConstant{Val: 1},
	})

	blocks := mustSplitBlocks(t, 3, insns)

	matchBlock(t, blocks[0], insns[0:2], map[pos]*block{2: blocks[1], 3: blocks[2]})
	matchBlock(t, blocks[1], insns[2:3], map[pos]*block{})
	matchBlock(t, blocks[2], insns[3:4], map[pos]*block{})
}

func TestBlocksJumpIfX(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		/* 0 */ bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
		/* 1 */ bpf.LoadConstant{Dst: bpf.RegX, Val: 3},
		/* 2 */ bpf.JumpIfX{Cond: bpf.JumpEqual, SkipTrue: 1, SkipFalse: 0},
		/* 3 */ bpf.RetConstant{Val: 0},
		/* 4 */ bpf.RetConstant{Val: 1},
	})

	blocks := mustSplitBlocks(t, 3, insns)

	matchBlock(t, blocks[0], insns[0:3], map[pos]*block{3: blocks[1], 4: blocks[2]})
	matchBlock(t, blocks[1], insns[3:4], map[pos]*block{})
	matchBlock(t, blocks[2], insns[4:5], map[pos]*block{})
}

// Division by constant 0
func TestDivisionByZeroImm(t *testing.T) {
	test := func(t *testing.T, op bpf.ALUOp) {
		t.Helper()

		blocks := mustSplitBlocks(t, 1, toInstructions([]bpf.Instruction{
			bpf.ALUOpConstant{Op: op, Val: 0},
			bpf.RetConstant{},
		}))

		requireError(t, addDivideByZeroGuards(blocks), "divides by 0")
	}

	test(t, bpf.ALUOpDiv)
	test(t, bpf.ALUOpMod)
}

// Division by RegX
func TestDivisionByZeroX(t *testing.T) {
	test := func(t *testing.T, op bpf.ALUOp) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			bpf.LoadAbsolute{Size: 1, Off: 0},
			bpf.TXA{},
			bpf.ALUOpX{Op: op},
			bpf.RetConstant{},
		})

		blocks := mustSplitBlocks(t, 1, insns)

		err := addDivideByZeroGuards(blocks)
		if err != nil {
			t.Fatal(err)
		}

		matchBlock(t, blocks[0], join(
			insns[:2],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[2:],
		), nil)
	}

	test(t, bpf.ALUOpDiv)
	test(t, bpf.ALUOpMod)
}

// Division by RegX twice in same block
func TestDivisionByZeroXTwice(t *testing.T) {
	test := func(t *testing.T, op bpf.ALUOp) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			bpf.LoadAbsolute{Size: 1, Off: 0},
			bpf.TXA{},
			bpf.ALUOpX{Op: op},
			bpf.ALUOpX{Op: op},
			bpf.RetConstant{},
		})

		blocks := mustSplitBlocks(t, 1, insns)

		err := addDivideByZeroGuards(blocks)
		if err != nil {
			t.Fatal(err)
		}

		matchBlock(t, blocks[0], join(
			insns[:2],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[2:],
		), nil)
	}

	test(t, bpf.ALUOpDiv)
	test(t, bpf.ALUOpMod)
}

// Division by RegX after RegX clobbered
func TestDivisionByZeroXConstant(t *testing.T) {
	test := func(t *testing.T, op bpf.ALUOp) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			bpf.LoadAbsolute{Size: 1, Off: 0},
			bpf.TXA{},
			bpf.ALUOpX{Op: op},

			bpf.LoadConstant{Dst: bpf.RegX}, // Clobber X
			bpf.ALUOpX{Op: op},

			bpf.RetConstant{},
		})

		blocks := mustSplitBlocks(t, 1, insns)

		err := addDivideByZeroGuards(blocks)
		if err != nil {
			t.Fatal(err)
		}

		matchBlock(t, blocks[0], join(
			insns[:2],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[2:4],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[4:],
		), nil)
	}

	test(t, bpf.ALUOpDiv)
	test(t, bpf.ALUOpMod)
}

func TestDivisionByZeroXMemShift(t *testing.T) {
	test := func(t *testing.T, op bpf.ALUOp) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			bpf.LoadAbsolute{Size: 1, Off: 0},
			bpf.TXA{},
			bpf.ALUOpX{Op: op},

			bpf.LoadMemShift{Off: 2}, // Clobber X
			bpf.ALUOpX{Op: op},

			bpf.RetConstant{},
		})

		blocks := mustSplitBlocks(t, 1, insns)

		err := addDivideByZeroGuards(blocks)
		if err != nil {
			t.Fatal(err)
		}

		matchBlock(t, blocks[0], join(
			insns[:2],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[2:4],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[4:],
		), nil)
	}

	test(t, bpf.ALUOpDiv)
	test(t, bpf.ALUOpMod)
}

func TestDivisionByZeroXTXA(t *testing.T) {
	test := func(t *testing.T, op bpf.ALUOp) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			bpf.LoadAbsolute{Size: 1, Off: 0},
			bpf.TXA{},
			bpf.ALUOpX{Op: op},

			bpf.TAX{}, // Clobber X
			bpf.ALUOpX{Op: op},

			bpf.RetConstant{},
		})

		blocks := mustSplitBlocks(t, 1, insns)

		err := addDivideByZeroGuards(blocks)
		if err != nil {
			t.Fatal(err)
		}

		matchBlock(t, blocks[0], join(
			insns[:2],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[2:4],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[4:],
		), nil)
	}

	test(t, bpf.ALUOpDiv)
	test(t, bpf.ALUOpMod)
}

// Check we use parent guards
func TestDivisionByZeroParentsOK(t *testing.T) {
	test := func(t *testing.T, op bpf.ALUOp) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			// block 0
			/* 0 */ bpf.LoadAbsolute{Size: 1, Off: 0},
			/* 1 */ bpf.TXA{},
			/* 2 */ bpf.ALUOpX{Op: op},
			/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 2}, // jump to block 1 or 2

			// block 1
			/* 4 */ bpf.LoadAbsolute{Size: 1, Off: 1},
			/* 5 */ bpf.Jump{Skip: 1}, // jump to block 3

			// block 2
			/* 6 */ bpf.LoadAbsolute{Size: 1, Off: 2},
			// fall through to block 3

			// block 3
			/* 7 */ bpf.ALUOpX{Op: op},
			/* 8 */ bpf.RetConstant{},
		})

		blocks := mustSplitBlocks(t, 4, insns)

		err := addDivideByZeroGuards(blocks)
		if err != nil {
			t.Fatal(err)
		}

		matchBlock(t, blocks[0], join(
			insns[:2],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[2:4],
		), nil)
		matchBlock(t, blocks[1], insns[4:6], nil)
		matchBlock(t, blocks[2], insns[6:7], nil)
		matchBlock(t, blocks[3], insns[7:], nil)
	}

	test(t, bpf.ALUOpDiv)
	test(t, bpf.ALUOpMod)
}

// Check we add new guards with partial parent guards
func TestDivisionByZeroParentsNOK(t *testing.T) {
	test := func(t *testing.T, op bpf.ALUOp) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			// block 0
			/* 0 */ bpf.LoadAbsolute{Size: 1, Off: 0},
			/* 1 */ bpf.TXA{},
			/* 2 */ bpf.ALUOpX{Op: op},
			/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 2}, // jump to block 1 or 2

			// block 1
			/* 4 */ bpf.LoadMemShift{Off: 1}, // clobber X
			/* 5 */ bpf.Jump{Skip: 1}, // jump to block 3

			// block 2
			/* 6 */ bpf.LoadAbsolute{Size: 1, Off: 2},
			// fall through to block 3

			// block 3
			/* 7 */ bpf.ALUOpX{Op: op},
			/* 8 */ bpf.RetConstant{},
		})

		blocks := mustSplitBlocks(t, 4, insns)

		err := addDivideByZeroGuards(blocks)
		if err != nil {
			t.Fatal(err)
		}

		matchBlock(t, blocks[0], join(
			insns[:2],
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[2:4],
		), nil)
		matchBlock(t, blocks[1], insns[4:6], nil)
		matchBlock(t, blocks[2], insns[6:7], nil)
		matchBlock(t, blocks[3], join(
			[]instruction{{Instruction: checkXNotZero{}}},
			insns[7:],
		), nil)
	}

	test(t, bpf.ALUOpDiv)
	test(t, bpf.ALUOpMod)
}

func TestRewriteLargePacketOffsets(t *testing.T) {
	testOK := func(t *testing.T, load bpf.Instruction) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			load,
			bpf.RetA{},
		})

		blocks := mustSplitBlocks(t, 1, insns)
		rewriteLargePacketOffsets(&blocks)

		matchBlock(t, blocks[0], insns, nil)
	}

	testOOB := func(t *testing.T, load bpf.Instruction) {
		t.Helper()

		insns := toInstructions([]bpf.Instruction{
			load,
			bpf.RetA{},
		})

		blocks := mustSplitBlocks(t, 1, insns)
		rewriteLargePacketOffsets(&blocks)

		matchBlock(t, blocks[0], []instruction{
			{Instruction: bpf.RetConstant{}},
		}, nil)
	}

	testOK(t, bpf.LoadAbsolute{Size: 1, Off: 65534})
	testOOB(t, bpf.LoadAbsolute{Size: 1, Off: 65535})
	testOK(t, bpf.LoadAbsolute{Size: 2, Off: 65533})
	testOOB(t, bpf.LoadAbsolute{Size: 2, Off: 65534})
	testOK(t, bpf.LoadAbsolute{Size: 4, Off: 65531})
	testOOB(t, bpf.LoadAbsolute{Size: 4, Off: 65532})

	testOK(t, bpf.LoadMemShift{Off: 65534})
	testOOB(t, bpf.LoadMemShift{Off: 65535})
}

// Test unreachable blocks due to large packet offsets are removed.
func TestRewriteLargePacketOffsetsDeadBlock(t *testing.T) {
	filter := []bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadAbsolute{Size: 4, Off: 2},
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 2, SkipTrue: 6}, // jump to block 1 or 6

		// block 1
		/* 2 */ bpf.JumpIf{Cond: bpf.JumpLessThan, Val: 2, SkipTrue: 3}, // jump to block 2 or 3

		// block 2
		/* 3 */ bpf.LoadAbsolute{Size: 1, Off: 65598},
		/* 4 */ bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 4},
		/* 5 */ bpf.Jump{Skip: 1}, // jump to block 4

		// block 3
		/* 6 */ bpf.LoadAbsolute{Size: 4, Off: 65532},

		// block 4
		/* 7 */ bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 2},

		// block 5
		/* 8 */ bpf.RetA{},
	}
	insns := toInstructions(filter)

	blocks := mustSplitBlocks(t, 6, insns)
	rewriteLargePacketOffsets(&blocks)
	if len(blocks) != 5 {
		t.Fatalf("expected 5 blocks, got %v", blocks)
	}

	matchBlock(t, blocks[0], insns[0:2], nil)
	matchBlock(t, blocks[1], insns[2:3], nil)
	matchBlock(t, blocks[2], []instruction{
		{Instruction: bpf.RetConstant{}},
	}, nil)
	matchBlock(t, blocks[3], []instruction{
		{Instruction: bpf.RetConstant{}},
	}, nil)
	// block 4 is unreachable and removed, block 5 replaces it
	matchBlock(t, blocks[4], insns[8:], nil)

	// Make sure this is accepted by the verifier.
	checkBackends(t, filter, []byte{}, noMatch)
}

// Test absolute guards
func TestAbsoluteGuardSize(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		bpf.LoadAbsolute{Size: 4, Off: 10}, // guard 14
		bpf.LoadAbsolute{Size: 1, Off: 10}, // guard 11
		bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 1, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardAbsolute{end: 14}}},
		insns,
	), nil)
}

// Check we don't add a guard if there are no packet loads
func TestNoAbsoluteGuard(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 23},
		bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 1, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], insns, nil)
}

// Check we use parent guards if they're big enough
func TestAbsoluteGuardParentsOK(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadAbsolute{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 2}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.LoadAbsolute{Size: 4, Off: 10}, // guard 14
		/* 3 */ bpf.Jump{Skip: 1}, // jump to block 3

		// block 2
		/* 4 */ bpf.LoadAbsolute{Size: 2, Off: 8}, // guard 10
		// fall through to block 3

		// block 3
		/* 5 */ bpf.LoadAbsolute{Size: 1, Off: 9}, // guard 10
		/* 6 */ bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardAbsolute{end: 14}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:4], nil)
	matchBlock(t, blocks[2], insns[4:5], nil)
	matchBlock(t, blocks[3], insns[5:], nil)
}

// Check the parent guard is extended to cover children that always return no match
func TestAbsoluteGuardParentNoMatch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadAbsolute{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 1 or 3

		// block 1
		/* 2 */ bpf.LoadAbsolute{Size: 4, Off: 12}, // guard 16
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 2 or 3

		// block 2
		/* 4 */ bpf.RetA{}, // potential match

		// block 3
		/* 5 */ bpf.RetConstant{}, // no match
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardAbsolute{end: 16}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:4], nil)
	matchBlock(t, blocks[2], insns[4:5], nil)
	matchBlock(t, blocks[3], insns[5:], nil)
}

// Check the parent guard is extended to cover indirect children that always return no match
func TestAbsoluteGuardParentDeepNoMatch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadAbsolute{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 5}, // jump to block 1 or 4

		// block 1
		/* 2 */ bpf.LoadAbsolute{Size: 4, Off: 12}, // guard 16
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 2 or 4

		// block 2
		/* 4 */ bpf.LoadAbsolute{Size: 4, Off: 14}, // guard 18
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 3 or 4

		// block 3
		/* 6 */ bpf.RetA{}, // potential match

		// block 4
		/* 7 */ bpf.RetConstant{}, // no match
	})

	blocks := mustSplitBlocks(t, 5, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardAbsolute{end: 18}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:4], nil)
	matchBlock(t, blocks[2], insns[4:6], nil)
	matchBlock(t, blocks[3], insns[6:7], nil)
	matchBlock(t, blocks[4], insns[7:], nil)
}

// Check the parent guard isn't extended to cover children that could match
func TestAbsoluteGuardParentMatch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadAbsolute{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 2}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.LoadAbsolute{Size: 4, Off: 11}, // guard 15
		/* 3 */ bpf.RetA{}, // potential match

		// block 2
		/* 4 */ bpf.LoadAbsolute{Size: 1, Off: 15}, // guard 16
		/* 5 */ bpf.RetConstant{}, // no match
	})

	blocks := mustSplitBlocks(t, 3, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardAbsolute{end: 15}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:4], nil)
	matchBlock(t, blocks[2], join(
		[]instruction{{Instruction: packetGuardAbsolute{end: 16}}},
		insns[4:],
	), nil)
}

func TestIndirectGuardSize(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		bpf.LoadIndirect{Size: 1, Off: 10}, // guard 11
		bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 1, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardIndirect{end: 14}}},
		insns,
	), nil)
}

// Check we don't add a guard if there are no packet loads
func TestNoIndirectGuard(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 23},
		bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 1, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], insns, nil)
}

// Check we add new guards if current is not big enough due to RegX clobber
func TestIndirectGuardClobber(t *testing.T) {
	check := func(clobber bpf.Instruction) func(t *testing.T) {
		return func(t *testing.T) {
			insns := toInstructions([]bpf.Instruction{
				bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
				clobber,                            // clobber X, packet guard no longer valid
				bpf.LoadIndirect{Size: 2, Off: 8},  // guard 10
				bpf.RetA{},
			})

			blocks := mustSplitBlocks(t, 1, insns)

			addIndirectPacketGuards(blocks)

			matchBlock(t, blocks[0], join(
				[]instruction{{Instruction: packetGuardIndirect{end: 14}}},
				insns[:2],
				[]instruction{{Instruction: packetGuardIndirect{end: 10}}},
				insns[2:],
			), nil)
		}
	}

	t.Run("constant", check(bpf.LoadConstant{Dst: bpf.RegX}))
	t.Run("scratch", check(bpf.LoadScratch{Dst: bpf.RegX}))
	t.Run("memshift", check(bpf.LoadMemShift{Off: 2}))
}

// #20: we didn't always emit packet guards for the last instruction of a block.
func TestIndirectGuardClobberLast(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.LoadConstant{Dst: bpf.RegX, Val: 23},
		// fall through to block 2

		// block 2
		/* 3 */ bpf.LoadIndirect{Size: 1, Off: 10}, // guard 11
		/* 4 */ bpf.TXA{},
		/* 5 */ bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 3, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardIndirect{end: 14}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:3], nil)
	matchBlock(t, blocks[2], join(
		[]instruction{{Instruction: packetGuardIndirect{end: 11}}},
		insns[3:],
	), nil)
}

// Check we use parent guards if they're long / big enough
func TestIndirectGuardParentsOK(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 2}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 3 */ bpf.Jump{Skip: 1}, // jump to block 3

		// block 2
		/* 4 */ bpf.LoadIndirect{Size: 2, Off: 8}, // guard 10
		// fall through to block 3

		// block 3
		/* 5 */ bpf.LoadIndirect{Size: 1, Off: 9}, // guard 10
		/* 6 */ bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardIndirect{end: 14}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:4], nil)
	matchBlock(t, blocks[2], insns[4:5], nil)
	matchBlock(t, blocks[3], insns[5:], nil)
}

// Check the parent guard is extended to cover children that always return no match
func TestIndirectGuardParentNoMatch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 1 or 3

		// block 1
		/* 2 */ bpf.LoadIndirect{Size: 4, Off: 12}, // guard 16
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 2 or 3

		// block 2
		/* 4 */ bpf.RetA{}, // potential match

		// block 3
		/* 5 */ bpf.RetConstant{}, // no match
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardIndirect{end: 16}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:4], nil)
	matchBlock(t, blocks[2], insns[4:5], nil)
	matchBlock(t, blocks[3], insns[5:], nil)
}

// Check the parent guard is extended to cover indirect children that always return no match
func TestIndirectGuardParentDeepNoMatch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 5}, // jump to block 1 or 4

		// block 1
		/* 2 */ bpf.LoadIndirect{Size: 4, Off: 12}, // guard 16
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 2 or 4

		// block 2
		/* 4 */ bpf.LoadIndirect{Size: 4, Off: 14}, // guard 18
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 3 or 4

		// block 3
		/* 6 */ bpf.RetA{}, // potential match

		// block 4
		/* 7 */ bpf.RetConstant{}, // no match
	})

	blocks := mustSplitBlocks(t, 5, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardIndirect{end: 18}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:4], nil)
	matchBlock(t, blocks[2], insns[4:6], nil)
	matchBlock(t, blocks[3], insns[6:7], nil)
	matchBlock(t, blocks[4], insns[7:], nil)
}

// Check the parent guard isn't extended to cover children that could match
func TestIndirectGuardParentMatch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 2}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.LoadIndirect{Size: 4, Off: 11}, // guard 15
		/* 3 */ bpf.RetA{}, // potential match

		// block 2
		/* 4 */ bpf.LoadIndirect{Size: 1, Off: 15}, // guard 16
		/* 5 */ bpf.RetConstant{}, // no match
	})

	blocks := mustSplitBlocks(t, 3, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], join(
		[]instruction{{Instruction: packetGuardIndirect{end: 15}}},
		insns[:2],
	), nil)
	matchBlock(t, blocks[1], insns[2:4], nil)
	matchBlock(t, blocks[2], join(
		[]instruction{{Instruction: packetGuardIndirect{end: 16}}},
		insns[4:],
	), nil)
}

// Check we add new guards if one of the parent guards is not big enough due to RegX clobber
func TestIndirectGuardParentClobber(t *testing.T) {
	check := func(clobber bpf.Instruction) func(t *testing.T) {
		return func(t *testing.T) {
			insns := toInstructions([]bpf.Instruction{
				// block 0
				/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
				/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 1 or 2

				// block 1
				/* 2 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
				/* 3 */ clobber, // clobber X, packet guard no longer valid
				/* 4 */ bpf.Jump{Skip: 1}, // jump to block 3

				// block 2
				/* 5 */ bpf.LoadIndirect{Size: 2, Off: 8}, // guard 10
				// fall through to block 3

				// block 3
				/* 6 */ bpf.LoadIndirect{Size: 1, Off: 1}, // guard 2
				/* 7 */ bpf.RetA{},
			})

			blocks := mustSplitBlocks(t, 4, insns)

			addIndirectPacketGuards(blocks)

			matchBlock(t, blocks[0], join(
				[]instruction{{Instruction: packetGuardIndirect{end: 14}}},
				insns[:2],
			), nil)
			matchBlock(t, blocks[1], insns[2:5], nil)
			matchBlock(t, blocks[2], insns[5:6], nil)
			matchBlock(t, blocks[3], join(
				[]instruction{{Instruction: packetGuardIndirect{end: 2}}},
				insns[6:],
			), nil)
		}
	}

	t.Run("constant", check(bpf.LoadConstant{Dst: bpf.RegX}))
	t.Run("scratch", check(bpf.LoadScratch{Dst: bpf.RegX}))
	t.Run("memshift", check(bpf.LoadMemShift{Off: 2}))
}

// Check we don't extend guards past RegX clobbers
func TestIndirectGuardExtendClobber(t *testing.T) {
	check := func(clobber bpf.Instruction) func(t *testing.T) {
		return func(t *testing.T) {
			insns := toInstructions([]bpf.Instruction{
				// block 0
				/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
				/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 5}, // jump to block 1 or 4

				// block 1
				/* 2 */ clobber, // clobber X, packet guard no longer valid
				/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 2 or 4

				// block 2
				/* 4 */ bpf.LoadIndirect{Size: 4, Off: 14}, // guard 18
				/* 5 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 3 or 4

				// block 3
				/* 6 */ bpf.RetA{}, // potential match

				// block 4
				/* 7 */ bpf.RetConstant{}, // no match
			})

			blocks := mustSplitBlocks(t, 5, insns)

			addIndirectPacketGuards(blocks)

			matchBlock(t, blocks[0], join(
				[]instruction{{Instruction: packetGuardIndirect{end: 14}}},
				insns[:2],
			), nil)
			matchBlock(t, blocks[1], insns[2:4], nil)
			matchBlock(t, blocks[2], join(
				[]instruction{{Instruction: packetGuardIndirect{end: 18}}},
				insns[4:6],
			), nil)
			matchBlock(t, blocks[3], insns[6:7], nil)
			matchBlock(t, blocks[4], insns[7:], nil)
		}
	}

	t.Run("constant", check(bpf.LoadConstant{Dst: bpf.RegX}))
	t.Run("scratch", check(bpf.LoadScratch{Dst: bpf.RegX}))
	t.Run("memshift", check(bpf.LoadMemShift{Off: 2}))
}

func join(insns ...[]instruction) []instruction {
	res := []instruction{}

	for _, insn := range insns {
		res = append(res, insn...)
	}

	return res
}

// matchBlock checks a block has the given instructions and jumps
func matchBlock(t *testing.T, b *block, expected []instruction, jumps map[pos]*block) {
	t.Helper()

	if !reflect.DeepEqual(expected, b.insns) {
		t.Fatalf("expected instructions %v, got %v", expected, b.insns)
	}

	if jumps != nil && !reflect.DeepEqual(jumps, b.jumps) {
		t.Fatalf("expected jumps %v, got %v", jumps, b.jumps)
	}
}

func mustSplitBlocks(t *testing.T, blockCount int, insns []instruction) []*block {
	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed:", err)
	}

	if len(blocks) != blockCount {
		t.Fatalf("expected %d blocks got %d", blockCount, len(blocks))
	}

	return blocks
}
