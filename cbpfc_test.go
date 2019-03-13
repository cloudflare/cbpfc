package cbpfc

import (
	"reflect"
	"testing"

	"golang.org/x/net/bpf"
)

// Make sure we bail out with 0 instructions
func TestZero(t *testing.T) {
	_, err := compile([]bpf.Instruction{})

	if err == nil {
		t.Fatal("zero length instructions compiled", err)
	}
}

func TestRaw(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.RawInstruction{},
	})

	if err == nil {
		t.Fatal("raw instruction accepted", err)
	}
}

func TestExtension(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadExtension{},
	})

	if err == nil {
		t.Fatal("load extension accepted", err)
	}
}

// Test out of bound jumps
func TestJumpOut(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegX, Val: 0},
		bpf.Jump{Skip: 0},
	})

	if err == nil {
		t.Fatal("out of bounds skip compiled")
	}
}

func TestJumpIfOut(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 2, SkipTrue: 0, SkipFalse: 1},
	})

	if err == nil {
		t.Fatal("out of bounds skip compiled")
	}
}

func TestJumpIfXOut(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 3},
		bpf.JumpIfX{Cond: bpf.JumpEqual, SkipTrue: 1, SkipFalse: 0},
	})

	if err == nil {
		t.Fatal("out of bounds skip compiled")
	}
}

// Out of bounds fall through - last block doesn't end in return
func TestFallthroughOut(t *testing.T) {
	_, err := compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
	})

	if err == nil {
		t.Fatal("out of bounds fall through compiled")
	}
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

// scratch reg uninitialized and used in one block
func TestUninitializedScratch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadScratch{Dst: bpf.RegA, N: 2},
		/* 1 */ bpf.RetA{},
	})

	blocks := mustSplitBlocks(t, 1, insns)

	initializeMemory(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: initializeScratch{N: 2}}}, insns...), nil)
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

	initializeMemory(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: initializeScratch{N: 5}}}, insns[:2]...), nil)
	matchBlock(t, blocks[1], insns[2:3], nil)
	matchBlock(t, blocks[2], insns[3:], nil)
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

		err := addDivideByZeroGuards(blocks)
		if err == nil {
			t.Fatal("Division by constant 0 not rejected")
		}
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

// Test absolute guards
func TestAbsoluteGuardSize(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		bpf.LoadAbsolute{Size: 4, Off: 10}, // guard 14
		bpf.LoadAbsolute{Size: 1, Off: 10}, // guard 11
		bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 1, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardAbsolute{guard: 14}}}, insns...), map[pos]*block{})
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

// Check we use parent guards if they're long / big enough
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
		/* 6 */ bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardAbsolute{guard: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 4: blocks[2]})
	matchBlock(t, blocks[1], insns[2:4], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[2], insns[4:5], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[3], insns[5:], map[pos]*block{})
}

// Check we add new guards if parent guards are not long / big enough
func TestAbsoluteGuardParentsNOK(t *testing.T) {
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
		/* 5 */ bpf.LoadAbsolute{Size: 1, Off: 15}, // guard 16
		/* 6 */ bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addAbsolutePacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardAbsolute{guard: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 4: blocks[2]})
	matchBlock(t, blocks[1], insns[2:4], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[2], insns[4:5], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardAbsolute{guard: 16}}}, insns[5:]...), map[pos]*block{})
}

func TestIndirectGuardSize(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		bpf.LoadIndirect{Size: 1, Off: 10}, // guard 11
		bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 1, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{guard: 14}}}, insns...), map[pos]*block{})
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

// Check we add new guards if current is not long / big enough due to RegX clobber
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
				[]instruction{{Instruction: packetGuardIndirect{guard: 14}}},
				insns[:2],
				[]instruction{{Instruction: packetGuardIndirect{guard: 10}}},
				insns[2:],
			), nil)
		}
	}

	t.Run("constant", check(bpf.LoadConstant{Dst: bpf.RegX}))
	t.Run("scratch", check(bpf.LoadScratch{Dst: bpf.RegX}))
	t.Run("memshift", check(bpf.LoadMemShift{Off: 2}))
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
		/* 6 */ bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{guard: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 4: blocks[2]})
	matchBlock(t, blocks[1], insns[2:4], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[2], insns[4:5], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[3], insns[5:], map[pos]*block{})
}

// Check we add new guards if parent guards are not long / big enough
func TestIndirectGuardParentsNOK(t *testing.T) {
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
		/* 5 */ bpf.LoadIndirect{Size: 1, Off: 15}, // guard 16
		/* 6 */ bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{guard: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 4: blocks[2]})
	matchBlock(t, blocks[1], insns[2:4], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[2], insns[4:5], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardIndirect{guard: 16}}}, insns[5:]...), map[pos]*block{})
}

// Check we add new guards if one of the parent guards is not long / big enough due to LoadConstant clobber
func TestIndirectGuardClobberConstant(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 3 */ bpf.LoadConstant{Dst: bpf.RegX}, // clobber X, packet guard no longer valid
		/* 4 */ bpf.Jump{Skip: 1}, // jump to block 3

		// block 2
		/* 5 */ bpf.LoadIndirect{Size: 2, Off: 8}, // guard 10
		// fall through to block 3

		// block 3
		/* 6 */ bpf.LoadIndirect{Size: 1, Off: 1}, // guard 2
		/* 7 */ bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{guard: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 5: blocks[2]})
	matchBlock(t, blocks[1], insns[2:5], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[2], insns[5:6], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardIndirect{guard: 2}}}, insns[6:]...), map[pos]*block{})
}

// Check we add new guards if one of the parent guards is not long / big enough due to LoadScratch clobber
func TestIndirectGuardClobberScratch(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 3 */ bpf.LoadScratch{Dst: bpf.RegX}, // clobber X, packet guard no longer valid
		/* 4 */ bpf.Jump{Skip: 1}, // jump to block 3

		// block 2
		/* 5 */ bpf.LoadIndirect{Size: 2, Off: 8}, // guard 10
		// fall through to block 3

		// block 3
		/* 6 */ bpf.LoadIndirect{Size: 1, Off: 1}, // guard 2
		/* 7 */ bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{guard: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 5: blocks[2]})
	matchBlock(t, blocks[1], insns[2:5], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[2], insns[5:6], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardIndirect{guard: 2}}}, insns[6:]...), map[pos]*block{})
}

// Check we add new guards if one of the parent guards is not long / big enough due to LoadMemShift clobber
func TestIndirectGuardClobberMemShift(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		// block 0
		/* 0 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 3}, // jump to block 1 or 2

		// block 1
		/* 2 */ bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		/* 3 */ bpf.LoadMemShift{Off: 2}, // clobber X, packet guard no longer valid. requires absolute packet guard
		/* 4 */ bpf.Jump{Skip: 1}, // jump to block 3

		// block 2
		/* 5 */ bpf.LoadIndirect{Size: 2, Off: 8}, // guard 10
		// fall through to block 3

		// block 3
		/* 6 */ bpf.LoadIndirect{Size: 1, Off: 1}, // guard 2
		/* 7 */ bpf.RetConstant{},
	})

	blocks := mustSplitBlocks(t, 4, insns)

	addAbsolutePacketGuards(blocks)
	addIndirectPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{guard: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 5: blocks[2]})
	matchBlock(t, blocks[1], append([]instruction{{Instruction: packetGuardAbsolute{guard: 3}}}, insns[2:5]...), map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[2], insns[5:6], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardIndirect{guard: 2}}}, insns[6:]...), map[pos]*block{})
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
