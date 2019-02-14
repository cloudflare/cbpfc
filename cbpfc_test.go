package cbpfc

import (
	"reflect"
	"testing"

	"golang.org/x/net/bpf"
)

// Make sure we bail out with 0 instructions
func TestZero(t *testing.T) {
	_, err := Compile([]bpf.Instruction{}, "test")

	if err == nil {
		t.Fatal("zero length instructions compiled", err)
	}
}

// Make sure we can compile every possible instruction
func TestAll(t *testing.T) {
	_, err := Compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA},
		bpf.LoadConstant{Dst: bpf.RegX},

		bpf.LoadScratch{Dst: bpf.RegA},
		bpf.LoadScratch{Dst: bpf.RegX},

		bpf.LoadAbsolute{Size: 1},
		bpf.LoadAbsolute{Size: 2},
		bpf.LoadAbsolute{Size: 4},

		bpf.LoadIndirect{Size: 1},
		bpf.LoadIndirect{Size: 2},
		bpf.LoadIndirect{Size: 4},

		bpf.LoadMemShift{},

		bpf.StoreScratch{Src: bpf.RegA},
		bpf.StoreScratch{Src: bpf.RegX},

		bpf.ALUOpConstant{Op: bpf.ALUOpAdd},
		bpf.ALUOpConstant{Op: bpf.ALUOpSub},
		bpf.ALUOpConstant{Op: bpf.ALUOpMul},
		bpf.ALUOpConstant{Op: bpf.ALUOpDiv},
		bpf.ALUOpConstant{Op: bpf.ALUOpOr},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftLeft},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight},
		bpf.ALUOpConstant{Op: bpf.ALUOpMod},
		bpf.ALUOpConstant{Op: bpf.ALUOpXor},

		bpf.ALUOpX{Op: bpf.ALUOpAdd},
		bpf.ALUOpX{Op: bpf.ALUOpSub},
		bpf.ALUOpX{Op: bpf.ALUOpMul},
		bpf.ALUOpX{Op: bpf.ALUOpDiv},
		bpf.ALUOpX{Op: bpf.ALUOpOr},
		bpf.ALUOpX{Op: bpf.ALUOpAnd},
		bpf.ALUOpX{Op: bpf.ALUOpShiftLeft},
		bpf.ALUOpX{Op: bpf.ALUOpShiftRight},
		bpf.ALUOpX{Op: bpf.ALUOpMod},
		bpf.ALUOpX{Op: bpf.ALUOpXor},

		bpf.NegateA{},

		bpf.Jump{},

		bpf.JumpIf{Cond: bpf.JumpEqual},
		bpf.JumpIf{Cond: bpf.JumpNotEqual},
		bpf.JumpIf{Cond: bpf.JumpGreaterThan},
		bpf.JumpIf{Cond: bpf.JumpLessThan},
		bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual},
		bpf.JumpIf{Cond: bpf.JumpLessOrEqual},
		bpf.JumpIf{Cond: bpf.JumpBitsSet},
		bpf.JumpIf{Cond: bpf.JumpBitsNotSet},

		bpf.JumpIfX{Cond: bpf.JumpEqual},
		bpf.JumpIfX{Cond: bpf.JumpNotEqual},
		bpf.JumpIfX{Cond: bpf.JumpGreaterThan},
		bpf.JumpIfX{Cond: bpf.JumpLessThan},
		bpf.JumpIfX{Cond: bpf.JumpGreaterOrEqual},
		bpf.JumpIfX{Cond: bpf.JumpLessOrEqual},
		bpf.JumpIfX{Cond: bpf.JumpBitsSet},
		bpf.JumpIfX{Cond: bpf.JumpBitsNotSet},

		bpf.RetA{},

		bpf.RetConstant{},

		bpf.TXA{},

		bpf.TAX{},
	}, "test")

	if err != nil {
		t.Fatal("all instructions failed to compile", err)
	}
}

// Test out of bound jumps
func TestJump(t *testing.T) {
	_, err := Compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegX, Val: 0},
		bpf.Jump{Skip: 0},
	}, "test")

	if err == nil {
		t.Fatal("out of bounds skip compiled")
	}
}

func TestJumpIf(t *testing.T) {
	_, err := Compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 2, SkipTrue: 0, SkipFalse: 1},
	}, "test")

	if err == nil {
		t.Fatal("out of bounds skip compiled")
	}
}

func TestJumpIfX(t *testing.T) {
	_, err := Compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 3},
		bpf.JumpIfX{Cond: bpf.JumpEqual, SkipTrue: 1, SkipFalse: 0},
	}, "test")

	if err == nil {
		t.Fatal("out of bounds skip compiled")
	}
}

// Out of bounds fall through - last block doesn't end in return
func TestFallthrough(t *testing.T) {
	_, err := Compile([]bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
	}, "test")

	if err == nil {
		t.Fatal("out of bounds fall through compiled")
	}
}

// Test block splitting
func TestBlocksJump(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		/* 0 */ bpf.LoadConstant{Dst: bpf.RegX, Val: 3},
		/* 1 */ bpf.Jump{Skip: 1},
		/* 2 */ bpf.RetConstant{Val: 0}, // unreachable
		/* 3 */ bpf.RetConstant{Val: 1},
	})

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks got %d", len(blocks))
	}

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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks got %d", len(blocks))
	}

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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks got %d", len(blocks))
	}

	matchBlock(t, blocks[0], insns[0:3], map[pos]*block{3: blocks[1], 4: blocks[2]})
	matchBlock(t, blocks[1], insns[3:4], map[pos]*block{})
	matchBlock(t, blocks[2], insns[4:5], map[pos]*block{})
}

// Test absolute guards
func TestAbsoluteGuardSize(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		bpf.LoadAbsolute{Size: 4, Off: 10}, // guard 14
		bpf.LoadAbsolute{Size: 1, Off: 10}, // guard 11
		bpf.RetConstant{},
	})

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 1 {
		t.Fatalf("expected 1 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardAbsolute{Len: 14}}}, insns...), map[pos]*block{})
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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardAbsolute{Len: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 4: blocks[2]})
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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardAbsolute{Len: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 4: blocks[2]})
	matchBlock(t, blocks[1], insns[2:4], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[2], insns[4:5], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardAbsolute{Len: 16}}}, insns[5:]...), map[pos]*block{})
}

func TestIndirectGuardSize(t *testing.T) {
	insns := toInstructions([]bpf.Instruction{
		bpf.LoadIndirect{Size: 4, Off: 10}, // guard 14
		bpf.LoadIndirect{Size: 1, Off: 10}, // guard 11
		bpf.RetConstant{},
	})

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 1 {
		t.Fatalf("expected 1 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{Len: 14}}}, insns...), map[pos]*block{})
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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{Len: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 4: blocks[2]})
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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{Len: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 4: blocks[2]})
	matchBlock(t, blocks[1], insns[2:4], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[2], insns[4:5], map[pos]*block{5: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardIndirect{Len: 16}}}, insns[5:]...), map[pos]*block{})
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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{Len: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 5: blocks[2]})
	matchBlock(t, blocks[1], insns[2:5], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[2], insns[5:6], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardIndirect{Len: 2}}}, insns[6:]...), map[pos]*block{})
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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{Len: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 5: blocks[2]})
	matchBlock(t, blocks[1], insns[2:5], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[2], insns[5:6], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardIndirect{Len: 2}}}, insns[6:]...), map[pos]*block{})
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

	blocks, err := splitBlocks(insns)
	if err != nil {
		t.Fatal("splitBlocks failed", err)
	}

	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks got %d", len(blocks))
	}

	addPacketGuards(blocks)

	matchBlock(t, blocks[0], append([]instruction{{Instruction: packetGuardIndirect{Len: 14}}}, insns[:2]...), map[pos]*block{2: blocks[1], 5: blocks[2]})
	matchBlock(t, blocks[1], append([]instruction{{Instruction: packetGuardAbsolute{Len: 3}}}, insns[2:5]...), map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[2], insns[5:6], map[pos]*block{6: blocks[3]})
	matchBlock(t, blocks[3], append([]instruction{{Instruction: packetGuardIndirect{Len: 2}}}, insns[6:]...), map[pos]*block{})
}

// matchBlock checks a block has the given instructions and jumps
func matchBlock(t *testing.T, b *block, expected []instruction, jumps map[pos]*block) {
	t.Helper()

	if !reflect.DeepEqual(expected, b.insns) {
		t.Fatalf("expected instructions %v, got %v", expected, b.insns)
	}

	if !reflect.DeepEqual(jumps, b.jumps) {
		t.Fatalf("expected jumps %v, got %v", jumps, b.jumps)
	}
}
