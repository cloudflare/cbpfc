// Package cbpfc implements a cBPF (classic BPF) to C compiler.
// The generated C is intended to be compiled to eBPF
// (extended BPF, not be confused with cBPF extensions) using clang.
//
// The cBPF is split into an ordered list of blocks.
// A block contains a linear flow on instructions:
//   - Nothing jumps into the middle of a block
//   - Nothing jumps out of the middle of a block
//
// A block may start or end with any instruction, as any instruction
// can be the target of a jump.
//
// A block also knows what blocks it jumps to. This forms a DAG of blocks.
//
// The blocks are preserved in the order they are found as this guarantees that
// a block only targets later blocks (cBPF jumps are positive, relative offsets).
// This also mimics the layout of the original cBPF, which is good for debugging.
//
// Every instruction is converted to a single statement.
// Every packet load must be preceeded by a "guard" checking the bounds
// the packet pointer. These are required by the eBPF verifier.
//
// Traversing the DAG of blocks (by visiting the blocks a block jumps to),
// we know all packet guards that exist at the start of a given block.
// We can check if the block requires a longer / bigger guard than
// the shortest / least existing guard.
//
// cBPF jumps are relative, these are stored in "skips".
// These have to be converted to an absolute instruction position
// or number, "pos".
package cbpfc

import (
	"fmt"
	"sort"

	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

// Map conditionals to their inverse
var condToInverse = map[bpf.JumpTest]bpf.JumpTest{
	bpf.JumpEqual:          bpf.JumpNotEqual,
	bpf.JumpNotEqual:       bpf.JumpEqual,
	bpf.JumpGreaterThan:    bpf.JumpLessOrEqual,
	bpf.JumpLessThan:       bpf.JumpGreaterOrEqual,
	bpf.JumpGreaterOrEqual: bpf.JumpLessThan,
	bpf.JumpLessOrEqual:    bpf.JumpGreaterThan,
	bpf.JumpBitsSet:        bpf.JumpBitsNotSet,
	bpf.JumpBitsNotSet:     bpf.JumpBitsSet,
}

// Absolute position of a cBPF instruction
type pos uint

// Relative position of a cBPF instruction
type skip uint

// instruction wraps a bpf instruction with it's
// original position
type instruction struct {
	bpf.Instruction
	id pos
}

func (i instruction) String() string {
	return fmt.Sprintf("%d: %v", i.id, i.Instruction)
}

// block contains a linear flow of instructions,
// with the last instruction potentially jumping to a set of blocks
type block struct {
	insns []instruction

	// Map of absolute instruction positions the last instruction
	// of this block can jump to, to the corresponding block
	jumps map[pos]*block

	// id of the instruction that started this block
	// Unique, but not guaranteed to match insns[0].id after blocks are modified
	id pos

	// True IFF another block jumps to this block as a target
	// A block falling-through to this one does not count
	IsTarget bool
}

// newBlock creates a block with copy of insns
func newBlock(insns []instruction) *block {
	// Copy the insns so blocks can be modified independently
	blockInsns := make([]instruction, len(insns))
	copy(blockInsns, insns)

	return &block{
		insns: blockInsns,
		jumps: make(map[pos]*block),
		id:    insns[0].id,
	}
}

func (b *block) Label() string {
	return fmt.Sprintf("block_%d", b.id)
}

func (b *block) skipToPos(s skip) pos {
	return b.last().id + 1 + pos(s)
}

// Get the target block of a skip
func (b *block) skipToBlock(s skip) *block {
	return b.jumps[b.skipToPos(s)]
}

func (b *block) insert(pos uint, insn instruction) {
	b.insns = append(b.insns[:pos], append([]instruction{insn}, b.insns[pos:]...)...)
}

func (b *block) last() instruction {
	return b.insns[len(b.insns)-1]
}

// packetGuardAbsolute is a "fake" instruction
// that checks the length of the packet for absolute packet loads
type packetGuardAbsolute struct {
	// Length the guard checks. offset + size
	Len uint32
}

// Assemble implements the Instruction Assemble method.
func (p packetGuardAbsolute) Assemble() (bpf.RawInstruction, error) {
	return bpf.RawInstruction{}, errors.Errorf("unsupported")
}

// packetGuardIndirect is a "fake" instruction
// that checks the length of the packet for indirect packet loads
type packetGuardIndirect struct {
	// Length the guard checks. offset + size
	Len uint32
}

// Assemble implements the Instruction Assemble method.
func (p packetGuardIndirect) Assemble() (bpf.RawInstruction, error) {
	return bpf.RawInstruction{}, errors.Errorf("unsupported")
}

// compile compiles a cBPF program to an ordered slice of blocks, with:
// - Reads from uninitialized scratch m[] rejected
// - Required packet access guards added
// - JumpIf and JumpIfX instructions normalized (see normalizeJumps)
func compile(insns []bpf.Instruction) ([]*block, error) {
	// Can't do anything meaningful with no instructions
	if len(insns) == 0 {
		return nil, errors.New("can't campile 0 instructions")
	}

	instructions := toInstructions(insns)

	normalizeJumps(instructions)

	// Split into blocks
	blocks, err := splitBlocks(instructions)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to compute blocks")
	}

	// Check uninitialized scratch usage
	err = checkUninitializedScratch(blocks)
	if err != nil {
		return nil, err
	}

	// Guard packet loads
	addPacketGuards(blocks)

	return blocks, nil
}

func toInstructions(insns []bpf.Instruction) []instruction {
	instructions := make([]instruction, len(insns))

	for pc, insn := range insns {
		instructions[pc] = instruction{
			Instruction: insn,
			id:          pos(pc),
		}
	}

	return instructions
}

// normalizeJumps normalizes conditional jumps to always use skipTrue:
// Jumps that only use skipTrue (skipFalse == 0) are unchanged.
// Jumps that use both skipTrue and skipFalse are unchanged.
// Jumps that only use skipFalse (skipTrue == 0) are inverted to only use skipTrue.
func normalizeJumps(insns []instruction) {
	for pc := range insns {
		switch i := insns[pc].Instruction.(type) {
		case bpf.JumpIf:
			if !shouldInvert(i.SkipTrue, i.SkipFalse) {
				continue
			}

			insns[pc].Instruction = bpf.JumpIf{Cond: condToInverse[i.Cond], Val: i.Val, SkipTrue: i.SkipFalse, SkipFalse: i.SkipTrue}

		case bpf.JumpIfX:
			if !shouldInvert(i.SkipTrue, i.SkipFalse) {
				continue
			}

			insns[pc].Instruction = bpf.JumpIfX{Cond: condToInverse[i.Cond], SkipTrue: i.SkipFalse, SkipFalse: i.SkipTrue}
		}
	}
}

// Check if a conditional jump should be inverted
func shouldInvert(skipTrue, skipFalse uint8) bool {
	return skipTrue == 0 && skipFalse != 0
}

// Traverse instructions until end of first block. Target is absolute start of block.
// Return block-relative jump targets
func visitBlock(insns []instruction, target pos) (*block, []skip) {
	for pc, insn := range insns {
		// Relative jumps from this instruction
		var skips []skip

		switch i := insn.Instruction.(type) {
		case bpf.Jump:
			skips = []skip{skip(i.Skip)}
		case bpf.JumpIf:
			skips = []skip{skip(i.SkipTrue), skip(i.SkipFalse)}
		case bpf.JumpIfX:
			skips = []skip{skip(i.SkipTrue), skip(i.SkipFalse)}

		case bpf.RetA, bpf.RetConstant:
			// No extra targets to visit

		default:
			// Regular instruction, next please!
			continue
		}

		// every insn including this one
		return newBlock(insns[:pc+1]), skips
	}

	// Try to fall through to next block
	return newBlock(insns), []skip{0}
}

// targetBlock is a block that targets (ie jumps) to another block
// used internally by splitBlocks()
type targetBlock struct {
	*block
	// True IFF the block falls through to the other block (skip == 0)
	isFallthrough bool
}

// Returns blocks in order they appear in original code
func splitBlocks(instructions []instruction) ([]*block, error) {
	// Blocks we've visited already
	blocks := []*block{}

	// map of targets to blocks that target them
	// target 0 is for the base case
	targets := map[pos][]targetBlock{
		0: nil,
	}

	// As long as we have un visited targets
	for len(targets) > 0 {
		sortedTargets := sortTargets(targets)

		// Get the first one (not really breadth first, but close enough!)
		target := sortedTargets[0]

		end := len(instructions)
		// If there's a next target, ensure we stop before it
		if len(sortedTargets) > 1 {
			end = int(sortedTargets[1])
		}

		next, nextSkips := visitBlock(instructions[target:end], target)

		// Add skips to our list of things to visit
		for _, s := range nextSkips {
			// Convert relative skip to absolute pos
			t := next.skipToPos(s)

			if t >= pos(len(instructions)) {
				return nil, errors.Errorf("instruction %v flows past last instruction", next.last())
			}

			targets[t] = append(targets[t], targetBlock{next, s == 0})
		}

		jmpBlocks := targets[target]

		// Mark all the blocks that jump to the block we've just visited as doing so
		for _, jmpBlock := range jmpBlocks {
			jmpBlock.jumps[target] = next

			// Not a fallthrough, the block we've just visited is explicitly jumped to
			if !jmpBlock.isFallthrough {
				next.IsTarget = true
			}
		}

		blocks = append(blocks, next)

		// Target is now a block!
		delete(targets, target)
	}

	return blocks, nil
}

// sortTargets sorts the target positions (keys), lowest first
func sortTargets(targets map[pos][]targetBlock) []pos {
	keys := make([]pos, len(targets))

	i := 0
	for k := range targets {
		keys[i] = k
		i++
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	return keys
}

// addPacketGuards traverses the DAG of blocks,
// and adds packet guards (absolute and indirect) as required.
func addPacketGuards(blocks []*block) {
	if len(blocks) == 0 {
		return
	}

	// Guards in effect at the start of each block
	// Can't jump backwards so we only need to traverse blocks once
	absoluteGuards := make(map[*block][]packetGuardAbsolute)
	indirectGuards := make(map[*block][]packetGuardIndirect)

	// first block starts with no guards
	absoluteGuards[blocks[0]] = []packetGuardAbsolute{{Len: 0}}
	indirectGuards[blocks[0]] = []packetGuardIndirect{{Len: 0}}

	for _, block := range blocks {
		absolute := addAbsolutePacketGuard(block, leastAbsoluteGuard(absoluteGuards[block]))
		indirect := addIndirectPacketGuard(block, leastIndirectGuard(indirectGuards[block]))

		for _, target := range block.jumps {
			absoluteGuards[target] = append(absoluteGuards[target], absolute)
			indirectGuards[target] = append(indirectGuards[target], indirect)
		}
	}
}

// leastAbsoluteGuard gets the packet guard with least Len / lowest range
func leastAbsoluteGuard(guards []packetGuardAbsolute) packetGuardAbsolute {
	sort.Slice(guards, func(i, j int) bool {
		return guards[i].Len < guards[j].Len
	})

	return guards[0]
}

// leastIndirectGuard gets the packet guard with least Len / lowest range
func leastIndirectGuard(guards []packetGuardIndirect) packetGuardIndirect {
	sort.Slice(guards, func(i, j int) bool {
		return guards[i].Len < guards[j].Len
	})

	return guards[0]
}

// addAbsolutePacketGuard adds required packet guards to a block knowing the least guard in effect at the start of block.
// The guard in effect at the end of the block is returned (may be nil).
func addAbsolutePacketGuard(block *block, guard packetGuardAbsolute) packetGuardAbsolute {
	var biggestLen uint32

	for _, insn := range block.insns {
		switch i := insn.Instruction.(type) {
		case bpf.LoadAbsolute:
			if a := i.Off + uint32(i.Size); a > biggestLen {
				biggestLen = a
			}
		case bpf.LoadMemShift:
			if a := i.Off + 1; a > biggestLen {
				biggestLen = a
			}
		}
	}

	if biggestLen > guard.Len {
		guard = packetGuardAbsolute{
			Len: biggestLen,
		}
		block.insert(0, instruction{Instruction: guard})
	}

	return guard
}

// addIndirectPacketGuard adds required packet guards to a block knowing the least guard in effect at the start of block.
// The guard in effect at the end of the block is returned (may be nil).
func addIndirectPacketGuard(block *block, guard packetGuardIndirect) packetGuardIndirect {
	var biggestLen, start uint32

	for pc := 0; pc < len(block.insns); pc++ {
		insn := block.insns[pc]

		switch i := insn.Instruction.(type) {
		case bpf.LoadIndirect:
			if a := i.Off + uint32(i.Size); a > biggestLen {
				biggestLen = a
			}
		}

		// Check if we clobbered x - this invalidates the guard
		clobbered := false
		switch i := insn.Instruction.(type) {
		case bpf.LoadConstant:
			clobbered = i.Dst == bpf.RegX
		case bpf.LoadScratch:
			clobbered = i.Dst == bpf.RegX
		case bpf.LoadMemShift, bpf.TAX:
			clobbered = true
		}

		// End of block or x clobbered -> create guard for previous instructions
		if pc == len(block.insns)-1 || clobbered {
			if biggestLen > guard.Len {
				guard = packetGuardIndirect{
					Len: biggestLen,
				}
				block.insert(uint(start), instruction{Instruction: guard})
				pc++ // Skip the instruction we've just added
			}
		}

		if clobbered {
			// New pseudo block starts here
			start = uint32(pc) + 1
			guard = packetGuardIndirect{Len: 0}
			biggestLen = 0
		}
	}

	return guard
}

// Status of scratch slots (0-15)
// true: initialized, false uninitialized
type scratchStatus [16]bool

// merge merges two scratch statuses into one
func (a scratchStatus) merge(b scratchStatus) scratchStatus {
	newScratch := scratchStatus{}

	for i := 0; i < len(newScratch); i++ {
		newScratch[i] = a[i] && b[i]
	}

	return newScratch
}

// checkUninitializedScratch checks the BPF program doesn't read from uninitialized scratch m[]
// TODO - Is this the right thing to do?
// AFAICT the kernel cBPF -> eBPF converter lets uninitialized m[] reads through as eBPF stack reads.
// Is the eBPF stack 0 initialized?
func checkUninitializedScratch(blocks []*block) error {
	if len(blocks) == 0 {
		return nil
	}

	// scratchStatus at the start of each block
	scratch := make(map[*block]scratchStatus)

	// First block starts with nothing initialized
	scratch[blocks[0]] = scratchStatus{}

	for _, block := range blocks {
		newScratch, err := checkUninitializedBlock(block, scratch[block])
		if err != nil {
			return err
		}

		// update the status of every block this one jumps to
		for _, target := range block.jumps {
			targetScratch, ok := scratch[target]
			if !ok {
				scratch[target] = newScratch
				continue
			}

			scratch[target] = targetScratch.merge(newScratch)
		}
	}

	return nil
}

func checkUninitializedBlock(block *block, status scratchStatus) (scratchStatus, error) {
	for pc, insn := range block.insns {
		switch i := insn.Instruction.(type) {

		case bpf.LoadScratch:
			if !status[i.N] {
				return scratchStatus{}, errors.Errorf("insn %d reads uninitialized scratch m[%d]", pc, i.N)
			}

		case bpf.StoreScratch:
			status[i.N] = true
		}
	}

	return status, nil
}
