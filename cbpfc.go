// Package cbpfc implements a cBPF (classic BPF) to eBPF
// (extended BPF, not be confused with cBPF extensions) compiler.
//
// cbpfc can compile cBPF filters to:
//   - C, which can be compiled to eBPF with Clang
//   - eBPF
//
// Both the C and eBPF output are intended to be accepted by the kernel verifier:
//   - All packet loads are guarded with runtime packet length checks
//   - RegA and RegX are zero initialized as required
//   - Division by zero is guarded by runtime checks
//
// The generated C / eBPF is intended to be embedded into a larger C / eBPF program.
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

// pos stores the absolute position of a cBPF instruction
type pos uint

// skips store cBPF jumps, which are relative
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

// block contains a linear flow on instructions:
//   - Nothing jumps into the middle of a block
//   - Nothing jumps out of the middle of a block
//
// A block may start or end with any instruction, as any instruction
// can be the target of a jump.
//
// A block also knows what blocks it jumps to. This forms a DAG of blocks.
type block struct {
	// Should not be directly modified, instead copy instructions to new slice
	insns []instruction

	// Map of absolute instruction positions the last instruction
	// of this block can jump to, to the corresponding block
	jumps map[pos]*block

	// id of the instruction that started this block
	// Unique, but not guaranteed to match insns[0].id after blocks are modified
	id pos
}

// newBlock creates a block with copy of insns
func newBlock(insns []instruction) *block {
	return &block{
		insns: insns,
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

func (b *block) last() instruction {
	return b.insns[len(b.insns)-1]
}

// Greatest known offset into the input packet that is read by the program
type packetGuard uint32

// packetGuardAbsolute is a "fake" instruction
// that checks the length of the packet for absolute packet loads
type packetGuardAbsolute struct {
	guard packetGuard
}

// Assemble implements the Instruction Assemble method.
func (p packetGuardAbsolute) Assemble() (bpf.RawInstruction, error) {
	return bpf.RawInstruction{}, errors.Errorf("unsupported")
}

// packetGuardIndirect is a "fake" instruction
// that checks the length of the packet for indirect packet loads
type packetGuardIndirect struct {
	guard packetGuard
}

// Assemble implements the Instruction Assemble method.
func (p packetGuardIndirect) Assemble() (bpf.RawInstruction, error) {
	return bpf.RawInstruction{}, errors.Errorf("unsupported")
}

// checksXNotZero is a "fake" instruction
// that returns no match if X is 0
type checkXNotZero struct {
}

// Assemble implements the Instruction Assemble method.
func (c checkXNotZero) Assemble() (bpf.RawInstruction, error) {
	return bpf.RawInstruction{}, errors.Errorf("unsupported")
}

// compile compiles a cBPF program to an ordered slice of blocks, with:
// - Registers zero initialized as required
// - Required packet access guards added
// - JumpIf and JumpIfX instructions normalized (see normalizeJumps)
func compile(insns []bpf.Instruction) ([]*block, error) {
	err := validateInstructions(insns)
	if err != nil {
		return nil, err
	}

	instructions := toInstructions(insns)

	normalizeJumps(instructions)

	// Split into blocks
	blocks, err := splitBlocks(instructions)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to compute blocks")
	}

	// Initialize registers
	err = initializeMemory(blocks)
	if err != nil {
		return nil, err
	}

	// Check we don't divide by zero
	err = addDivideByZeroGuards(blocks)
	if err != nil {
		return nil, err
	}

	// Guard packet loads
	addAbsolutePacketGuards(blocks)
	addIndirectPacketGuards(blocks)

	return blocks, nil
}

// validateInstructions checks the instructions are valid, and we support them
func validateInstructions(insns []bpf.Instruction) error {
	// Can't do anything meaningful with no instructions
	if len(insns) == 0 {
		return errors.New("can't compile 0 instructions")
	}

	for pc, insn := range insns {
		// Assemble does some input validation
		_, err := insn.Assemble()
		if err != nil {
			return errors.Errorf("can't assemble instruction %d: %v", pc, insn)
		}

		switch i := insn.(type) {
		case bpf.RawInstruction:
			return errors.Errorf("unsupported instruction %d: %v", pc, insn)

		case bpf.LoadExtension:
			switch i.Num {
			case bpf.ExtLen:
				break
			default:
				return errors.Errorf("unsupported BPF extension %d: %v", pc, insn)
			}
		}
	}

	return nil
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

// splitBlocks splits the cBPF into an ordered list of blocks.
//
// The blocks are preserved in the order they are found as this guarantees that
// a block only targets later blocks (cBPF jumps are positive, relative offsets).
// This also mimics the layout of the original cBPF, which is good for debugging.
func splitBlocks(instructions []instruction) ([]*block, error) {
	// Blocks we've visited already
	blocks := []*block{}

	// map of targets to blocks that target them
	// target 0 is for the base case
	targets := map[pos][]*block{
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

			targets[t] = append(targets[t], next)
		}

		jmpBlocks := targets[target]

		// Mark all the blocks that jump to the block we've just visited as doing so
		for _, jmpBlock := range jmpBlocks {
			jmpBlock.jumps[target] = next
		}

		blocks = append(blocks, next)

		// Target is now a block!
		delete(targets, target)
	}

	return blocks, nil
}

// sortTargets sorts the target positions (keys), lowest first
func sortTargets(targets map[pos][]*block) []pos {
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

// addDivideByZeroGuards adds runtime guards / checks to ensure
// the program returns no match when it would otherwise divide by zero.
func addDivideByZeroGuards(blocks []*block) error {
	isDivision := func(op bpf.ALUOp) bool {
		return op == bpf.ALUOpDiv || op == bpf.ALUOpMod
	}

	// Is RegX known to be none 0 at the start of each block
	// We can't divide by RegA, only need to check RegX.
	xNotZero := make(map[*block]bool)

	for _, block := range blocks {
		notZero := xNotZero[block]

		// newInsns to replace those in the block
		newInsns := []instruction{}
		for _, insn := range block.insns {
			switch i := insn.Instruction.(type) {
			case bpf.ALUOpConstant:
				if isDivision(i.Op) && i.Val == 0 {
					return errors.Errorf("instruction %v divides by 0", insn)
				}
			case bpf.ALUOpX:
				if isDivision(i.Op) && !notZero {
					newInsns = append(newInsns, instruction{Instruction: checkXNotZero{}})
					notZero = true
				}
			}

			newInsns = append(newInsns, insn)

			// check if X clobbered - check is invalidated
			if memWrites(insn.Instruction).regs[bpf.RegX] {
				notZero = false
			}
		}
		block.insns = newInsns

		// update the status of every block this one jumps to
		for _, target := range block.jumps {
			targetNotZero, ok := xNotZero[target]
			if !ok {
				xNotZero[target] = notZero
				continue
			}

			// x needs to be not zero from every possible path
			xNotZero[target] = targetNotZero && notZero
		}
	}

	return nil
}

// addAbsolutePacketGuard adds required packet guards for absolute packet accesses to blocks.
func addAbsolutePacketGuards(blocks []*block) {
	addPacketGuards(blocks, packetGuardOpts{
		requiredGuard: func(insns []instruction) (int, packetGuard) {
			var biggestGuard packetGuard

			for _, insn := range insns {
				switch i := insn.Instruction.(type) {
				case bpf.LoadAbsolute:
					if a := packetGuard(i.Off + uint32(i.Size)); a > biggestGuard {
						biggestGuard = a
					}
				case bpf.LoadMemShift:
					if a := packetGuard(i.Off + 1); a > biggestGuard {
						biggestGuard = a
					}
				}
			}

			return len(insns), biggestGuard
		},

		createInsn: func(guard packetGuard) bpf.Instruction {
			return packetGuardAbsolute{guard: guard}
		},
	})
}

// addIndirectPacketGuard adds required packet guards for indirect packet accesses to blocks.
func addIndirectPacketGuards(blocks []*block) {
	addPacketGuards(blocks, packetGuardOpts{
		requiredGuard: func(insns []instruction) (int, packetGuard) {
			var (
				insnCount    int
				biggestGuard packetGuard
			)

			for _, insn := range insns {
				insnCount++

				switch i := insn.Instruction.(type) {
				case bpf.LoadIndirect:
					if a := packetGuard(i.Off + uint32(i.Size)); a > biggestGuard {
						biggestGuard = a
					}
				}

				// Check if we clobbered x - this invalidates the guard
				if memWrites(insn.Instruction).regs[bpf.RegX] {
					break
				}
			}

			return insnCount, biggestGuard
		},

		createInsn: func(guard packetGuard) bpf.Instruction {
			return packetGuardIndirect{guard: guard}
		},
	})
}

type packetGuardOpts struct {
	// requiredGuard returns:
	// - the packetGuard needed by insns
	// - the number of instructions in insns covered by the guard.
	//   The guard is assumed to be invalidated for the remaining / uncovered insns (eg RegX was clobbered for indirect guards).
	//   requiredGuard will be called until all instructions are covered.
	requiredGuard func(insns []instruction) (int, packetGuard)

	// createInsn creates an instruction that checks the packet length against the guard
	createInsn func(guard packetGuard) bpf.Instruction
}

// addPacketGuards adds packet guards as required.
//
// Traversing the DAG of blocks (by visiting the blocks a block jumps to),
// we know all packet guards that exist at the start of a given block.
// We can check if the block requires a longer / bigger guard than
// the shortest / least existing guard.
func addPacketGuards(blocks []*block, opts packetGuardOpts) {
	// Guards in effect at the start of each block
	// Can't jump backwards so we only need to traverse blocks once
	guards := make(map[*block][]packetGuard)

	for _, block := range blocks {
		blockGuard := addBlockGuards(block, leastGuard(guards[block]), opts)

		for _, target := range block.jumps {
			guards[target] = append(guards[target], blockGuard)
		}
	}
}

// addBlockGuards add the guards required for the instructions in block.
func addBlockGuards(block *block, currentGuard packetGuard, opts packetGuardOpts) packetGuard {
	// block insns with guards added
	newInsns := []instruction{}

	// Start of the current pseudo block in case guard is reset / invalidated
	start := 0

	for start < len(block.insns) {
		// The guard has been reset for the next instructions
		if start != 0 {
			currentGuard = 0
		}

		insnsCovered, insnsGuard := opts.requiredGuard(block.insns[start:])

		// Need a bigger guard for these insns
		if insnsGuard != 0 && insnsGuard > currentGuard {

			// Last guard we need for this block -> what our children / target blocks will start with
			if start+insnsCovered >= len(block.insns) {

				// If packets must go through a bigger guard (guaranteed guard) to match, we can use the guaranteed guard here,
				// without changing the return value of the program:
				//   - packets smaller than the guaranteed guard cannot match anyways, we can safely reject them earlier
				//   - packets bigger than the guaranteed guard won't be affected by it
				if guaranteed := guaranteedGuard(block.jumps, opts); guaranteed > insnsGuard {
					insnsGuard = guaranteed
				}
			}

			currentGuard = insnsGuard

			newInsns = append(newInsns, instruction{Instruction: opts.createInsn(insnsGuard)})
		}

		newInsns = append(newInsns, block.insns[start:start+insnsCovered]...)
		start += insnsCovered
	}

	block.insns = newInsns

	return currentGuard
}

// guaranteedGuard performs a recursive depth first search of blocks in target to determine
// the greatest packet guard that must be made for a packet to match
//
// If the DAG of blocks needs these packet guards:
//
//           [4]
//          /   \
//      false   [6]
//             /   \
//          true   [8]
//                /   \
//            false   true
//
// A packet can only match ("true") by going through guards 4 and 6. It does not have to go through guard 8.
// guaranteedGuard would return 6.
func guaranteedGuard(targets map[pos]*block, opts packetGuardOpts) packetGuard {

	// Inner implementation - Uses memoization
	return guaranteedGuardCached(targets, opts, make(map[*block]packetGuard))
}

// 'cache' is used in order to not calculate guard more than once for the same block.
func guaranteedGuardCached(targets map[pos]*block, opts packetGuardOpts, cache map[*block]packetGuard) packetGuard {
	targetGuards := []packetGuard{}

	for _, target := range targets {
		// Block can't match the packet, ignore it
		if blockNeverMatches(target) {
			continue
		}
		if guard, ok := cache[target]; ok {
			targetGuards = append(targetGuards, guard)
			continue
		}

		insnsCovered, insnsGuard := opts.requiredGuard(target.insns)

		// Guard invalidated by block, stop exploring
		if insnsCovered < len(target.insns) {
			targetGuards = append(targetGuards, insnsGuard)
			continue
		}

		guaranteed := guaranteedGuardCached(target.jumps, opts, cache)

		if guaranteed > insnsGuard {
			insnsGuard = guaranteed
		}

		cache[target] = insnsGuard

		targetGuards = append(targetGuards, insnsGuard)
	}

	return leastGuard(targetGuards)
}

// leastGuard returns the smallest guard from guards.
// 0 if there are no guards.
func leastGuard(guards []packetGuard) packetGuard {
	var least packetGuard

	for i, guard := range guards {
		if i == 0 || guard < least {
			least = guard
		}
	}

	return least
}

// blockNeverMatches returns true IFF the insns in block will never match the input packet
func blockNeverMatches(block *block) bool {
	for _, insn := range block.insns {
		switch i := insn.Instruction.(type) {
		case bpf.RetConstant:
			if i.Val == 0 {
				return true
			}
		}
	}

	return false
}

// memStatus represents a context defined status of registers & scratch
type memStatus struct {
	// indexed by bpf.Register
	regs    [2]bool
	scratch [16]bool
}

// merge merges this status with the other by applying policy to regs and scratch
func (r memStatus) merge(other memStatus, policy func(this, other bool) bool) memStatus {
	newStatus := memStatus{}

	for i := range newStatus.regs {
		newStatus.regs[i] = policy(r.regs[i], other.regs[i])
	}

	for i := range newStatus.scratch {
		newStatus.scratch[i] = policy(r.scratch[i], other.scratch[i])
	}

	return newStatus
}

// and merges this status with the other by logical AND
func (r memStatus) and(other memStatus) memStatus {
	return r.merge(other, func(this, other bool) bool {
		return this && other
	})
}

// and merges this status with the other by logical OR
func (r memStatus) or(other memStatus) memStatus {
	return r.merge(other, func(this, other bool) bool {
		return this || other
	})
}

// initializeMemory zero initializes all the registers that the BPF program reads from before writing to. Returns an error if any scratch memory is used uninitialized.
func initializeMemory(blocks []*block) error {
	// memory initialized at the start of each block
	statuses := make(map[*block]memStatus)

	// uninitialized memory used so far
	uninitialized := memStatus{}

	for _, block := range blocks {
		status := statuses[block]

		for _, insn := range block.insns {
			insnUninitialized := memUninitializedReads(insn.Instruction, status)
			// Check no uninitialized scratch registers are read
			for scratch, uninit := range insnUninitialized.scratch {
				if uninit {
					return errors.Errorf("instruction %v reads potentially uninitialized scratch register M[%d]", insn, scratch)
				}
			}

			uninitialized = uninitialized.or(insnUninitialized)
			status = status.or(memWrites(insn.Instruction))
		}

		// update the status of every block this one jumps to
		for _, target := range block.jumps {
			targetStatus, ok := statuses[target]
			if !ok {
				statuses[target] = status
				continue
			}

			// memory needs to be initialized from every possible path
			statuses[target] = targetStatus.and(status)
		}
	}

	// new instructions we need to prepend to initialize uninitialized registers
	initInsns := []instruction{}
	for reg, uninit := range uninitialized.regs {
		if !uninit {
			continue
		}

		initInsns = append(initInsns, instruction{
			Instruction: bpf.LoadConstant{
				Dst: bpf.Register(reg),
				Val: 0,
			},
		})
	}
	blocks[0].insns = append(initInsns, blocks[0].insns...)
	return nil
}

// memUninitializedReads returns the memory read by insn that has not yet been initialized according to initialized.
func memUninitializedReads(insn bpf.Instruction, initialized memStatus) memStatus {
	return memReads(insn).merge(initialized, func(read, init bool) bool {
		return read && !init
	})
}

// memReads returns the memory read by insn
func memReads(insn bpf.Instruction) memStatus {
	read := memStatus{}

	switch i := insn.(type) {
	case bpf.ALUOpConstant:
		read.regs[bpf.RegA] = true
	case bpf.ALUOpX:
		read.regs[bpf.RegA] = true
		read.regs[bpf.RegX] = true

	case bpf.JumpIf:
		read.regs[bpf.RegA] = true
	case bpf.JumpIfX:
		read.regs[bpf.RegA] = true
		read.regs[bpf.RegX] = true

	case bpf.LoadIndirect:
		read.regs[bpf.RegX] = true
	case bpf.LoadScratch:
		read.scratch[i.N] = true

	case bpf.NegateA:
		read.regs[bpf.RegA] = true

	case bpf.RetA:
		read.regs[bpf.RegA] = true

	case bpf.StoreScratch:
		read.regs[i.Src] = true

	case bpf.TAX:
		read.regs[bpf.RegA] = true
	case bpf.TXA:
		read.regs[bpf.RegX] = true
	}

	return read
}

// memWrites returns the memory written by insn
func memWrites(insn bpf.Instruction) memStatus {
	write := memStatus{}

	switch i := insn.(type) {
	case bpf.ALUOpConstant:
		write.regs[bpf.RegA] = true
	case bpf.ALUOpX:
		write.regs[bpf.RegA] = true

	case bpf.LoadAbsolute:
		write.regs[bpf.RegA] = true
	case bpf.LoadConstant:
		write.regs[i.Dst] = true
	case bpf.LoadExtension:
		write.regs[bpf.RegA] = true
	case bpf.LoadIndirect:
		write.regs[bpf.RegA] = true
	case bpf.LoadMemShift:
		write.regs[bpf.RegX] = true
	case bpf.LoadScratch:
		write.regs[i.Dst] = true

	case bpf.NegateA:
		write.regs[bpf.RegA] = true

	case bpf.StoreScratch:
		write.scratch[i.N] = true

	case bpf.TAX:
		write.regs[bpf.RegX] = true
	case bpf.TXA:
		write.regs[bpf.RegA] = true
	}

	return write
}
