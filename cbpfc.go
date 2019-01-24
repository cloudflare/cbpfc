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
// Storing an ordered list of the blocks allows us to mimick the layout
// of the original code as closely as possible (which is great for debugging!)
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
	"strings"
	"text/template"

	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

const funcTemplate = `
// True if packet matches, false otherwise
static inline
bool {{.Name}}(const uint8_t *const data, const uint8_t *const data_end) {
	__attribute__((unused))
    uint32_t a, x, m[16];
{{range $i, $b := .Blocks}}
{{if $b.HasLabel}}{{$b.Label}}:{{end}}
{{- range $i, $s := $b.Statements}}
	{{$s}}
{{- end}}
{{end}}
}`

type function struct {
	Name   string
	Blocks []compiledBlock
}

// cBPF reg to C symbol
var regToSym = map[bpf.Register]string{
	bpf.RegA: "a",
	bpf.RegX: "x",
}

// alu operation to C operator
var aluToOp = map[bpf.ALUOp]string{
	bpf.ALUOpAdd:        "+",
	bpf.ALUOpSub:        "-",
	bpf.ALUOpMul:        "*",
	bpf.ALUOpDiv:        "/",
	bpf.ALUOpOr:         "|",
	bpf.ALUOpAnd:        "&",
	bpf.ALUOpShiftLeft:  "<<",
	bpf.ALUOpShiftRight: ">>",
	bpf.ALUOpMod:        "%",
	bpf.ALUOpXor:        "^",
}

// jump test to fmt string for condition
var condToFmt = map[bpf.JumpTest]string{
	bpf.JumpEqual:          "a == %v",
	bpf.JumpNotEqual:       "a != %v",
	bpf.JumpGreaterThan:    "a > %v",
	bpf.JumpLessThan:       "a < %v",
	bpf.JumpGreaterOrEqual: "a >= %v",
	bpf.JumpLessOrEqual:    "a <= %v",
	bpf.JumpBitsSet:        "a & %v",
	bpf.JumpBitsNotSet:     "!(a & %v)",
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

	// True if a label has been created
	HasLabel bool

	// Map of absolute instruction positions the last instruction
	// of this block can jump to, to the corresponding block
	jumps map[pos]*block

	// id of the instruction that started this block
	// Unique, but not guaranteed to match insns[0].id after blocks are modified
	id pos
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

// Create a unique label for this block
func (b *block) createLabel() string {
	b.HasLabel = true
	return b.Label()
}

func (b *block) skipToPos(s skip) pos {
	return b.last().id + 1 + pos(s)
}

// Get the target label of a skip
func (b *block) createSkipLabel(s skip) string {
	return b.jumps[b.skipToPos(s)].createLabel()
}

func (b *block) insert(pos uint, insn instruction) {
	b.insns = append(b.insns[:pos], append([]instruction{insn}, b.insns[pos:]...)...)
}

func (b *block) last() instruction {
	return b.insns[len(b.insns)-1]
}

type compiledBlock struct {
	*block

	Statements []string
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

// Compile compiles a cBPF program to a C function, named "funcName",
// with a signature of: bool funcName(uint8_t *data, uint8_t *data_end).
// The function returns true IFF the packet in "data" matches the cBPF program.
func Compile(insns []bpf.Instruction, funcName string) (string, error) {
	// Can't do anything meaningful with no instructions
	if len(insns) == 0 {
		return "", errors.New("can't campile 0 instructions")
	}

	instructions := toInstructions(insns)

	// Split into blocks
	blocks, err := splitBlocks(instructions)
	if err != nil {
		return "", errors.Wrapf(err, "unable to compute blocks")
	}

	// Guard packet loads
	addPacketGuards(blocks)

	fun := function{
		Name:   funcName,
		Blocks: make([]compiledBlock, len(blocks)),
	}

	// Compile blocks to C
	for i, block := range blocks {
		fun.Blocks[i], err = compileBlock(block)
		if err != nil {
			return "", err
		}
	}

	// Fill in the template
	tmpl, err := template.New("cbfp_func").Parse(funcTemplate)
	if err != nil {
		return "", errors.Wrapf(err, "unable to parse func template")
	}

	c := strings.Builder{}

	if err := tmpl.Execute(&c, fun); err != nil {
		return "", errors.Wrapf(err, "unable to execute func template")
	}

	return c.String(), nil
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

// Returns blocks in order they appear in original code
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

// compileBlock compiles a block to C.
func compileBlock(blk *block) (compiledBlock, error) {
	cBlk := compiledBlock{
		block:      blk,
		Statements: make([]string, len(blk.insns)),
	}

	for i, insn := range blk.insns {
		stat, err := compileInsn(insn, blk)
		if err != nil {
			return cBlk, errors.Wrapf(err, "unable to compile %v", insn)
		}

		cBlk.Statements[i] = stat
	}

	return cBlk, nil
}

// compileInsn compiles an instruction to a single C line / statement.
func compileInsn(insn instruction, blk *block) (string, error) {
	switch i := insn.Instruction.(type) {

	case bpf.LoadConstant:
		return stat("%s = %d;", regToSym[i.Dst], i.Val)
	case bpf.LoadScratch:
		return stat("%s = m[%d];", regToSym[i.Dst], i.N)
	case bpf.LoadAbsolute:
		return packetLoad(i.Size, "data + %d", i.Off)
	case bpf.LoadIndirect:
		return packetLoad(i.Size, "data + x + %d", i.Off)
	case bpf.LoadMemShift:
		return stat("x = 4*(*(data + %d) & 0xf);", i.Off)

	case bpf.StoreScratch:
		return stat("m[%d] = %s;", i.N, regToSym[i.Src])

	case bpf.ALUOpConstant:
		return stat("a %s= %d;", aluToOp[i.Op], i.Val)
	case bpf.ALUOpX:
		return stat("a %s= x;", aluToOp[i.Op])
	case bpf.NegateA:
		return stat("a = -a;")

	case bpf.Jump:
		return stat("goto %s;", blk.createSkipLabel(skip(i.Skip)))
	case bpf.JumpIf:
		return conditionalJump(skip(i.SkipTrue), skip(i.SkipFalse), blk, condToFmt[i.Cond], i.Val)
	case bpf.JumpIfX:
		return conditionalJump(skip(i.SkipTrue), skip(i.SkipFalse), blk, condToFmt[i.Cond], "x")

	// From man iptables-extensions, non-zero is match (which they call "pass" in their example because the iptables
	// action is "ACCEPT", but gatesetter uses iptable rules with "DROP")
	case bpf.RetA:
		return stat("return a != 0;")
	case bpf.RetConstant:
		if i.Val == 0 {
			return stat("return false;")
		} else {
			return stat("return true;")
		}

	case bpf.TXA:
		return stat("a = x;")
	case bpf.TAX:
		return stat("x = a;")

	case packetGuardAbsolute:
		return stat("if (data + %d > data_end) return false;", i.Len)
	case packetGuardIndirect:
		return stat("if (data + x + %d > data_end) return false;", i.Len)

	default:
		return "", errors.Errorf("unsupported instruction %v", insn)
	}
}

func packetLoad(size int, offsetFmt string, offsetArgs ...interface{}) (string, error) {
	offset := fmt.Sprintf(offsetFmt, offsetArgs...)

	switch size {
	case 1:
		return stat("a = *(%s);", offset)
	case 2:
		return stat("a = ntohs(*((uint16_t *) (%s)));", offset)
	case 4:
		return stat("a = ntohl(*((uint32_t *) (%s)));", offset)
	}

	return "", errors.Errorf("unsupported load size %d", size)
}

func conditionalJump(skipTrue, skipFalse skip, blk *block, condFmt string, condArgs ...interface{}) (string, error) {
	cond := fmt.Sprintf(condFmt, condArgs...)

	if skipTrue > 0 {
		if skipFalse > 0 {
			return stat("if (%s) goto %s; else goto %s;", cond, blk.createSkipLabel(skipTrue), blk.createSkipLabel(skipFalse))
		}
		return stat("if (%s) goto %s;", cond, blk.createSkipLabel(skipTrue))
	}
	return stat("if (!(%s)) goto %s;", cond, blk.createSkipLabel(skipFalse))
}

func stat(format string, a ...interface{}) (string, error) {
	return fmt.Sprintf(format, a...), nil
}
