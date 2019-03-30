package cbpfc

import (
	"fmt"
	"math"

	"github.com/newtools/ebpf/asm"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

// alu operation to eBPF
var aluToEBPF = map[bpf.ALUOp]asm.ALUOp{
	bpf.ALUOpAdd:        asm.Add,
	bpf.ALUOpSub:        asm.Sub,
	bpf.ALUOpMul:        asm.Mul,
	bpf.ALUOpDiv:        asm.Div,
	bpf.ALUOpOr:         asm.Or,
	bpf.ALUOpAnd:        asm.And,
	bpf.ALUOpShiftLeft:  asm.LSh,
	bpf.ALUOpShiftRight: asm.RSh,
	bpf.ALUOpMod:        asm.Mod,
	bpf.ALUOpXor:        asm.Xor,
}

// bpf sizes to ebpf
var sizeToEBPF = map[int]asm.Size{
	1: asm.Byte,
	2: asm.Half,
	4: asm.Word,
}

// EBPFOpts control how a cBPF filter is converted to eBPF
type EBPFOpts struct {
	// PacketStart is a register holding a pointer to the start of the packet.
	// Not modified.
	PacketStart asm.Register
	// PacketEnd is a register holding a pointer to the end of the packet.
	// Not modified.
	PacketEnd asm.Register

	// Working are registers used internally.
	// Caller saved.
	Working [4]asm.Register

	// StackOffset is the first stack offset that can be used.
	StackOffset int

	// MatchLabel is the label to jump to if the packet matches the filter.
	MatchLabel string

	// NoMatchLabel is the label to jump to if the packet doesn't match the filter.
	NoMatchLabel string

	// LabelPrefix is the prefix to prepend to labels used internally.
	LabelPrefix string
}

// ebpfOpts is the internal version of EBPFOpts
type ebpfOpts struct {
	EBPFOpts

	// Registers mapping directly to cBPF
	regA asm.Register
	regX asm.Register

	// Temp / scratch register
	regTmp asm.Register

	// Register for indirect packet loads
	// Allows the range of a packet guard to be preserved across multiple loads by the verifier
	regIndirect asm.Register
}

func (e ebpfOpts) reg(reg bpf.Register) asm.Register {
	switch reg {
	case bpf.RegA:
		return e.regA
	case bpf.RegX:
		return e.regX
	default:
		panic("unknown bpf register")
	}
}

func (e ebpfOpts) label(name string) string {
	return fmt.Sprintf("%s_%s", e.LabelPrefix, name)
}

func (e ebpfOpts) stackOffset(n int) int16 {
	return -int16(e.StackOffset + n*4)
}

// ToEBF converts a cBPF filter to eBPF.
//
// The generated eBPF code jumps to opts.MatchLabel if the packet pointed to by opts.PacketStart matches the cBPF filter (cBPF filter returns != 0),
// otherwise it jumps to opts.NoMatchLabel.
func ToEBPF(filter []bpf.Instruction, opts EBPFOpts) ([]asm.Instruction, error) {
	blocks, err := compile(filter)
	if err != nil {
		return nil, err
	}

	eOpts := ebpfOpts{
		EBPFOpts:    opts,
		regA:        opts.Working[0],
		regX:        opts.Working[1],
		regTmp:      opts.Working[2],
		regIndirect: opts.Working[3],
	}

	err = checkRegs(eOpts.PacketStart, eOpts.PacketEnd, eOpts.regA, eOpts.regX, eOpts.regTmp, eOpts.regIndirect)
	if err != nil {
		return nil, err
	}

	if eOpts.StackOffset&1 == 1 {
		return nil, errors.Errorf("unaligned stack offset")
	}

	eInsns := []asm.Instruction{}

	for _, block := range blocks {
		for i, insn := range block.insns {
			eInsn, err := insnToEBPF(insn, block, eOpts)
			if err != nil {
				return nil, errors.Wrapf(err, "unable to compile %v", insn)
			}

			// First insn of the block, add symbol so it can be referenced in jumps
			if block.IsTarget && i == 0 {
				eInsn[0].Symbol = eOpts.label(block.Label())
			}

			eInsns = append(eInsns, eInsn...)
		}
	}

	return eInsns, nil
}

// checkRegs ensures the registers are valid and unique
func checkRegs(regs ...asm.Register) error {
	seen := make(map[asm.Register]struct{}, len(regs))

	for _, r := range regs {
		if r > asm.R9 {
			return errors.Errorf("invalid register %v", r)
		}

		if _, ok := seen[r]; ok {
			return errors.Errorf("register %v used twice", r)
		}
		seen[r] = struct{}{}
	}

	return nil
}

// insnToEBPF compiles an instruction to a set of eBPF instructions
func insnToEBPF(insn instruction, blk *block, opts ebpfOpts) (asm.Instructions, error) {
	switch i := insn.Instruction.(type) {

	case bpf.LoadConstant:
		return ebpfInsn(asm.Mov.Imm32(opts.reg(i.Dst), int32(i.Val)))
	case bpf.LoadScratch:
		return ebpfInsn(asm.LoadMem(opts.reg(i.Dst), asm.R10, opts.stackOffset(i.N), asm.Word))
	case bpf.LoadAbsolute:
		if i.Off > math.MaxInt16 {
			return nil, errors.Errorf("LoadAbsolute offset %v too large", i.Off)
		}

		return appendNtoh(opts.regA, sizeToEBPF[i.Size],
			asm.LoadMem(opts.regA, opts.PacketStart, int16(i.Off), sizeToEBPF[i.Size]),
		)
	case bpf.LoadIndirect:
		if i.Off > math.MaxInt16 {
			return nil, errors.Errorf("LoadIndirect offset %v too large", i.Off)
		}

		return appendNtoh(opts.regA, sizeToEBPF[i.Size],
			// last packet guard set opts.regIndirect to packetstart + x
			asm.LoadMem(opts.regA, opts.regIndirect, int16(i.Off), sizeToEBPF[i.Size]),
		)
	case bpf.LoadMemShift:
		if i.Off > math.MaxInt16 {
			return nil, errors.Errorf("LoadMemShift offset %v too large", i.Off)
		}

		return ebpfInsn(
			asm.LoadMem(opts.regX, opts.PacketStart, int16(i.Off), asm.Byte),
			asm.And.Imm32(opts.regX, 0xF), // clear upper 4 bits
			asm.LSh.Imm32(opts.regX, 2),   // 32bit words to bytes
		)

	case bpf.StoreScratch:
		return ebpfInsn(asm.StoreMem(asm.R10, opts.stackOffset(i.N), opts.reg(i.Src), asm.Word))

	case bpf.ALUOpConstant:
		return ebpfInsn(aluToEBPF[i.Op].Imm32(opts.regA, int32(i.Val)))
	case bpf.ALUOpX:
		return ebpfInsn(aluToEBPF[i.Op].Reg32(opts.regA, opts.regX))
	case bpf.NegateA:
		return ebpfInsn(asm.Neg.Imm32(opts.regA, 0))

	case bpf.Jump:
		return ebpfInsn(asm.Ja.Label(opts.label(blk.skipToBlock(skip(i.Skip)).Label())))
	case bpf.JumpIf:
		return condToEBPF(opts, skip(i.SkipTrue), skip(i.SkipFalse), blk, i.Cond, func(jo asm.JumpOp, label string) asm.Instructions {
			// eBPF immediates are signed, zero extend into temp register
			if int32(i.Val) < 0 {
				return asm.Instructions{
					asm.Mov.Imm32(opts.regTmp, int32(i.Val)),
					jo.Reg(opts.regA, opts.regTmp, label),
				}
			}

			return asm.Instructions{jo.Imm(opts.regA, int32(i.Val), label)}
		})
	case bpf.JumpIfX:
		return condToEBPF(opts, skip(i.SkipTrue), skip(i.SkipFalse), blk, i.Cond, func(jo asm.JumpOp, label string) asm.Instructions {
			return asm.Instructions{jo.Reg(opts.regA, opts.regX, label)}
		})

	case bpf.RetA:
		// a == 0 -> no match
		return ebpfInsn(
			asm.JEq.Imm(opts.regA, 0, opts.NoMatchLabel),
			asm.Ja.Label(opts.MatchLabel),
		)
	case bpf.RetConstant:
		if i.Val == 0 {
			return ebpfInsn(asm.Ja.Label(opts.NoMatchLabel))
		} else {
			return ebpfInsn(asm.Ja.Label(opts.MatchLabel))
		}

	case bpf.TXA:
		return ebpfInsn(asm.Mov.Reg32(opts.regA, opts.regX))
	case bpf.TAX:
		return ebpfInsn(asm.Mov.Reg32(opts.regX, opts.regA))

	case packetGuardAbsolute:
		return ebpfInsn(
			asm.Mov.Reg(opts.regTmp, opts.PacketStart),
			asm.Add.Imm(opts.regTmp, int32(i.Len)),
			asm.JGT.Reg(opts.regTmp, opts.PacketEnd, opts.NoMatchLabel),
		)
	case packetGuardIndirect:
		return ebpfInsn(
			// packet start + x
			asm.Mov.Reg(opts.regIndirect, opts.PacketStart),
			asm.Add.Reg(opts.regIndirect, opts.regX),
			// different reg (so actual load picks offset), but same verifier context id
			asm.Mov.Reg(opts.regTmp, opts.regIndirect),
			asm.Add.Imm(opts.regTmp, int32(i.Len)),
			asm.JGT.Reg(opts.regTmp, opts.PacketEnd, opts.NoMatchLabel),
		)

	case initializeScratch:
		return ebpfInsn(asm.StoreImm(asm.R10, opts.stackOffset(i.N), 0, asm.Word))

	case checkXNotZero:
		return ebpfInsn(asm.JEq.Imm(opts.regX, 0, opts.NoMatchLabel))

	default:
		return nil, errors.Errorf("unsupported instruction %v", insn)
	}
}

func appendNtoh(reg asm.Register, size asm.Size, insns ...asm.Instruction) (asm.Instructions, error) {
	if size == asm.Byte {
		return insns, nil
	}

	// BPF_FROM_BE should be a nop on big endian architectures
	return append(insns, asm.HostTo(asm.BE, reg, size)), nil
}

func condToEBPF(opts ebpfOpts, skipTrue, skipFalse skip, blk *block, cond bpf.JumpTest, insn func(jo asm.JumpOp, label string) asm.Instructions) (asm.Instructions, error) {
	var condToJump = map[bpf.JumpTest]asm.JumpOp{
		bpf.JumpEqual:          asm.JEq,
		bpf.JumpNotEqual:       asm.JNE,
		bpf.JumpGreaterThan:    asm.JGT,
		bpf.JumpLessThan:       asm.JLT,
		bpf.JumpGreaterOrEqual: asm.JGE,
		bpf.JumpLessOrEqual:    asm.JLE,
		bpf.JumpBitsSet:        asm.JSet,
		// BitsNotSet doesn't map to anything nicely
	}

	trueLabel := opts.label(blk.skipToBlock(skipTrue).Label())
	falseLabel := opts.label(blk.skipToBlock(skipFalse).Label())

	// no skipFalse, we only have to explicitly jump to one block
	trueOnly := skipFalse == 0

	// No native BitsNotSet, convert to BitsSet
	if cond == bpf.JumpBitsNotSet {
		cond = bpf.JumpBitsSet

		trueLabel, falseLabel = falseLabel, trueLabel

		trueOnly = false

		// skipFalse could have fallen through before
		blk.skipToBlock(skipFalse).IsTarget = true
	}

	if trueOnly {
		return insn(condToJump[cond], trueLabel), nil
	}

	return append(
		insn(condToJump[cond], trueLabel),
		asm.Ja.Label(falseLabel),
	), nil
}

func ebpfInsn(insns ...asm.Instruction) (asm.Instructions, error) {
	return insns, nil
}
