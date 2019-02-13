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

type EBPFOpts struct {
	// Pointer to start of packet - not modified
	PacketStart asm.Register
	// Pointer to end of packet - not modified
	PacketEnd asm.Register

	// Registers mapping directly to cBPF
	RegA asm.Register
	RegX asm.Register
	// Temp / scratch register
	RegTmp asm.Register
	// Register for indirect packet loads
	// Allows the range of a packet guard to be preserved across multiple loads by the verifier
	RegIndirect asm.Register

	// First stack offset we can use
	StackOffset int

	// Label to jump to when packet matches
	MatchLabel string

	// Label to jump to when packet doesn't match
	NoMatchLabel string

	// Prefix to prepend to generated labels
	LabelPrefix string
}

func (r EBPFOpts) reg(reg bpf.Register) asm.Register {
	switch reg {
	case bpf.RegA:
		return r.RegA
	case bpf.RegX:
		return r.RegX
	default:
		panic("unknown bpf register")
	}
}

func (r EBPFOpts) label(name string) string {
	return fmt.Sprintf("%s_%s", r.LabelPrefix, name)
}

func (r EBPFOpts) stackOffset(n int) int16 {
	return -int16(r.StackOffset + n*4)
}

// ToEBF converts cBPF instructions to eBPF
func ToEBPF(insns []bpf.Instruction, opts EBPFOpts) ([]asm.Instruction, error) {
	blocks, err := compile(insns)
	if err != nil {
		return nil, err
	}

	err = checkRegs(opts.PacketStart, opts.PacketEnd, opts.RegA, opts.RegX, opts.RegTmp, opts.RegIndirect)
	if err != nil {
		return nil, err
	}

	if opts.StackOffset&1 == 1 {
		return nil, errors.Errorf("unaligned stack offset")
	}

	eInsns := []asm.Instruction{}

	// TODO - Better 0 initialization
	//   m[] should be 0 initialized if it's read from before being written to.
	//   a & x should only be reset to 0 if they're read from before being written to.
	// In practice always resetting a & x works, and reading zero initialized m[] is rather pointless,
	// so no programs seem to rely on it
	// cbpftoc proper could add 0 init instructions as required so both backends benefit.
	eInsns = append(eInsns,
		asm.Mov.Imm32(opts.RegA, 0),
		asm.Mov.Imm32(opts.RegX, 0),
	)

	for _, block := range blocks {
		for i, insn := range block.insns {
			eInsn, err := insnToEBPF(insn, block, opts)
			if err != nil {
				return nil, errors.Wrapf(err, "unable to compile %v", insn)
			}

			// First insn of the block, add symbol so it can be referenced in jumps
			if block.IsTarget && i == 0 {
				eInsn[0].Symbol = opts.label(block.Label())
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
func insnToEBPF(insn instruction, blk *block, opts EBPFOpts) (asm.Instructions, error) {
	switch i := insn.Instruction.(type) {

	case bpf.LoadConstant:
		return ebpfInsn(asm.Mov.Imm32(opts.reg(i.Dst), int32(i.Val)))
	case bpf.LoadScratch:
		return ebpfInsn(asm.LoadMem(opts.reg(i.Dst), asm.R10, opts.stackOffset(i.N), asm.Word))
	case bpf.LoadAbsolute:
		if i.Off > math.MaxInt16 {
			return nil, errors.Errorf("LoadAbsolute offset %v too large", i.Off)
		}

		return appendNtoh(opts.RegA, sizeToEBPF[i.Size],
			asm.LoadMem(opts.RegA, opts.PacketStart, int16(i.Off), sizeToEBPF[i.Size]),
		)
	case bpf.LoadIndirect:
		if i.Off > math.MaxInt16 {
			return nil, errors.Errorf("LoadIndirect offset %v too large", i.Off)
		}

		return appendNtoh(opts.RegA, sizeToEBPF[i.Size],
			// last packet guard set opts.RegIndirect to packetstart + x
			asm.LoadMem(opts.RegA, opts.RegIndirect, int16(i.Off), sizeToEBPF[i.Size]),
		)
	case bpf.LoadMemShift:
		if i.Off > math.MaxInt16 {
			return nil, errors.Errorf("LoadMemShift offset %v too large", i.Off)
		}

		return ebpfInsn(
			asm.LoadMem(opts.RegX, opts.PacketStart, int16(i.Off), asm.Byte),
			asm.And.Imm32(opts.RegX, 0xF), // clear upper 4 bits
			asm.LSh.Imm32(opts.RegX, 2),   // 32bit words to bytes
		)

	case bpf.StoreScratch:
		return ebpfInsn(asm.StoreMem(asm.R10, opts.stackOffset(i.N), opts.reg(i.Src), asm.Word))

	case bpf.ALUOpConstant:
		return ebpfInsn(aluToEBPF[i.Op].Imm32(opts.RegA, int32(i.Val)))
	case bpf.ALUOpX:
		return ebpfInsn(aluToEBPF[i.Op].Reg32(opts.RegA, opts.RegX))
	case bpf.NegateA:
		return ebpfInsn(asm.Neg.Imm32(opts.RegA, 0))

	case bpf.Jump:
		return ebpfInsn(asm.Ja.Label(opts.label(blk.skipToBlock(skip(i.Skip)).Label())))
	case bpf.JumpIf:
		return condToEBPF(opts, skip(i.SkipTrue), skip(i.SkipFalse), blk, i.Cond, func(jo asm.JumpOp, label string) asm.Instructions {
			// eBPF immediates are signed, zero extend into temp register
			if int32(i.Val) < 0 {
				return asm.Instructions{
					asm.Mov.Imm32(opts.RegTmp, int32(i.Val)),
					jo.Reg(opts.RegA, opts.RegTmp, label),
				}
			}

			return asm.Instructions{jo.Imm(opts.RegA, int32(i.Val), label)}
		})
	case bpf.JumpIfX:
		return condToEBPF(opts, skip(i.SkipTrue), skip(i.SkipFalse), blk, i.Cond, func(jo asm.JumpOp, label string) asm.Instructions {
			return asm.Instructions{jo.Reg(opts.RegA, opts.RegX, label)}
		})

	case bpf.RetA:
		// a == 0 -> no match
		return ebpfInsn(
			asm.JEq.Imm(opts.RegA, 0, opts.NoMatchLabel),
			asm.Ja.Label(opts.MatchLabel),
		)
	case bpf.RetConstant:
		if i.Val == 0 {
			return ebpfInsn(asm.Ja.Label(opts.NoMatchLabel))
		} else {
			return ebpfInsn(asm.Ja.Label(opts.MatchLabel))
		}

	case bpf.TXA:
		return ebpfInsn(asm.Mov.Reg32(opts.RegA, opts.RegX))
	case bpf.TAX:
		return ebpfInsn(asm.Mov.Reg32(opts.RegX, opts.RegA))

	case packetGuardAbsolute:
		return ebpfInsn(
			asm.Mov.Reg(opts.RegTmp, opts.PacketStart),
			asm.Add.Imm(opts.RegTmp, int32(i.Len)),
			asm.JGT.Reg(opts.RegTmp, opts.PacketEnd, opts.NoMatchLabel),
		)
	case packetGuardIndirect:
		return ebpfInsn(
			// packet start + x
			asm.Mov.Reg(opts.RegIndirect, opts.PacketStart),
			asm.Add.Reg(opts.RegIndirect, opts.RegX),
			// different reg (so actual load picks offset), but same verifier context
			asm.Mov.Reg(opts.RegTmp, opts.RegIndirect),
			asm.Add.Imm(opts.RegTmp, int32(i.Len)),
			asm.JGT.Reg(opts.RegTmp, opts.PacketEnd, opts.NoMatchLabel),
		)

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

func condToEBPF(opts EBPFOpts, skipTrue, skipFalse skip, blk *block, cond bpf.JumpTest, insn func(jo asm.JumpOp, label string) asm.Instructions) (asm.Instructions, error) {
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
