// Package clang implements a simple wrapper for invoking clang to
// compile C to eBPF
package clang

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Opts configure how an XDP program is compiled / built
type Opts struct {
	// clang binary to use
	Clang string

	// Header directories to include
	Include []string

	// Destination directory for compiled programs.
	// Uses stdout if empty.
	Output string

	// Emit DWARF debug info in the XDP elf.
	// Required for BTF.
	EmitDebug bool
}

// Res is the result of compiling a C source with clang.
type Res struct {
	ELF []byte

	// CPUTime is the user + system CPU time used by this clang invocation.
	CPUTime time.Duration
}

func (o Opts) cmd(inputFile string, outputFile string) (*exec.Cmd, error) {
	flags := []string{
		"-O2",
		"-Wall", "-Werror",
		"-nostdinc",
		"-c",
		"-target", "bpf",
		// read C source (to support stdin)
		"-x", "c", inputFile,
		// output
		"-o", outputFile,
	}

	for _, include := range o.Include {
		// debug build script will be in a different directory, relative imports won't work
		absInclude, err := filepath.Abs(include)
		if err != nil {
			return nil, errors.Wrapf(err, "can't get absolute path to include %s", include)
		}

		flags = append(flags, "-I", absInclude)
	}

	if o.EmitDebug {
		flags = append(flags, "-g")
	}

	return exec.Command(o.Clang, flags...), nil
}

// Compile compiles a C source string into an ELF, and returns metadata in Res.
func CompileRes(source []byte, name string, opts Opts) (Res, error) {
	// Use stdout if no output dir is set to avoid a temporary file.
	input := "-"
	output := "-"
	outputFunc := func(stdout []byte) ([]byte, error) {
		return stdout, nil
	}
	if opts.Output != "" {
		_ = os.Mkdir(opts.Output, 0755)
		input = filepath.Join(opts.Output, fmt.Sprintf("%s.c", name))
		if err := os.WriteFile(input, source, 0644); err != nil {
			return Res{}, err
		}
		output = filepath.Join(opts.Output, fmt.Sprintf("%s.elf", name))
		outputFunc = func(stdout []byte) ([]byte, error) {
			return os.ReadFile(output)
		}
	}

	cmd, err := opts.cmd(input, output)
	if err != nil {
		return Res{}, err
	}

	// debug build script
	if opts.Output != "" {
		cmdline := cmd.Path + " " + strings.Join(cmd.Args, " ") + "\n"
		err := os.WriteFile(filepath.Join(opts.Output, "build"), []byte(cmdline), 0644)
		if err != nil {
			return Res{}, errors.Wrap(err, "can't write build cmdline")
		}
	} else {
		cmd.Stdin = bytes.NewReader(source)
	}

	return compileRes(cmd, outputFunc)
}

func compileRes(cmd *exec.Cmd, output func(stdout []byte) ([]byte, error)) (Res, error) {
	stdout, err := cmd.Output()
	if err != nil {
		switch e := err.(type) {
		case *exec.ExitError:
			return Res{}, errors.Wrapf(e, "unable to compile C:\n%s", string(e.Stderr))
		default:
			return Res{}, errors.Wrapf(e, "unable to compile C")
		}
	}
	elf, err := output(stdout)
	if err != nil {
		return Res{}, err
	}

	return Res{
		ELF:     elf,
		CPUTime: cmd.ProcessState.SystemTime() + cmd.ProcessState.UserTime(),
	}, nil
}

// Compile compiles a C source string into an ELF.
func Compile(source []byte, name string, opts Opts) ([]byte, error) {
	res, err := CompileRes(source, name, opts)
	return res.ELF, err
}
