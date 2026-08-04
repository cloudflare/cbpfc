// Package clang implements a simple wrapper for invoking clang to
// compile C to eBPF
package clang

import (
	"fmt"
	"io/ioutil"
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
	// Uses a temporary directory if empty.
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

// Compile compiles a C source string into an ELF, and returns metadata in Res.
func CompileRes(source []byte, name string, opts Opts) (Res, error) {
	var err error

	outdir := opts.Output
	if outdir == "" {
		outdir, err = ioutil.TempDir("", "cbpfc-clang")
		if err != nil {
			return Res{}, errors.Wrap(err, "can't create output directory")
		}
		defer os.RemoveAll(outdir)
	} else {
		_ = os.Mkdir(outdir, 0755)
	}

	inputFile := fmt.Sprintf("%s.c", name)
	outputFile := fmt.Sprintf("%s.elf", name)
	err = ioutil.WriteFile(filepath.Join(outdir, inputFile), source, 0644)
	if err != nil {
		return Res{}, errors.Wrap(err, "can't write out program")
	}

	flags := []string{
		"-O2",
		"-Wall", "-Werror",
		"-nostdinc",
		"-c",
		"-target", "bpf",
		inputFile,
		"-o", outputFile,
	}

	for _, include := range opts.Include {
		// debug build script will be in a different directory, relative imports won't work
		absInclude, err := filepath.Abs(include)
		if err != nil {
			return Res{}, errors.Wrapf(err, "can't get absolute path to include %s", include)
		}

		flags = append(flags, "-I", absInclude)
	}

	if opts.EmitDebug {
		flags = append(flags, "-g")
	}

	cmd := exec.Command(opts.Clang, flags...)

	// debug build script
	if opts.Output != "" {
		cmdline := cmd.Path + " " + strings.Join(flags, " ") + "\n"
		err := ioutil.WriteFile(filepath.Join(outdir, "build"), []byte(cmdline), 0644)
		if err != nil {
			return Res{}, errors.Wrap(err, "can't write build cmdline")
		}
	}

	cmd.Dir = outdir
	_, err = cmd.Output()
	if err != nil {
		switch e := err.(type) {
		case *exec.ExitError:
			return Res{}, errors.Wrapf(e, "unable to compile C:\n%s", string(e.Stderr))
		default:
			return Res{}, errors.Wrapf(e, "unable to compile C")
		}
	}

	elf, err := ioutil.ReadFile(filepath.Join(outdir, outputFile))
	if err != nil {
		return Res{}, errors.Wrap(err, "can't read ELF")
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
