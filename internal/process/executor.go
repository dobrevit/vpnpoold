package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const defaultOutputLimit = 64 * 1024

type Command struct {
	Path  string
	Args  []string
	Env   []string
	Dir   string
	Stdin []byte
}

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type Runner interface {
	Run(context.Context, Command) (Result, error)
}

type ManagedProcess interface {
	PID() int
	Wait() error
	Signal(os.Signal) error
	Kill() error
}

type Starter interface {
	Start(context.Context, Command) (ManagedProcess, error)
}

type OSRunner struct {
	OutputLimit int
}

type OSStarter struct{}

func (OSStarter) Start(ctx context.Context, command Command) (ManagedProcess, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, command.Path, command.Args...)
	cmd.Env = append([]string(nil), command.Env...)
	cmd.Dir = command.Dir
	if len(command.Stdin) != 0 {
		cmd.Stdin = bytes.NewReader(command.Stdin)
	}
	// Long-running OpenVPN output is discarded here because profiles can cause
	// secrets to be printed. Structured lifecycle events come from the
	// supervisor and the private management interface instead.
	if err := cmd.Start(); err != nil {
		return nil, &RunError{Path: command.Path, ExitCode: -1, Err: err}
	}
	return &osProcess{cmd: cmd}, nil
}

type osProcess struct {
	cmd *exec.Cmd
}

func (p *osProcess) PID() int {
	return p.cmd.Process.Pid
}

func (p *osProcess) Wait() error {
	return p.cmd.Wait()
}

func (p *osProcess) Signal(signal os.Signal) error {
	return p.cmd.Process.Signal(signal)
}

func (p *osProcess) Kill() error {
	return p.cmd.Process.Kill()
}

func (r OSRunner) Run(ctx context.Context, command Command) (Result, error) {
	if err := command.Validate(); err != nil {
		return Result{}, err
	}
	limit := r.OutputLimit
	if limit <= 0 {
		limit = defaultOutputLimit
	}

	// Arguments are passed directly to execve. A shell is intentionally never
	// involved, so metacharacters cannot become additional commands.
	cmd := exec.CommandContext(ctx, command.Path, command.Args...)
	cmd.Env = append([]string(nil), command.Env...)
	cmd.Dir = command.Dir
	if len(command.Stdin) != 0 {
		cmd.Stdin = bytes.NewReader(command.Stdin)
	}
	var stdout, stderr limitedBuffer
	stdout.remaining = limit
	stderr.remaining = limit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}
	if err == nil {
		return result, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	} else {
		result.ExitCode = -1
	}
	// Do not include arguments or captured output in the error: both can carry
	// paths or process output that an OpenVPN profile considers sensitive.
	return result, &RunError{Path: command.Path, ExitCode: result.ExitCode, Err: err}
}

func (c Command) Validate() error {
	if c.Path == "" {
		return errors.New("process path must not be empty")
	}
	if !filepath.IsAbs(c.Path) {
		return fmt.Errorf("process path %q must be absolute", c.Path)
	}
	if strings.IndexByte(c.Path, 0) >= 0 {
		return errors.New("process path contains a NUL byte")
	}
	for index, arg := range c.Args {
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("process argument %d contains a NUL byte", index)
		}
	}
	for index, value := range c.Env {
		separator := strings.IndexByte(value, '=')
		if separator <= 0 || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("process environment entry %d is invalid", index)
		}
	}
	if c.Dir != "" && !filepath.IsAbs(c.Dir) {
		return errors.New("process working directory must be absolute")
	}
	return nil
}

type RunError struct {
	Path     string
	ExitCode int
	Err      error
}

func (e *RunError) Error() string {
	if e.ExitCode >= 0 {
		return fmt.Sprintf("run %q: process exited with code %d", e.Path, e.ExitCode)
	}
	return fmt.Sprintf("run %q: %v", e.Path, e.Err)
}

func (e *RunError) Unwrap() error {
	return e.Err
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	if b.remaining > 0 {
		toWrite := len(data)
		if toWrite > b.remaining {
			toWrite = b.remaining
		}
		_, _ = b.buffer.Write(data[:toWrite])
		b.remaining -= toWrite
	}
	return originalLength, nil
}

func (b *limitedBuffer) String() string {
	return b.buffer.String()
}
