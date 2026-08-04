package openvpn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dobrevit/vpnpoold/internal/process"
)

const (
	maxCredentialFileBytes  = 16 * 1024
	maxChallengeResponse    = 4096
	defaultChallengeTimeout = 30 * time.Second
)

type ChallengeKind string

const (
	ChallengeStatic  ChallengeKind = "static"
	ChallengeDynamic ChallengeKind = "dynamic"
	ChallengeText    ChallengeKind = "text"
)

type Challenge struct {
	Kind             ChallengeKind `json:"kind"`
	Text             string        `json:"text"`
	Echo             bool          `json:"echo"`
	ResponseRequired bool          `json:"response_required"`
}

type CredentialProvider interface {
	UsernamePassword(context.Context) (string, string, error)
	PrivateKeyPassword(context.Context) (string, error)
	ChallengeResponse(context.Context, Challenge) (string, error)
}

// FileCredentialProvider reads secrets only when OpenVPN requests them. A
// challenge helper receives a bounded JSON request on stdin and returns only
// the response on stdout. It is executed directly without a shell and neither
// its output nor its stderr is included in returned errors.
type FileCredentialProvider struct {
	UsernamePasswordFile   string
	PrivateKeyPasswordFile string
	ChallengeCommand       string
	ChallengeTimeout       time.Duration
	Runner                 process.Runner
}

func (p FileCredentialProvider) UsernamePassword(context.Context) (string, string, error) {
	if p.UsernamePasswordFile == "" {
		return "", "", errors.New("management username/password source is not configured")
	}
	data, err := readPrivateCredentialFile(p.UsernamePasswordFile)
	if err != nil {
		return "", "", fmt.Errorf("read management username/password: %w", err)
	}
	defer clearBytes(data)
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) != 2 {
		return "", "", errors.New("management username/password file must contain exactly two lines")
	}
	username := strings.TrimSuffix(string(lines[0]), "\r")
	password := strings.TrimSuffix(string(lines[1]), "\r")
	if username == "" {
		return "", "", errors.New("management username must not be empty")
	}
	if err := validateManagementValue(username); err != nil {
		return "", "", fmt.Errorf("management username: %w", err)
	}
	if err := validateManagementValue(password); err != nil {
		return "", "", fmt.Errorf("management password: %w", err)
	}
	return username, password, nil
}

func (p FileCredentialProvider) PrivateKeyPassword(context.Context) (string, error) {
	if p.PrivateKeyPasswordFile == "" {
		return "", errors.New("management private-key password source is not configured")
	}
	data, err := readPrivateCredentialFile(p.PrivateKeyPasswordFile)
	if err != nil {
		return "", fmt.Errorf("read management private-key password: %w", err)
	}
	defer clearBytes(data)
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	password := string(data)
	if password == "" {
		return "", errors.New("management private-key password must not be empty")
	}
	if err := validateManagementValue(password); err != nil {
		return "", fmt.Errorf("management private-key password: %w", err)
	}
	return password, nil
}

func (p FileCredentialProvider) ChallengeResponse(
	ctx context.Context,
	challenge Challenge,
) (string, error) {
	if p.ChallengeCommand == "" {
		if challenge.ResponseRequired {
			return "", errors.New("management challenge response helper is not configured")
		}
		return "", nil
	}
	if p.Runner == nil {
		return "", errors.New("management challenge runner is not configured")
	}
	request, err := json.Marshal(challenge)
	if err != nil {
		return "", errors.New("encode management challenge request")
	}
	request = append(request, '\n')
	timeout := p.ChallengeTimeout
	if timeout <= 0 {
		timeout = defaultChallengeTimeout
	}
	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := p.Runner.Run(runContext, process.Command{
		Path:  p.ChallengeCommand,
		Env:   []string{"LANG=C", "PATH=/usr/sbin:/usr/bin"},
		Stdin: request,
	})
	clearBytes(request)
	if err != nil {
		return "", errors.New("management challenge helper failed")
	}
	if len(result.Stdout) > maxChallengeResponse {
		return "", errors.New("management challenge response is too large")
	}
	response := strings.TrimSuffix(result.Stdout, "\n")
	response = strings.TrimSuffix(response, "\r")
	if err := validateManagementValue(response); err != nil {
		return "", fmt.Errorf("management challenge response: %w", err)
	}
	if challenge.ResponseRequired && response == "" {
		return "", errors.New("management challenge response must not be empty")
	}
	return response, nil
}

func readPrivateCredentialFile(path string) ([]byte, error) {
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("credential file parent directory is not trusted")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("credential file is unavailable")
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credential file is not a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open credential file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, errors.New("inspect opened credential file")
	}
	after, err := os.Lstat(path)
	if err != nil ||
		!after.Mode().IsRegular() ||
		!os.SameFile(before, opened) ||
		!os.SameFile(opened, after) {
		return nil, errors.New("credential file changed while opening")
	}
	reader := io.LimitReader(file, maxCredentialFileBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, errors.New("read credential file")
	}
	if len(data) > maxCredentialFileBytes {
		clearBytes(data)
		return nil, errors.New("credential file is too large")
	}
	return data, nil
}

func validateManagementValue(value string) error {
	if strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("value contains a prohibited control character")
	}
	return nil
}

func clearBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
