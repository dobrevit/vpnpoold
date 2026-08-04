package openvpn

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
)

const (
	managementStateConnected    = "CONNECTED"
	managementStateReconnecting = "RECONNECTING"
	managementStateExiting      = "EXITING"
)

type ManagementState struct {
	Name       string
	Successful bool
}

type ManagementWatcher interface {
	Watch(context.Context, chan<- ManagementState) error
}

type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// ManagementClient consumes OpenVPN state notifications over a private Unix
// management socket. It deliberately does not log or return raw management
// lines because password prompts and server-provided messages may contain
// sensitive values.
type ManagementClient struct {
	SocketPath    string
	Dialer        ContextDialer
	RetryInterval time.Duration
	Provider      CredentialProvider
}

func (c ManagementClient) Watch(ctx context.Context, events chan<- ManagementState) error {
	if ctx == nil {
		return errors.New("management context is required")
	}
	if events == nil {
		return errors.New("management event channel is required")
	}
	if !filepath.IsAbs(c.SocketPath) {
		return errors.New("management socket path must be absolute")
	}
	retryInterval := c.RetryInterval
	if retryInterval <= 0 {
		retryInterval = 50 * time.Millisecond
	}
	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	connection, err := dialManagementSocket(ctx, dialer, c.SocketPath, retryInterval)
	if err != nil {
		return err
	}
	defer connection.Close()

	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-closed:
		}
	}()
	defer close(closed)

	if _, err := connection.Write([]byte("state on\nhold release\n")); err != nil {
		return fmt.Errorf("initialize OpenVPN management session: %w", err)
	}

	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	var pendingChallenge *dynamicChallenge
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ">PASSWORD:") {
			if err := c.handlePassword(
				ctx,
				connection,
				line,
				&pendingChallenge,
			); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ">INFOMSG:CR_TEXT:") {
			if err := c.handleTextChallenge(ctx, connection, line); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ">HOLD:") {
			if _, err := connection.Write([]byte("hold release\n")); err != nil {
				return fmt.Errorf("release OpenVPN management hold: %w", err)
			}
			continue
		}
		state, ok := parseManagementState(line)
		if !ok {
			continue
		}
		select {
		case events <- state:
		case <-ctx.Done():
			return nil
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read OpenVPN management session: %w", err)
	}
	return errors.New("OpenVPN management session closed unexpectedly")
}

type dynamicChallenge struct {
	stateID   string
	username  string
	challenge Challenge
}

func (c ManagementClient) handlePassword(
	ctx context.Context,
	connection io.Writer,
	line string,
	pending **dynamicChallenge,
) error {
	const (
		authRequest = ">PASSWORD:Need 'Auth' username/password"
		keyRequest  = ">PASSWORD:Need 'Private Key' password"
	)
	if strings.HasPrefix(line, authRequest) {
		if c.Provider == nil {
			return errors.New("OpenVPN requested management credentials but no credential provider is configured")
		}
		suffix := strings.TrimSpace(strings.TrimPrefix(line, authRequest))
		if *pending != nil {
			if suffix != "" {
				return errors.New("OpenVPN combined dynamic and static management challenges")
			}
			challenge := *pending
			response, err := c.Provider.ChallengeResponse(ctx, challenge.challenge)
			if err != nil {
				return fmt.Errorf("answer OpenVPN dynamic challenge: %w", err)
			}
			password := "CRV1::" + challenge.stateID + "::" + response
			if err := writeUsernamePassword(
				connection,
				challenge.username,
				password,
			); err != nil {
				return err
			}
			*pending = nil
			return nil
		}

		username, password, err := c.Provider.UsernamePassword(ctx)
		if err != nil {
			return fmt.Errorf("obtain OpenVPN management credentials: %w", err)
		}
		if suffix != "" {
			challenge, parseErr := parseStaticChallenge(suffix)
			if parseErr != nil {
				return parseErr
			}
			response, responseErr := c.Provider.ChallengeResponse(ctx, challenge)
			if responseErr != nil {
				return fmt.Errorf("answer OpenVPN static challenge: %w", responseErr)
			}
			password = "SCRV1:" +
				base64.StdEncoding.EncodeToString([]byte(password)) + ":" +
				base64.StdEncoding.EncodeToString([]byte(response))
		}
		return writeUsernamePassword(connection, username, password)
	}
	if line == keyRequest {
		if c.Provider == nil {
			return errors.New("OpenVPN requested a private-key password but no credential provider is configured")
		}
		password, err := c.Provider.PrivateKeyPassword(ctx)
		if err != nil {
			return fmt.Errorf("obtain OpenVPN private-key password: %w", err)
		}
		return writeManagementValue(connection, "password", "Private Key", password)
	}
	if strings.HasPrefix(line, ">PASSWORD:Verification Failed:") {
		challenge, ok, err := parseDynamicChallenge(line)
		if err != nil {
			return err
		}
		if ok {
			if *pending != nil {
				return errors.New("OpenVPN replaced an unanswered dynamic challenge")
			}
			*pending = &challenge
			return nil
		}
		return errors.New("OpenVPN management credential verification failed")
	}
	if strings.HasPrefix(line, ">PASSWORD:Auth-Token:") {
		return nil
	}
	return errors.New("OpenVPN sent an unsupported management password message")
}

func (c ManagementClient) handleTextChallenge(
	ctx context.Context,
	connection io.Writer,
	line string,
) error {
	if c.Provider == nil {
		return errors.New("OpenVPN requested a text challenge but no credential provider is configured")
	}
	const prefix = ">INFOMSG:CR_TEXT:"
	fields := strings.SplitN(strings.TrimPrefix(line, prefix), ":", 2)
	if len(fields) != 2 {
		return errors.New("OpenVPN sent a malformed text challenge")
	}
	challenge, err := challengeFromFlags(ChallengeText, fields[0], fields[1])
	if err != nil {
		return err
	}
	response, err := c.Provider.ChallengeResponse(ctx, challenge)
	if err != nil {
		return fmt.Errorf("answer OpenVPN text challenge: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(response))
	if _, err := fmt.Fprintf(connection, "cr-response %s\n", encoded); err != nil {
		return fmt.Errorf("write OpenVPN text challenge response: %w", err)
	}
	return nil
}

func parseStaticChallenge(suffix string) (Challenge, error) {
	if !strings.HasPrefix(suffix, "SC:") {
		return Challenge{}, errors.New("OpenVPN sent an unsupported authentication request")
	}
	fields := strings.SplitN(strings.TrimPrefix(suffix, "SC:"), ",", 2)
	if len(fields) != 2 || (fields[0] != "0" && fields[0] != "1") {
		return Challenge{}, errors.New("OpenVPN sent a malformed static challenge")
	}
	return Challenge{
		Kind: ChallengeStatic, Text: fields[1],
		Echo: fields[0] == "1", ResponseRequired: true,
	}, nil
}

func parseDynamicChallenge(line string) (dynamicChallenge, bool, error) {
	const marker = "['CRV1:"
	start := strings.Index(line, marker)
	if start < 0 {
		return dynamicChallenge{}, false, nil
	}
	payload := line[start+len(marker):]
	end := strings.LastIndex(payload, "']")
	if end < 0 {
		return dynamicChallenge{}, false, errors.New("OpenVPN sent a malformed dynamic challenge")
	}
	fields := strings.SplitN(payload[:end], ":", 4)
	if len(fields) != 4 || fields[1] == "" {
		return dynamicChallenge{}, false, errors.New("OpenVPN sent a malformed dynamic challenge")
	}
	usernameBytes, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil || len(usernameBytes) == 0 {
		clearBytes(usernameBytes)
		return dynamicChallenge{}, false, errors.New("OpenVPN sent a malformed dynamic challenge username")
	}
	username := string(usernameBytes)
	clearBytes(usernameBytes)
	if err := validateManagementValue(username); err != nil {
		return dynamicChallenge{}, false, errors.New("OpenVPN sent an invalid dynamic challenge username")
	}
	challenge, err := challengeFromFlags(
		ChallengeDynamic,
		fields[0],
		fields[3],
	)
	if err != nil {
		return dynamicChallenge{}, false, err
	}
	if err := validateManagementValue(fields[1]); err != nil {
		return dynamicChallenge{}, false, errors.New("OpenVPN sent an invalid dynamic challenge state")
	}
	return dynamicChallenge{
		stateID: fields[1], username: username, challenge: challenge,
	}, true, nil
}

func challengeFromFlags(
	kind ChallengeKind,
	flags string,
	text string,
) (Challenge, error) {
	challenge := Challenge{Kind: kind, Text: text}
	if flags == "" {
		return challenge, nil
	}
	for _, flag := range strings.Split(flags, ",") {
		switch flag {
		case "E":
			challenge.Echo = true
		case "R":
			challenge.ResponseRequired = true
		default:
			return Challenge{}, errors.New("OpenVPN challenge contains an unsupported flag")
		}
	}
	return challenge, nil
}

func writeUsernamePassword(connection io.Writer, username, password string) error {
	if err := writeManagementValue(connection, "username", "Auth", username); err != nil {
		return err
	}
	return writeManagementValue(connection, "password", "Auth", password)
}

func writeManagementValue(
	connection io.Writer,
	command, kind, value string,
) error {
	if err := validateManagementValue(value); err != nil {
		return errors.New("refuse invalid OpenVPN management credential value")
	}
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
	if _, err := fmt.Fprintf(
		connection,
		"%s %q \"%s\"\n",
		command,
		kind,
		escaped,
	); err != nil {
		return errors.New("write OpenVPN management credential")
	}
	return nil
}

func dialManagementSocket(
	ctx context.Context,
	dialer ContextDialer,
	socketPath string,
	retryInterval time.Duration,
) (net.Conn, error) {
	for {
		connection, err := dialer.DialContext(ctx, "unix", socketPath)
		if err == nil {
			return connection, nil
		}
		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, fmt.Errorf("connect to OpenVPN management socket: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func parseManagementState(line string) (ManagementState, bool) {
	if !strings.HasPrefix(line, ">STATE:") {
		return ManagementState{}, false
	}
	line = strings.TrimPrefix(line, ">STATE:")
	fields := strings.Split(line, ",")
	if len(fields) < 3 {
		return ManagementState{}, false
	}
	switch fields[1] {
	case managementStateConnected:
		return ManagementState{
			Name:       managementStateConnected,
			Successful: fields[2] == "SUCCESS",
		}, true
	case managementStateReconnecting, managementStateExiting:
		return ManagementState{Name: fields[1]}, true
	default:
		return ManagementState{}, false
	}
}
