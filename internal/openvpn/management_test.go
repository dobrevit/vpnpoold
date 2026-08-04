package openvpn

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestManagementClientReleasesHoldAndReportsState(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})
	dialer := &singleConnectionDialer{connection: clientConnection}
	client := ManagementClient{
		SocketPath:    "/run/vpnpoold/test.management.sock",
		Dialer:        dialer,
		RetryInterval: time.Millisecond,
	}
	events := make(chan ManagementState, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.Watch(ctx, events)
	}()

	reader := bufio.NewReader(serverConnection)
	for _, expected := range []string{"state on\n", "hold release\n"} {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line != expected {
			t.Fatalf("management command = %q, want %q", line, expected)
		}
	}
	if _, err := serverConnection.Write([]byte(
		">HOLD:Waiting for hold release:1\n" +
			">STATE:1,CONNECTED,SUCCESS,10.0.0.2,198.51.100.1\n",
	)); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "hold release\n" {
		t.Fatalf("hold command = %q", line)
	}
	select {
	case event := <-events:
		if event.Name != managementStateConnected || !event.Successful {
			t.Fatalf("event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("management state was not reported")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
}

func TestManagementClientRefusesUnhandledCredentialPrompt(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})
	client := ManagementClient{
		SocketPath: "/run/vpnpoold/test.management.sock",
		Dialer:     &singleConnectionDialer{connection: clientConnection},
	}
	done := make(chan error, 1)
	go func() {
		done <- client.Watch(context.Background(), make(chan ManagementState, 1))
	}()
	reader := bufio.NewReader(serverConnection)
	for range 2 {
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := serverConnection.Write([]byte(">PASSWORD:Need 'Auth' username/password\n")); err != nil {
		t.Fatal(err)
	}
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "no credential provider") {
		t.Fatalf("Watch() error = %v", err)
	}
}

func TestManagementClientSuppliesEscapedUsernamePassword(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})
	client := ManagementClient{
		SocketPath: "/run/vpnpoold/test.management.sock",
		Dialer:     &singleConnectionDialer{connection: clientConnection},
		Provider: &recordingCredentialProvider{
			username: `ali"ce`,
			password: `p\ass`,
		},
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- client.Watch(ctx, make(chan ManagementState, 1))
	}()
	reader := initializeManagementTest(t, serverConnection)
	if _, err := serverConnection.Write([]byte(
		">PASSWORD:Need 'Auth' username/password\n",
	)); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"username \"Auth\" \"ali\\\"ce\"\n",
		"password \"Auth\" \"p\\\\ass\"\n",
	} {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line != expected {
			t.Fatalf("management command = %q, want %q", line, expected)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
}

func TestManagementClientAnswersStaticChallenge(t *testing.T) {
	provider := &recordingCredentialProvider{
		username: "alice", password: "secret", response: "8675309",
	}
	clientConnection, serverConnection := net.Pipe()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})
	client := ManagementClient{
		SocketPath: "/run/vpnpoold/test.management.sock",
		Dialer:     &singleConnectionDialer{connection: clientConnection},
		Provider:   provider,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Watch(ctx, make(chan ManagementState, 1)) }()
	reader := initializeManagementTest(t, serverConnection)
	if _, err := serverConnection.Write([]byte(
		">PASSWORD:Need 'Auth' username/password SC:0,Token PIN\n",
	)); err != nil {
		t.Fatal(err)
	}
	username, _ := reader.ReadString('\n')
	password, _ := reader.ReadString('\n')
	if username != "username \"Auth\" \"alice\"\n" ||
		password != "password \"Auth\" \"SCRV1:c2VjcmV0:ODY3NTMwOQ==\"\n" {
		t.Fatalf("management commands = %q %q", username, password)
	}
	if len(provider.challenges) != 1 ||
		provider.challenges[0].Kind != ChallengeStatic ||
		provider.challenges[0].Text != "Token PIN" ||
		provider.challenges[0].Echo ||
		!provider.challenges[0].ResponseRequired {
		t.Fatalf("challenge = %+v", provider.challenges)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
}

func TestManagementClientAnswersDynamicChallengeOnNextAuthRequest(t *testing.T) {
	provider := &recordingCredentialProvider{response: "123456"}
	clientConnection, serverConnection := net.Pipe()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})
	client := ManagementClient{
		SocketPath: "/run/vpnpoold/test.management.sock",
		Dialer:     &singleConnectionDialer{connection: clientConnection},
		Provider:   provider,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Watch(ctx, make(chan ManagementState, 1)) }()
	reader := initializeManagementTest(t, serverConnection)
	if _, err := serverConnection.Write([]byte(
		">PASSWORD:Verification Failed: 'Auth' " +
			"['CRV1:R,E:opaque-state:YWxpY2U=:Enter: token']\n" +
			">PASSWORD:Need 'Auth' username/password\n",
	)); err != nil {
		t.Fatal(err)
	}
	username, _ := reader.ReadString('\n')
	password, _ := reader.ReadString('\n')
	if username != "username \"Auth\" \"alice\"\n" ||
		password != "password \"Auth\" \"CRV1::opaque-state::123456\"\n" {
		t.Fatalf("management commands = %q %q", username, password)
	}
	if len(provider.challenges) != 1 ||
		provider.challenges[0] != (Challenge{
			Kind: ChallengeDynamic, Text: "Enter: token", Echo: true,
			ResponseRequired: true,
		}) {
		t.Fatalf("challenge = %+v", provider.challenges)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
}

func TestManagementClientAnswersPrivateKeyAndTextChallenges(t *testing.T) {
	provider := &recordingCredentialProvider{
		privateKeyPassword: "key secret",
		response:           "approved",
	}
	clientConnection, serverConnection := net.Pipe()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})
	client := ManagementClient{
		SocketPath: "/run/vpnpoold/test.management.sock",
		Dialer:     &singleConnectionDialer{connection: clientConnection},
		Provider:   provider,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Watch(ctx, make(chan ManagementState, 1)) }()
	reader := initializeManagementTest(t, serverConnection)
	if _, err := serverConnection.Write([]byte(
		">PASSWORD:Need 'Private Key' password\n" +
			">INFOMSG:CR_TEXT:R:Approve login\n",
	)); err != nil {
		t.Fatal(err)
	}
	keyPassword, _ := reader.ReadString('\n')
	textResponse, _ := reader.ReadString('\n')
	if keyPassword != "password \"Private Key\" \"key secret\"\n" ||
		textResponse != "cr-response YXBwcm92ZWQ=\n" {
		t.Fatalf("management commands = %q %q", keyPassword, textResponse)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
}

func TestParseManagementStateRejectsUnrelatedLines(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		want       ManagementState
		wantParsed bool
	}{
		{
			name:       "connected live event",
			line:       ">STATE:1,CONNECTED,SUCCESS,10.0.0.2",
			want:       ManagementState{Name: managementStateConnected, Successful: true},
			wantParsed: true,
		},
		{
			name:       "untagged history is not a live event",
			line:       "2,RECONNECTING,tls-error",
			wantParsed: false,
		},
		{
			name:       "reconnecting live event",
			line:       ">STATE:2,RECONNECTING,tls-error",
			want:       ManagementState{Name: managementStateReconnecting},
			wantParsed: true,
		},
		{name: "info", line: ">INFO:OpenVPN Management Interface", wantParsed: false},
		{name: "malformed", line: ">STATE:broken", wantParsed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, parsed := parseManagementState(test.line)
			if parsed != test.wantParsed || got != test.want {
				t.Fatalf("parseManagementState() = (%+v, %t), want (%+v, %t)", got, parsed, test.want, test.wantParsed)
			}
		})
	}
}

func initializeManagementTest(t *testing.T, connection net.Conn) *bufio.Reader {
	t.Helper()
	reader := bufio.NewReader(connection)
	for range 2 {
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
	}
	return reader
}

type recordingCredentialProvider struct {
	username           string
	password           string
	privateKeyPassword string
	response           string
	challenges         []Challenge
	err                error
}

func (p *recordingCredentialProvider) UsernamePassword(
	context.Context,
) (string, string, error) {
	return p.username, p.password, p.err
}

func (p *recordingCredentialProvider) PrivateKeyPassword(
	context.Context,
) (string, error) {
	return p.privateKeyPassword, p.err
}

func (p *recordingCredentialProvider) ChallengeResponse(
	_ context.Context,
	challenge Challenge,
) (string, error) {
	p.challenges = append(p.challenges, challenge)
	return p.response, p.err
}

type singleConnectionDialer struct {
	connection net.Conn
	used       bool
}

func (d *singleConnectionDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	if d.used {
		return nil, errors.New("connection already used")
	}
	d.used = true
	return d.connection, nil
}
