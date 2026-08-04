package openvpn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// WriteDerivedProfile creates a private OpenVPN profile whose remote
// directives contain only host-resolved IP literals. The source profile is
// read-only and is never modified.
func WriteDerivedProfile(reader ProfileReader, sourcePath, destinationPath string, endpoints []ResolvedEndpoint) (err error) {
	if reader == nil {
		return errors.New("profile reader is required")
	}
	if !filepath.IsAbs(sourcePath) || !filepath.IsAbs(destinationPath) {
		return errors.New("profile paths must be absolute")
	}
	if len(endpoints) == 0 {
		return errors.New("at least one resolved OpenVPN endpoint is required")
	}
	for index, endpoint := range endpoints {
		if !usableEndpoint(endpoint) {
			return fmt.Errorf("resolved OpenVPN endpoint %d is invalid", index)
		}
	}

	data, err := reader.ReadProfile(sourcePath, maxProfileSize)
	if err != nil {
		return fmt.Errorf("read OpenVPN profile: %w", err)
	}
	derived, err := deriveProfile(data, endpoints)
	if err != nil {
		return err
	}
	return writePrivateProfile(destinationPath, derived)
}

// WriteResolvedProfile preserves connection-block boundaries by replacing each
// remote directive in place with only that directive's resolved IP literals.
func WriteResolvedProfile(
	reader ProfileReader,
	sourcePath, destinationPath string,
	groups []ResolvedRemote,
) error {
	return WriteResolvedProfileWithCredentials(
		reader,
		sourcePath,
		destinationPath,
		"",
		groups,
	)
}

// WriteResolvedProfileWithCredentials also replaces the profile's
// auth-user-pass directive with a private, operator-supplied credentials file.
// The credentials are never copied into the derived profile.
func WriteResolvedProfileWithCredentials(
	reader ProfileReader,
	sourcePath, destinationPath, credentialsFile string,
	groups []ResolvedRemote,
) (err error) {
	return WriteResolvedProfileWithCredentialOptions(
		reader,
		sourcePath,
		destinationPath,
		CredentialOptions{File: credentialsFile},
		groups,
	)
}

type CredentialOptions struct {
	File                         string
	QueryViaManagement           bool
	QueryPrivateKeyViaManagement bool
}

// WriteResolvedProfileWithCredentialOptions can leave auth-user-pass
// credential delivery under the daemon-owned management channel. In that
// mode, any source-file argument is removed from the private derived copy so
// OpenVPN cannot bypass the configured provider.
func WriteResolvedProfileWithCredentialOptions(
	reader ProfileReader,
	sourcePath, destinationPath string,
	credentials CredentialOptions,
	groups []ResolvedRemote,
) (err error) {
	if reader == nil {
		return errors.New("profile reader is required")
	}
	if !filepath.IsAbs(sourcePath) || !filepath.IsAbs(destinationPath) {
		return errors.New("profile paths must be absolute")
	}
	if len(groups) == 0 {
		return errors.New("at least one resolved OpenVPN remote is required")
	}
	if credentials.File != "" && !filepath.IsAbs(credentials.File) {
		return errors.New("OpenVPN credentials file path must be absolute")
	}
	if credentials.QueryViaManagement && credentials.File == "" {
		return errors.New("management username/password requires an OpenVPN credentials file")
	}
	for groupIndex, group := range groups {
		if len(group.Endpoints) == 0 {
			return fmt.Errorf("resolved OpenVPN remote %d has no endpoints", groupIndex)
		}
		for endpointIndex, endpoint := range group.Endpoints {
			if !usableEndpoint(endpoint) {
				return fmt.Errorf(
					"resolved OpenVPN remote %d endpoint %d is invalid",
					groupIndex,
					endpointIndex,
				)
			}
		}
	}
	data, err := reader.ReadProfile(sourcePath, maxProfileSize)
	if err != nil {
		return fmt.Errorf("read OpenVPN profile: %w", err)
	}
	derived, err := deriveResolvedProfile(data, groups, credentials)
	if err != nil {
		return err
	}
	return writePrivateProfile(destinationPath, derived)
}

func deriveProfile(data []byte, endpoints []ResolvedEndpoint) ([]byte, error) {
	if len(data) > maxProfileSize {
		return nil, fmt.Errorf("OpenVPN profile exceeds %d-byte limit", maxProfileSize)
	}
	if _, err := parseRemotes(data); err != nil {
		return nil, err
	}

	lines := strings.SplitAfter(string(data), "\n")
	var result strings.Builder
	inlineBlock := ""
	for lineNumber, line := range lines {
		content := strings.TrimSuffix(line, "\n")
		content = strings.TrimSuffix(content, "\r")
		trimmed := strings.TrimSpace(content)
		if inlineBlock != "" {
			result.WriteString(line)
			if strings.EqualFold(trimmed, "</"+inlineBlock+">") {
				inlineBlock = ""
			}
			continue
		}
		if name, ok := openingInlineBlock(trimmed); ok {
			if name == "connection" {
				return nil, fmt.Errorf("OpenVPN connection blocks are unsupported on line %d", lineNumber+1)
			}
			inlineBlock = name
			result.WriteString(line)
			continue
		}
		fields, parseErr := splitDirective(trimmed)
		if parseErr != nil {
			return nil, fmt.Errorf("parse OpenVPN directive on line %d: invalid quoting", lineNumber+1)
		}
		if len(fields) > 0 {
			directive := strings.TrimPrefix(strings.ToLower(fields[0]), "--")
			if directive == "remote" || daemonOwnsManagementDirective(directive) {
				continue
			}
		}
		result.WriteString(line)
	}
	if result.Len() > 0 && !strings.HasSuffix(result.String(), "\n") {
		result.WriteByte('\n')
	}
	result.WriteString("\n# Host-resolved endpoints added by vpnpoold.\n")
	for _, endpoint := range endpoints {
		fmt.Fprintf(&result, "remote %s %d %s\n", endpoint.Address, endpoint.Port, endpoint.Protocol)
	}
	return []byte(result.String()), nil
}

func deriveResolvedProfile(
	data []byte,
	groups []ResolvedRemote,
	credentials CredentialOptions,
) ([]byte, error) {
	remotes, err := parseRemotes(data)
	if err != nil {
		return nil, err
	}
	if len(remotes) != len(groups) {
		return nil, errors.New("resolved OpenVPN remote count does not match the profile")
	}
	for index, remote := range remotes {
		if remote != groups[index].Source {
			return nil, fmt.Errorf("resolved OpenVPN remote %d does not match the profile", index)
		}
	}

	lines := strings.SplitAfter(string(data), "\n")
	var result strings.Builder
	inlineBlock := ""
	remoteIndex := 0
	credentialsReplaced := false
	askpassReplaced := false
	for lineNumber, line := range lines {
		content := strings.TrimSuffix(line, "\n")
		content = strings.TrimSuffix(content, "\r")
		trimmed := strings.TrimSpace(content)
		if inlineBlock != "" {
			result.WriteString(line)
			if strings.EqualFold(trimmed, "</"+inlineBlock+">") {
				inlineBlock = ""
			}
			continue
		}
		if name, ok := openingInlineBlock(trimmed); ok && name != "connection" {
			inlineBlock = name
			result.WriteString(line)
			continue
		}
		fields, parseErr := splitDirective(trimmed)
		if parseErr != nil {
			return nil, fmt.Errorf("parse OpenVPN directive on line %d: invalid quoting", lineNumber+1)
		}
		if len(fields) == 0 {
			result.WriteString(line)
			continue
		}
		directive := strings.TrimPrefix(strings.ToLower(fields[0]), "--")
		if daemonOwnsManagementDirective(directive) {
			continue
		}
		if directive == "askpass" && credentials.QueryPrivateKeyViaManagement {
			if askpassReplaced {
				return nil, errors.New("OpenVPN profile contains multiple askpass directives")
			}
			ending := "\n"
			if strings.HasSuffix(line, "\r\n") {
				ending = "\r\n"
			}
			indentLength := len(content) - len(strings.TrimLeft(content, " \t"))
			fmt.Fprintf(
				&result,
				"%saskpass%s",
				content[:indentLength],
				ending,
			)
			askpassReplaced = true
			continue
		}
		if directive == "auth-user-pass" && credentials.File != "" {
			if credentialsReplaced {
				return nil, errors.New("OpenVPN profile contains multiple auth-user-pass directives")
			}
			ending := "\n"
			if strings.HasSuffix(line, "\r\n") {
				ending = "\r\n"
			}
			indentLength := len(content) - len(strings.TrimLeft(content, " \t"))
			if credentials.QueryViaManagement {
				fmt.Fprintf(
					&result,
					"%sauth-user-pass%s",
					content[:indentLength],
					ending,
				)
			} else {
				fmt.Fprintf(
					&result,
					"%sauth-user-pass %s%s",
					content[:indentLength],
					strconv.Quote(credentials.File),
					ending,
				)
			}
			credentialsReplaced = true
			continue
		}
		if directive != "remote" {
			result.WriteString(line)
			continue
		}
		if remoteIndex >= len(groups) {
			return nil, errors.New("OpenVPN profile contains an unexpected remote directive")
		}
		ending := "\n"
		if strings.HasSuffix(line, "\r\n") {
			ending = "\r\n"
		}
		indentLength := len(content) - len(strings.TrimLeft(content, " \t"))
		indent := content[:indentLength]
		for _, endpoint := range groups[remoteIndex].Endpoints {
			fmt.Fprintf(
				&result,
				"%sremote %s %d %s%s",
				indent,
				endpoint.Address,
				endpoint.Port,
				endpoint.Protocol,
				ending,
			)
		}
		remoteIndex++
	}
	if remoteIndex != len(groups) {
		return nil, errors.New("OpenVPN profile remote replacement was incomplete")
	}
	if credentials.File != "" && !credentialsReplaced {
		return nil, errors.New("OpenVPN credentials file is configured but the profile contains no auth-user-pass directive")
	}
	if result.Len() > 0 && !strings.HasSuffix(result.String(), "\n") {
		result.WriteByte('\n')
	}
	result.WriteString(
		"\n# Enforce full-tunnel IPv4 routing for the isolated worker.\n" +
			"redirect-gateway def1\n",
	)
	return []byte(result.String()), nil
}

func daemonOwnsManagementDirective(directive string) bool {
	return directive == "management" || strings.HasPrefix(directive, "management-")
}

func writePrivateProfile(destinationPath string, data []byte) (err error) {
	directory := filepath.Dir(destinationPath)
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("inspect derived profile directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("derived profile parent is not a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("derived profile directory must not be accessible by group or other")
	}

	temp, err := os.CreateTemp(directory, ".profile-*")
	if err != nil {
		return fmt.Errorf("create temporary derived profile: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err = temp.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict derived profile permissions: %w", err)
	}
	if _, err = temp.Write(data); err != nil {
		return fmt.Errorf("write derived profile: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("sync derived profile: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("close derived profile: %w", err)
	}
	if err = os.Rename(tempPath, destinationPath); err != nil {
		return fmt.Errorf("publish derived profile: %w", err)
	}
	return nil
}

func usableEndpoint(endpoint ResolvedEndpoint) bool {
	address := endpoint.Address.Unmap()
	return address.IsValid() &&
		(address.Is4() || address.Is6()) &&
		!address.IsUnspecified() &&
		!address.IsMulticast() &&
		endpoint.Port != 0 &&
		(endpoint.Protocol == "udp" || endpoint.Protocol == "tcp")
}
