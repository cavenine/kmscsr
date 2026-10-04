package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestParseIPAddresses(t *testing.T) {
	t.Parallel()

	addresses, err := parseIPAddresses([]string{" 192.0.2.1 ", "2001:db8::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 2 || !addresses[0].Equal(net.ParseIP("192.0.2.1")) ||
		!addresses[1].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("unexpected parsed addresses: %#v", addresses)
	}
}

func TestParseIPAddressesRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{"hostname", "not-an-ip"},
		{"empty", ""},
		{"whitespace only", "   "},
		{"CIDR notation", "192.0.2.0/24"},
		{"octet out of range", "256.0.2.1"},
		{"too few octets", "192.0.2"},
		{"IPv6 zone", "fe80::1%eth0"},
		{"bracketed IPv6", "[2001:db8::1]"},
		{"address with port", "192.0.2.1:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// A valid address first shows one bad entry fails the whole list.
			addresses, err := parseIPAddresses([]string{"192.0.2.1", tt.value})
			if err == nil || err.Error() != "invalid IP address: "+tt.value {
				t.Fatalf("expected the error to name %q, got: %v", tt.value, err)
			}
			if addresses != nil {
				t.Errorf("expected no addresses alongside the error, got: %#v", addresses)
			}
		})
	}
}

func TestBuildMetadataResolve(t *testing.T) {
	t.Parallel()

	defaults := buildMetadata{version: defaultVersion, commit: defaultCommit, date: defaultDate}
	linked := buildMetadata{version: "v9.9.9", commit: "linkercommit", date: "linkerdate"}

	vcsInfo := &debug.BuildInfo{
		Main: debug.Module{Version: develVersion},
		Settings: []debug.BuildSetting{
			{Key: vcsRevisionKey, Value: "abc123"},
			{Key: vcsTimeKey, Value: "2026-08-09T00:00:00Z"},
			{Key: vcsModifiedKey, Value: "false"},
		},
	}

	tests := []struct {
		name    string
		start   buildMetadata
		info    *debug.BuildInfo
		ok      bool
		want    buildMetadata
		comment string
	}{
		{
			name:    "no build info leaves defaults",
			start:   defaults,
			ok:      false,
			want:    defaults,
			comment: "nothing to fall back to",
		},
		{
			name:    "nil build info leaves defaults",
			start:   defaults,
			info:    nil,
			ok:      true,
			want:    defaults,
			comment: "ok is true but the pointer is nil",
		},
		{
			name:  "module version fills in for go install",
			start: defaults,
			info: &debug.BuildInfo{
				Main: debug.Module{Version: "v0.1.0"},
			},
			ok:      true,
			want:    buildMetadata{version: "v0.1.0", commit: defaultCommit, date: defaultDate},
			comment: "this is the go install pkg@version path",
		},
		{
			name:    "devel module version is not used",
			start:   defaults,
			info:    &debug.BuildInfo{Main: debug.Module{Version: develVersion}},
			ok:      true,
			want:    defaults,
			comment: "(devel) says less than the sentinel",
		},
		{
			name:    "vcs stamp fills commit and date",
			start:   defaults,
			info:    vcsInfo,
			ok:      true,
			want:    buildMetadata{version: defaultVersion, commit: "abc123", date: "2026-08-09T00:00:00Z"},
			comment: "this is the go build from a source tree path",
		},
		{
			name:  "dirty tree is marked",
			start: defaults,
			info: &debug.BuildInfo{
				Settings: []debug.BuildSetting{
					{Key: vcsRevisionKey, Value: "abc123"},
					{Key: vcsModifiedKey, Value: "true"},
				},
			},
			ok:      true,
			want:    buildMetadata{version: defaultVersion, commit: "abc123-dirty", date: defaultDate},
			comment: "uncommitted changes must be visible",
		},
		{
			name:    "linker values win over build info",
			start:   linked,
			info:    vcsInfo,
			ok:      true,
			want:    linked,
			comment: "GoReleaser is authoritative when it sets -X",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if actual := tt.start.resolve(tt.info, tt.ok); actual != tt.want {
				t.Errorf("expected %+v, got %+v (%s)", tt.want, actual, tt.comment)
			}
		})
	}
}

func TestBuildMetadataString(t *testing.T) {
	t.Parallel()

	actual := buildMetadata{version: "v1.2.3", commit: "deadbeef", date: "2026-01-01"}.String()
	for _, want := range []string{"kmscsr", "v1.2.3", "deadbeef", "2026-01-01", runtime.Version()} {
		if !strings.Contains(actual, want) {
			t.Errorf("expected %q in version string, got: %s", want, actual)
		}
	}
}

// TestGoReleaserLdflagsMatchDeclaredVariables guards the failure that shipped
// three releases with no build metadata: the linker silently discards -X for a
// symbol it cannot find, so renaming a variable here would go unnoticed until
// someone inspected a released binary.
func TestGoReleaserLdflagsMatchDeclaredVariables(t *testing.T) {
	t.Parallel()

	config, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatalf("failed to read goreleaser config: %v", err)
	}

	// Referencing the variables keeps this in step with the declarations.
	declared := map[string]string{
		"version": version,
		"commit":  commit,
		"date":    date,
	}

	matches := regexp.MustCompile(`-X main\.(\w+)=`).FindAllStringSubmatch(string(config), -1)
	if len(matches) == 0 {
		t.Fatal("no -X main.* ldflags found in .goreleaser.yaml")
	}
	for _, match := range matches {
		if _, ok := declared[match[1]]; !ok {
			t.Errorf("-X main.%s has no matching package variable; the linker will discard it", match[1])
		}
	}
	if len(matches) != len(declared) {
		t.Errorf("expected %d injected variables, .goreleaser.yaml has %d", len(declared), len(matches))
	}
}

func TestRootCommandVersionFlag(t *testing.T) {
	t.Parallel()

	// --version needs none of the required flags and must not reach AWS.
	stdout, stderr, err := executeWith(t, unusedFactory(t), "--version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expected := versionString() + "\n"; stdout != expected {
		t.Errorf("expected exactly %q, got: %q", expected, stdout)
	}
	if stderr != "" {
		t.Errorf("expected nothing on stderr, got: %q", stderr)
	}
}

func TestRootCommandRequiresKMSArn(t *testing.T) {
	t.Parallel()

	command, err := newRootCommand()
	if err != nil {
		t.Fatalf("failed to create command: %v", err)
	}
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--common-name", "example.com"})

	err = command.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "required flag(s) \"kms-arn\"") {
		t.Fatalf("expected missing KMS ARN error, got: %v", err)
	}
}

func TestRootCommandRejectsInvalidIPBeforeAWS(t *testing.T) {
	t.Parallel()

	// unusedFactory fails the test if the builder, and so AWS, is reached.
	_, _, err := executeWith(t, unusedFactory(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--san-ip", "192.0.2.1",
		"--san-ip", "invalid",
	)
	if err == nil || err.Error() != "invalid IP address: invalid" {
		t.Fatalf("expected invalid IP address error, got: %v", err)
	}
}

// TestRootCommandRejectsPositionalArgs guards against a repeated value being
// silently dropped: cobra otherwise treats the second name below as an ignored
// positional argument and signs a request without it.
func TestRootCommandRejectsPositionalArgs(t *testing.T) {
	t.Parallel()

	_, _, err := executeWith(t, unusedFactory(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--san-dns", "a.example.com", "b.example.com",
	)
	if err == nil || !strings.Contains(err.Error(), "b.example.com") {
		t.Fatalf("expected an error naming the stray argument, got: %v", err)
	}
}

func TestRootCommandRejectsNegativeTimeout(t *testing.T) {
	t.Parallel()

	_, _, err := executeWith(t, unusedFactory(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--timeout", "-1s",
	)
	if err == nil || !strings.Contains(err.Error(), "--timeout cannot be negative") {
		t.Fatalf("expected negative timeout error, got: %v", err)
	}
}

func TestRootCommandHasBoundedDefaultTimeout(t *testing.T) {
	t.Parallel()

	command, err := newRootCommand()
	if err != nil {
		t.Fatalf("failed to create command: %v", err)
	}
	flag := command.Flags().Lookup("timeout")
	if flag == nil {
		t.Fatal("timeout flag not found")

		return
	}
	parsed, err := time.ParseDuration(flag.DefValue)
	if err != nil {
		t.Fatalf("invalid timeout default: %v", err)
	}
	if parsed != defaultTimeout || parsed <= 0 {
		t.Fatalf("expected bounded default timeout %s, got: %s", defaultTimeout, parsed)
	}
}
