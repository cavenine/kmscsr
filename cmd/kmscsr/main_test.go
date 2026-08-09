package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseIPAddresses(t *testing.T) {
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
	_, err := parseIPAddresses([]string{"not-an-ip"})
	if err == nil || !strings.Contains(err.Error(), "invalid IP address") {
		t.Fatalf("expected invalid IP address error, got: %v", err)
	}
}

func TestRootCommandRequiresKMSArn(t *testing.T) {
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
	command, err := newRootCommand()
	if err != nil {
		t.Fatalf("failed to create command: %v", err)
	}
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{
		"--kms-arn", "arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		"--common-name", "example.com",
		"--san-ip", "invalid",
	})

	err = command.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid IP address") {
		t.Fatalf("expected invalid IP address error, got: %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected AWS request: %v", err)
	}
}

func TestRootCommandHasBoundedDefaultTimeout(t *testing.T) {
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
