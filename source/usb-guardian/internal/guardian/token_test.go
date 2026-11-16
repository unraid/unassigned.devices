package guardian

import (
	"strings"
	"testing"
)

func TestOpaqueTokenRoundTripAndTamper(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TokenSecret = "unit-test-secret"
	d := Device{KernelName: "sdb", MajorMinor: "8:16", DiskSeq: "44", USBPath: "devices/pci/usb1/1-2", USBSerial: "ABC"}
	token, err := encodeToken(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(token, "sdb") || strings.Contains(token, "8:16") {
		t.Fatalf("token leaks plain identity: %s", token)
	}
	payload, err := decodeToken(cfg, token)
	if err != nil {
		t.Fatal(err)
	}
	if payload.KernelName != d.KernelName || payload.DiskSeq != d.DiskSeq || payload.USBPath != d.USBPath {
		t.Fatalf("wrong payload: %+v", payload)
	}
	last := token[len(token)-1]
	replacement := byte('A')
	if last == replacement {
		replacement = 'B'
	}
	if _, err := decodeToken(cfg, token[:len(token)-1]+string(replacement)); err == nil {
		t.Fatal("tampered token was accepted")
	}
}

func TestTokenSecretMismatch(t *testing.T) {
	a, b := DefaultConfig(), DefaultConfig()
	a.TokenSecret = "a"
	b.TokenSecret = "b"
	token, _ := encodeToken(a, Device{KernelName: "sdc", MajorMinor: "8:32", DiskSeq: "1", USBPath: "devices/usb/1-1"})
	if _, err := decodeToken(b, token); err == nil {
		t.Fatal("token signed by another installation was accepted")
	}
}
