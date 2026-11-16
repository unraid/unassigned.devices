package guardian

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readKV(path string) map[string]string {
	out := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

func cleanKernelName(input string) (string, error) {
	name := filepath.Base(filepath.Clean(input))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "", errors.New("empty device name")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return "", fmt.Errorf("invalid device name %q", name)
		}
	}
	return name, nil
}

func unescapeMount(s string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(s)
}

func pathWithin(path, base string) bool {
	path = filepath.ToSlash(strings.TrimSuffix(path, " (deleted)"))
	base = filepath.ToSlash(base)
	path = strings.TrimSuffix(path, "/")
	base = strings.TrimSuffix(base, "/")
	if path == base {
		return true
	}
	return strings.HasPrefix(path, base+"/")
}

func stableSecret(cfg Config) []byte {
	if cfg.TokenSecret != "" {
		return []byte(cfg.TokenSecret)
	}
	for _, p := range []string{filepath.Join(cfg.ProcRoot, "sys/kernel/random/boot_id"), "/boot/config/ident.cfg", "/etc/machine-id"} {
		if v := readTrim(p); v != "" {
			h := sha256.Sum256([]byte("usb-guardian-v1\x00" + v))
			return h[:]
		}
	}
	return []byte("usb-guardian-no-machine-id-fail-closed")
}

func currentBootID(cfg Config) string {
	if id := readTrim(filepath.Join(cfg.ProcRoot, "sys/kernel/random/boot_id")); id != "" {
		return id
	}
	if stat := readTrim(filepath.Join(cfg.ProcRoot, "stat")); stat != "" {
		for _, line := range strings.Split(stat, "\n") {
			if strings.HasPrefix(line, "btime ") {
				return "btime:" + strings.TrimSpace(strings.TrimPrefix(line, "btime "))
			}
		}
	}
	return "unknown"
}

func trustedBootID(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value != "unknown"
}

type tokenPayload struct {
	Version    int    `json:"v"`
	KernelName string `json:"n"`
	MajorMinor string `json:"d"`
	DiskSeq    string `json:"q"`
	USBPath    string `json:"u"`
	USBSerial  string `json:"s,omitempty"`
	USBBusNum  string `json:"b,omitempty"`
	USBDevNum  string `json:"e,omitempty"`
}

func encodeToken(cfg Config, d Device) (string, error) {
	p := tokenPayload{Version: 1, KernelName: d.KernelName, MajorMinor: d.MajorMinor, DiskSeq: d.DiskSeq, USBPath: d.USBPath, USBSerial: d.USBSerial, USBBusNum: d.USBBusNum, USBDevNum: d.USBDevNum}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, stableSecret(cfg))
	_, _ = mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func decodeToken(cfg Config, token string) (tokenPayload, error) {
	left, right, ok := strings.Cut(token, ".")
	if !ok {
		return tokenPayload{}, errors.New("malformed target token")
	}
	b, err := base64.RawURLEncoding.DecodeString(left)
	if err != nil {
		return tokenPayload{}, errors.New("malformed target token payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(right)
	if err != nil {
		return tokenPayload{}, errors.New("malformed target token signature")
	}
	mac := hmac.New(sha256.New, stableSecret(cfg))
	_, _ = mac.Write(b)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return tokenPayload{}, errors.New("target token signature mismatch")
	}
	var p tokenPayload
	if err := json.Unmarshal(b, &p); err != nil || p.Version != 1 {
		return tokenPayload{}, errors.New("unsupported target token")
	}
	return p, nil
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func copyTail(path string, max int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if max > 0 && st.Size() > max {
		if _, err := f.Seek(-max, io.SeekEnd); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	return string(b), err
}
