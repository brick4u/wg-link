package wglink

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func fixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	k, e := wgtypes.GeneratePrivateKey()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "key"), []byte(k.String()), 0600); e != nil {
		t.Fatal(e)
	}
	return filepath.Join(dir, "config.yaml"), fmt.Sprintf("interfaces:\n- name: wg-test\n  addresses: [10.0.0.1/32]\n  privateKeyFile: key\n  routes: [10.1.0.0/16]\n  peers:\n  - publicKey: %s\n    allowedIPs: [10.1.0.0/16]\n    persistentKeepalive: 25\n", k.PublicKey().String())
}
func TestConfig(t *testing.T) {
	path, valid := fixture(t)
	for _, tc := range []struct {
		name, config string
		ok           bool
	}{
		{"valid", valid, true}, {"unknown", valid + "  unknown: true\n", false}, {"duplicate YAML", valid + "  mtu: 1280\n  mtu: 1300\n", false}, {"multiple documents", valid + "---\ninterfaces: []\n", false}, {"hostname", valid + "    endpoint: vpn.example:51820\n", false}, {"IPv6", valid + "    endpoint: '[2001:db8::1]:51820'\n", true}, {"bad port", valid + "    endpoint: '1.2.3.4:0'\n", false}, {"bad MTU", valid + "  mtu: 100\n", false}, {"bad route", strings.Replace(valid, "routes: [10.1.0.0/16]", "routes: [10.1.0.1/16]", 1), false}, {"bad key", strings.Replace(valid, "privateKeyFile: key", "privateKeyFile: missing", 1), false}, {"both endpoint types", valid + "    endpoint: '1.2.3.4:51820'\n    service: {namespace: ns, name: peer, port: wg}\n", false}, {"service", valid + "    service: {namespace: ns, name: peer, port: wg}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := os.WriteFile(path, []byte(tc.config), 0600); e != nil {
				t.Fatal(e)
			}
			c, e := Load(path)
			if (e == nil) != tc.ok {
				t.Fatalf("Load error=%v expected success=%v", e, tc.ok)
			}
			if e == nil && c.Interfaces[0].MTU != 1280 {
				t.Fatal("default MTU")
			}
		})
	}
}
func TestProjectedSecretReload(t *testing.T) {
	path, data := fixture(t)
	dir := filepath.Dir(path)
	for _, version := range []string{"v1", "v2"} {
		if e := os.Mkdir(filepath.Join(dir, version), 0700); e != nil {
			t.Fatal(e)
		}
		key, _ := wgtypes.GeneratePrivateKey()
		if e := os.WriteFile(filepath.Join(dir, version, "secret"), []byte(key.String()), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink("v1", filepath.Join(dir, "current")); e != nil {
		t.Fatal(e)
	}
	data = strings.Replace(data, "privateKeyFile: key", "privateKeyFile: current/secret", 1)
	if e := os.WriteFile(path, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	one, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("v2", filepath.Join(dir, "next")); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(dir, "next"), filepath.Join(dir, "current")); e != nil {
		t.Fatal(e)
	}
	two, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if one.Interfaces[0].key == two.Interfaces[0].key {
		t.Fatal("projected key rotation not observed")
	}
}
