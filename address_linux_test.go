package wglink

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestAddressIdentityIgnoresKernelLabel(t *testing.T) {
	for _, cidr := range []string{"10.0.0.1/24", "10.0.0.1/32", "2001:db8::1/64", "2001:db8::1/128"} {
		t.Run(cidr, func(t *testing.T) {
			desired, err := netlink.ParseAddr(cidr)
			if err != nil {
				t.Fatal(err)
			}
			current := *desired
			current.Label = "wg-source"
			current.Flags = 128
			current.Scope = 253
			current.ValidLft = 1234
			want, ok := identityOfAddress(*desired)
			if !ok {
				t.Fatal("invalid desired")
			}
			got, ok := identityOfAddress(current)
			if !ok || got != want {
				t.Fatalf("kernel label changed identity: %v != %v", got, want)
			}
			wanted := map[addressIdentity]bool{want: true}
			if !wanted[got] {
				t.Fatal("existing configured address would be removed")
			}
		})
	}
}
func TestAddressIdentityNormalization(t *testing.T) {
	a := netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(24, 32)}}
	b := netlink.Addr{IPNet: &net.IPNet{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(24, 32)}}
	x, ok := identityOfAddress(a)
	if !ok {
		t.Fatal("invalid IPv4")
	}
	y, ok := identityOfAddress(b)
	if !ok || x != y {
		t.Fatal("IPv4 byte encoding mismatch")
	}
	b.IPNet = &net.IPNet{IP: net.ParseIP("::ffff:10.0.0.1"), Mask: net.CIDRMask(120, 128)}
	y, ok = identityOfAddress(b)
	if !ok || x != y {
		t.Fatal("mapped IPv4 prefix mismatch")
	}
	for _, cidr := range []string{"10.0.0.2/24", "10.0.0.1/25", "2001:db8::1/24"} {
		n, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		id, valid := identityOfAddress(*n)
		if !valid || id == x {
			t.Errorf("lost local address/prefix/family identity: %s", cidr)
		}
	}
	peer := a
	peer.Peer = &net.IPNet{IP: net.IPv4(10, 0, 0, 2), Mask: net.CIDRMask(32, 32)}
	id, ok := identityOfAddress(peer)
	if !ok || id == x {
		t.Fatal("lost peer identity")
	}
	if _, ok := identityOfAddress(netlink.Addr{}); ok {
		t.Fatal("accepted nil address")
	}
}
