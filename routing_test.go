package wglink

import "testing"

func TestRoutingCrossInterfaceShadow(t *testing.T) {
	for _, address := range []string{"10.0.0.1/24", "10.0.0.1/32", "10.0.0.129/25"} {
		c := &Config{Interfaces: []Interface{{Name: "wg-a", Addresses: []string{address}}, {Name: "wg-b", Routes: []string{"10.0.0.0/24"}}}}
		if validateRouting(c) == nil {
			t.Errorf("accepted shadowing address %s", address)
		}
	}
	c := &Config{Interfaces: []Interface{{Name: "wg-a", Addresses: []string{"10.0.0.1/32"}}, {Name: "wg-b", Routes: []string{"10.0.0.2/32"}}}}
	if err := validateRouting(c); err != nil {
		t.Fatal(err)
	}
}
