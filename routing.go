package wglink

import (
	"fmt"
	"net/netip"
)

// Connected and local routes have kernel priority over agent-managed routes.
func validateRouting(c *Config) error {
	for _, out := range c.Interfaces {
		for _, route := range out.Routes {
			dst, err := netip.ParsePrefix(route)
			if err != nil {
				return fmt.Errorf("invalid route")
			}
			for _, other := range c.Interfaces {
				if other.Name == out.Name {
					continue
				}
				for _, address := range other.Addresses {
					addr, err := netip.ParsePrefix(address)
					if err != nil {
						return fmt.Errorf("invalid address")
					}
					if dst.Contains(addr.Addr()) || (addr.Bits() >= dst.Bits() && dst.Contains(addr.Masked().Addr())) {
						return fmt.Errorf("interface %s address shadows route on %s", other.Name, out.Name)
					}
				}
			}
		}
	}
	return nil
}
