package wglink

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPerInterfaceEndpointCommitPreservesRoamingAfterPartialFailure(t *testing.T) {
	key, _ := wgtypes.GeneratePrivateKey()
	public := key.PublicKey()
	declared, _ := parseEndpoint("10.0.0.2:51820")
	roamed, _ := parseEndpoint("10.0.0.3:51820")
	desired := []DesiredPeer{{Config: wgtypes.PeerConfig{PublicKey: public, Endpoint: declared}, Endpoint: declared}}
	// Interface A succeeds; interface B later fails, so Agent retries A's same endpoint declaration.
	configs, applied := preparePeers(desired, nil, nil)
	if configs[0].Endpoint == nil {
		t.Fatal("initial declaration not applied")
	}
	configs, _ = preparePeers(desired, []wgtypes.Peer{{PublicKey: public, Endpoint: roamed}}, applied)
	if configs[0].Endpoint != nil {
		t.Fatal("later-interface failure overwrote authenticated roaming")
	}
	// An externally removed interface/peer must still restore the declared endpoint.
	configs, _ = preparePeers(desired, nil, applied)
	if configs[0].Endpoint == nil || configs[0].Endpoint.String() != declared.String() {
		t.Fatal("recreated peer endpoint not restored")
	}
	// An actual new declaration must replace the endpoint, even if the peer has roamed.
	changed, _ := parseEndpoint("10.0.0.4:51820")
	desired[0].Endpoint = changed
	desired[0].Config.Endpoint = changed
	configs, next := preparePeers(desired, []wgtypes.Peer{{PublicKey: public, Endpoint: roamed}}, applied)
	if configs[0].Endpoint == nil || configs[0].Endpoint.String() != changed.String() {
		t.Fatal("new declaration not applied")
	}
	if applied[public] == next[public] {
		t.Fatal("helper mutated committed state before kernel success")
	}
	// Failed ConfigureDevice must leave the previous declaration, so retry still updates.
	configs, _ = preparePeers(desired, []wgtypes.Peer{{PublicKey: public, Endpoint: roamed}}, applied)
	if configs[0].Endpoint == nil {
		t.Fatal("failed kernel change suppressed retry")
	}
}
