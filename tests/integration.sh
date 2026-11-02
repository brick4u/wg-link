#!/usr/bin/env bash
# Docker integration test, not a production launcher.
# Usage: WG_LINK_IMAGE=wg-link:test bash tests/integration.sh
# Requires: built local image, Docker daemon, Bash, python3, Linux WireGuard,
# NET_ADMIN permission, and image-provided wg/ip/ping/wget. Never builds/pulls.
set -Eeuo pipefail
umask 077
image=${WG_LINK_IMAGE:-wg-link:test}
for command in docker python3 mktemp; do
    command -v "$command" >/dev/null || { echo "Missing requirement: $command" >&2; exit 1; }
done
docker image inspect "$image" >/dev/null 2>&1 || {
    echo "Build image first (default wg-link:test); override with WG_LINK_IMAGE." >&2
    exit 1
}
# Always outside the checkout, regardless of TMPDIR.
tmp=$(mktemp -d /tmp/wg-link-integration.XXXXXXXX)
token=${tmp##*/}
network=$token-net
a=$token-a
b=$token-b
label=wg-link.integration
cleanup() {
    local status=$? name actual cleanup_failed=0
    trap - EXIT ERR INT TERM
    set +e
    if (( status != 0 )); then
        # Do not print raw logs: redact all WireGuard-shaped keys first.
        for name in "$a" "$b"; do
            actual=$(docker inspect -f '{{ index .Config.Labels "wg-link.integration" }}' "$name" 2>/dev/null)
            if [[ $actual == "$token" ]]; then
                docker logs "$name" 2>&1 | python3 -c 'import re,sys; print(re.sub(r"[A-Za-z0-9+/]{43}=", "[REDACTED-KEY]", sys.stdin.read()), end="")' >"$tmp/$name.log"
                if (( PIPESTATUS[0] != 0 )); then echo "Could not collect logs for $name" >&2; fi
            fi
        done
        echo "Test failed; sanitized logs retained in $tmp (private keys removed)." >&2
    fi
    for name in "$a" "$b" "$token-key"; do
        actual=$(docker inspect -f '{{ index .Config.Labels "wg-link.integration" }}' "$name" 2>/dev/null)
        if [[ $actual == "$token" ]]; then
            docker rm -f "$name" >/dev/null || cleanup_failed=1
        elif [[ -n $actual ]]; then
            echo "Refusing cleanup of foreign container $name" >&2
            cleanup_failed=1
        fi
    done
    actual=$(docker network inspect -f '{{ index .Labels "wg-link.integration" }}' "$network" 2>/dev/null)
    if [[ $actual == "$token" ]]; then
        docker network rm "$network" >/dev/null || cleanup_failed=1
    elif [[ -n $actual ]]; then
        echo "Refusing cleanup of foreign network $network" >&2
        cleanup_failed=1
    fi
    # Verify exact absolute paths before deleting our generated secrets.
    if [[ $tmp == /tmp/wg-link-integration.* && -d $tmp ]]; then
        python3 - "$tmp" "$status" <<'PY'
import pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
assert root.parent == pathlib.Path('/tmp') and root.name.startswith('wg-link-integration.')
for child in ('a', 'b', 'keys'):
    path = root / child
    if path.exists():
        shutil.rmtree(path)
if sys.argv[2] == '0':
    shutil.rmtree(root)
PY
        if (( $? != 0 )); then cleanup_failed=1; fi
    else
        cleanup_failed=1
    fi
    (( status != 0 )) || status=$cleanup_failed
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$tmp/a" "$tmp/b" "$tmp/keys"
# Container root deliberately lacks DAC_OVERRIDE. The mounted subdirectories
# must be traversable; the enclosing host temp directory remains mode 0700.
chmod 0755 "$tmp/a" "$tmp/b"
docker network create --driver bridge --internal --label "$label=$token" "$network" >/dev/null
subnet=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$network")
read -r ip_a ip_b < <(python3 - "$subnet" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1])
assert net.version == 4 and net.num_addresses > 4
assert not net.overlaps(ipaddress.ip_network('198.18.0.0/15'))
print(net.network_address + 2, net.network_address + 3)
PY
)
# No key ever appears in command arguments or console output.
for key in a b rotated; do
    docker run --rm --name "$token-key" --label "$label=$token" --network none --entrypoint wg "$image" genkey >"$tmp/keys/$key"
    docker run --rm -i --name "$token-key" --label "$label=$token" --network none --entrypoint wg "$image" pubkey <"$tmp/keys/$key" >"$tmp/keys/$key.pub"
done
cp "$tmp/keys/a" "$tmp/a/private"
cp "$tmp/keys/b" "$tmp/b/private"
chmod 0644 "$tmp/a/private" "$tmp/b/private"
config() {
    python3 - "$tmp" "$1" "$2" "$ip_a" "$ip_b" "${3:-yes}" <<'PY'
import json, os, pathlib, sys
root, side, peerkey, ipa, ipb, routes = sys.argv[1:]
root = pathlib.Path(root)
other = 'b' if side == 'a' else 'a'
inner = {'a': '198.18.0.1', 'b': '198.18.0.2'}
iface = dict(name='wgtest', addresses=[inner[side]+'/32'], listenPort=51820,
             privateKeyFile='private', routes=[inner[other]+'/32'] if routes == 'yes' else [],
             peers=[dict(publicKey=(root/'keys'/peerkey).read_text().strip(),
                         allowedIPs=[inner[other]+'/32'],
                         endpoint=(ipb if side == 'a' else ipa)+':51820', persistentKeepalive=1)])
path = root/side/'config.yaml'
staged = path.with_suffix('.new')
staged.write_text(json.dumps(dict(interfaces=[iface])))
staged.chmod(0o644)
os.replace(staged, path)
PY
}
config a b.pub
config b a.pub
for side in a b; do
    if [[ $side == a ]]; then name=$a; ip=$ip_a; else name=$b; ip=$ip_b; fi
    docker run -d --name "$name" --label "$label=$token" \
        --network "$network" --ip "$ip" --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
        --read-only --security-opt no-new-privileges \
        --mount "type=bind,src=$tmp/$side,dst=/etc/wg-link,readonly" \
        "$image" -config /etc/wg-link/config.yaml >/dev/null
done
# Bounded readiness/convergence retry; no unbounded sleep or busy polling.
await() {
    local attempt
    for ((attempt=0; attempt<30; attempt++)); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "Timed out waiting for: $1" >&2
    return 1
}
ready() { docker exec "$1" wget -q -O /dev/null http://127.0.0.1:9090/readyz; }
ping_peer() { docker exec "$1" ping -c 1 -W 1 "$2"; }
await ready "$a"
await ready "$b"
await ping_peer "$a" 198.18.0.2
await ping_peer "$b" 198.18.0.1
echo 'PASS: bidirectional tunnel connectivity'
# Rotate A's key file in the mounted directory and B's peer configuration.
cp "$tmp/keys/rotated" "$tmp/a/private.new"
chmod 0644 "$tmp/a/private.new"
mv "$tmp/a/private.new" "$tmp/a/private"
config b rotated.pub
rotated() {
    local actual expected peers
    actual=$(docker exec "$a" wg show wgtest public-key) || return 1
    expected=$(<"$tmp/keys/rotated.pub")
    [[ $actual == "$expected" ]] || return 1
    peers=$(docker exec "$b" wg show wgtest peers) || return 1
    [[ $peers == "$expected" ]]
}
await rotated
await ping_peer "$a" 198.18.0.2
await ping_peer "$b" 198.18.0.1
echo 'PASS: live private-key and peer reload'
config a b.pub no
blackhole() {
    local routes
    routes=$(docker exec "$a" ip -4 route show exact 198.18.0.2/32) || return 1
    [[ $routes == *'blackhole 198.18.0.2'* && $routes == *'metric 42761'* && $routes != *'dev wgtest'* ]]
}
await blackhole
await ready "$a"
# Guard must reject a route lookup rather than select the bridge/default route.
if docker exec "$a" ip -4 route get 198.18.0.2 >"$tmp/route-get.log" 2>&1; then
    echo 'Removed route leaked to a forwarding path' >&2
    exit 1
fi
# Confirm the underlay remains reachable, while the protected inner IP does not.
ping_peer "$a" "$ip_b" >/dev/null
if ping_peer "$a" 198.18.0.2 >"$tmp/negative-ping.log" 2>&1; then
    echo 'Protected destination remained reachable after route removal' >&2
    exit 1
fi
blackhole
echo 'PASS: route removal retains blackhole; no underlay fallback'
