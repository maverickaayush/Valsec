# Two-router discovery demo runbook

This procedure rebuilds the temporary laptop network after a laptop restart.
It does not upgrade, reset, or permanently reconfigure either router.

## Physical connections

1. Connect the USB Ethernet adapter `enxc817f57c5783` to the OpenWrt seed router (Router 1).
2. Connect the laptop's built-in Ethernet port `eno1` to the Cirotech neighbor (Router 2).
3. Power both routers and wait for them to finish booting.

Expected addresses:

| Device | Address | Link |
| --- | --- | --- |
| OpenWrt seed | `192.168.1.2/24` | `enxc817f57c5783` |
| Cirotech neighbor | `192.168.1.1/24` | `eno1` |
| Ubuntu laptop bridge | `192.168.1.250/24` | `br-valsec` |

The bridge is a temporary Layer 2 connection between the two Ethernet ports.
No gateway or routed subnet scan is needed.

## Recreate the temporary Ubuntu bridge

Open a terminal on Ubuntu. These commands disable NetworkManager control of
only the two demo Ethernet ports for this boot, clear their direct addresses,
and create a bridge. They do not create persistent NetworkManager profiles.

```bash
nmcli device status
sudo nmcli device set enxc817f57c5783 managed no
sudo nmcli device set eno1 managed no
sudo ip link set enxc817f57c5783 down
sudo ip link set eno1 down
sudo ip address flush dev enxc817f57c5783
sudo ip address flush dev eno1
sudo ip link add br-valsec type bridge
sudo ip link set dev br-valsec type bridge stp_state 0
sudo ip link set enxc817f57c5783 master br-valsec
sudo ip link set eno1 master br-valsec
sudo ip address add 192.168.1.250/24 dev br-valsec
sudo ip link set br-valsec up
sudo ip link set enxc817f57c5783 up
sudo ip link set eno1 up
ip -br address
ip route get 192.168.1.1
```

The route lookup should show `dev br-valsec src 192.168.1.250`. If `br-valsec`
already exists after a partial setup, remove only that temporary bridge and
repeat the bridge commands:

```bash
sudo ip link set enxc817f57c5783 nomaster
sudo ip link set eno1 nomaster
sudo ip link set br-valsec down
sudo ip link delete br-valsec type bridge
```

If either router is unreachable, check that the cables are in the ports listed
above and that the bridge shows both ports as members:

```bash
bridge link
ping -c 2 -I br-valsec 192.168.1.2
ping -c 2 -I br-valsec 192.168.1.1
ip neigh show dev br-valsec
```

## Verify each router login

Verify the seed over SSH. Type its password at the prompt; do not put it in the
command line:

```bash
ssh root@192.168.1.2
```

At the OpenWrt shell, refresh the neighbor entry and check the Cirotech MAC:

```sh
ping -c 2 192.168.1.1
ip neigh show 192.168.1.1
cat /proc/net/arp
exit
```

The expected entry is `192.168.1.1` with MAC `c4:70:0b:bc:19:30` on `br-lan`.
The neighbor may be `STALE` instead of `REACHABLE`; both are valid candidate
states for discovery.

Verify Cirotech Telnet manually only if needed. Close this session before
starting Valsec because this appliance may allow only one Telnet session:

```bash
telnet 192.168.1.1 23
```

At `login:`, enter the Cirotech username and password interactively. The prompt
should become `#`. Read-only identity/export verification commands are:

```sh
cat /proc/version
cat /etc/version
mib --help
exit
```

The observed platform is Realtek Luna SDK 3.3.0, firmware `V2.1.01-200817`.
`mib --help` documents `mib all` as a configd MIB dump and distinguishes it
from `mib commit`, which writes configuration to flash. Valsec uses only
`mib all`. Do not run `mib commit` for this demo.

## Optional temporary OpenWrt LLDP tooling

LLDP is optional for this hardware pair: Cirotech has no LLDP/CDP agent, so the
demo discovers it from the OpenWrt kernel neighbor/ARP tables. If the OpenWrt
router rebooted and you still want to restore the LLDP test tooling, install it
to OpenWrt's RAM destination (`ram` maps to `/tmp` in the [OpenWrt opkg
documentation](https://openwrt.org/docs/guide-user/additional-software/opkg)).
The package files and opkg lists are temporary
and disappear at reboot; do not use `sysupgrade` or a normal root-filesystem
install.

```bash
ssh root@192.168.1.2
```

At the OpenWrt shell:

```sh
opkg update
opkg -d ram install lldpd
ls -l /tmp/usr/sbin/lldpd /tmp/usr/sbin/lldpcli
/tmp/usr/sbin/lldpd -d -f -I br-lan >/tmp/lldpd.log 2>&1 &
sleep 2
/tmp/usr/sbin/lldpcli show neighbors -f json
ip neigh show dev br-lan
```

An empty LLDP neighbor result for Cirotech is expected. `ip neigh show` should
still show `192.168.1.1`. If the old OpenWrt 18.06 package feed is unavailable
or the temporary daemon cannot start, skip LLDP and continue; the Valsec
discovery path uses the kernel neighbor table and `/proc/net/arp`. No daemon is
required for the live two-router demo.

## Start the Valsec demo services

From the repository on Ubuntu:

```bash
cd ~/valsec
docker compose -p valsec_final up -d --build
docker compose -p valsec_final ps
curl -fsS http://127.0.0.1:8000/openapi.json | grep -E 'discovery-sessions|pull-discovered-device'
curl -fsS http://127.0.0.1:11434/api/tags | grep qwen2.5
curl -fsS http://127.0.0.1:3000/configs/upload >/dev/null && echo 'Valsec UI is ready'
```

The expected services are PostgreSQL, Redis, backend, worker, and frontend.
Compose applies migrations during backend startup. Do not use `docker compose
down -v`; that deletes the demo database volume. Local Ollama should have
`qwen2.5:7b` loaded for proposal suggestions. If Ollama is unavailable or a
response fails validation, affected lines remain in the manual training queue
instead of being discarded or automatically confirmed.

## Run the seed-to-neighbor audit

1. Open `http://localhost:3000/configs/upload`.
2. In **Discover & Audit Neighbors**, enter seed address `192.168.1.2`, vendor **OpenWrt**, its SSH username/password, depth `2`, and device limit `25`. Leave **Reuse seed credentials** enabled for advertised devices.
3. Click **Discover neighbors**. Valsec creates a persistent session and lists the seed evidence. Confirm `192.168.1.1`, MAC `c4:70:0b:bc:19:30`, on `br-lan`. It appears as **Profile required / needs input** because ARP cannot prove product identity or credentials.
4. On the `192.168.1.1` card, enter the Cirotech Telnet username/password, leave transport as **Telnet · isolated LAN**, choose **Cirotech Linux shell**, keep **NIST SP 800-53 Rev. 5**, and use device name `cirotech-neighbor`.
5. Click **Continue pull & audit**. The IP is already part of the persisted discovery record; do not re-enter it. Valsec validates/pins it, opens Telnet, and runs only the fixed read-only `mib all` export.
6. If `192.168.1.250` or another laptop address appears from the passive neighbor table, click **Not a router** for that row. Passive evidence is deliberately not treated as device identity.
7. The Cirotech row changes to **audit queued** and gains **Open audit**. The configuration creates one ordinary Cirotech `Config`, dispatches the existing Celery task, and appears under **Fleet Audits**.
8. The first audit is expected to reach **Awaiting Training** because the proprietary Cirotech MIB has no hand-written parser. Valid local Ollama proposals appear as `probable`; unmatched lines remain `unverified`. Both require deliberate operator approval before deterministic compliance can use them.

To verify through the API without placing passwords in shell history, use the
UI flow above. On the status page, confirm the vendor is Cirotech and the
status changes from `queued`/`normalising` to `awaiting_training` (or `complete`
if the required mappings already exist). The fleet list and device report show
the persisted audit result. The discovery session also preserves each
candidate's state, linked Config ID, and live audit status across a page
refresh.

## Emergency recovery

- **Cannot reach either router:** check physical port/cable mapping, run `bridge link`, then repeat the two bridge-scoped pings. Confirm the route uses `br-valsec` and host address `.250`.
- **Seed has no neighbor entry:** SSH to OpenWrt and run `ping -c 2 192.168.1.1`, then `ip neigh show 192.168.1.1`; retry Valsec discovery.
- **SSH seed login fails:** confirm the seed is `.2`, the bridge route is correct, and use the interactive OpenWrt root login. Do not factory reset it.
- **Telnet says connection closed or times out:** close any other Cirotech Telnet terminal; the device may permit one session. Confirm `.1` is reachable and that the login prompt appears. Do not retry with SSH or UCI; neither is the Cirotech pull profile.
- **Pull succeeds but audit waits for training:** this is expected on an untrained Cirotech configuration. Review proposals and approve mappings deliberately; the compliance engine stays gated until then.
- **Docker/API unavailable:** run `docker compose -p valsec_final ps` and `docker compose -p valsec_final logs --tail=100 backend worker frontend`. Restart without deleting volumes using `docker compose -p valsec_final up -d`.
- **Return Ubuntu interfaces to NetworkManager:**

  ```bash
  sudo ip link set enxc817f57c5783 nomaster
  sudo ip link set eno1 nomaster
  sudo ip link set br-valsec down
  sudo ip link delete br-valsec type bridge
  sudo nmcli device set enxc817f57c5783 managed yes
  sudo nmcli device set eno1 managed yes
  sudo nmcli device connect enxc817f57c5783
  sudo nmcli device connect eno1
  ```

## Persistent versus temporary changes

- The bridge, `192.168.1.250/24` host address, and NetworkManager unmanaged state are runtime laptop settings. They do not survive reboot; use the bridge section again. Removing `br-valsec` and restoring NetworkManager returns these ports to automatic management.
- OpenWrt LLDP packages installed with `opkg -d ram` and the `/tmp/lldpd` runtime are temporary RAM state and disappear on router reboot. LLDP is not required for Cirotech discovery.
- The Valsec PostgreSQL Docker volume persists audit data across container restarts. Do not remove it for the demo.
- No router factory reset, firmware upgrade, persistent package installation, or permanent Cirotech/OpenWrt configuration change is part of this runbook.
