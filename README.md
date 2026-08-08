# SSH Honeypot

A SSH honeypot written in Go. It impersonates an SSH server, logs every
authentication attempt (source IP, username, password, client version), **always rejects
the login**, and never executes anything the connecting client sends. 

It has been deployed on a VPS since May 2026, where it has logged 382,921 real login attempts from 962 unique
source IPs over 71 days.

## How it works

Opens a TCP listener and speaks enough SSH to get a client through the handshake and into password auth. Every attempt hits a `PasswordCallback`, gets turned into an `Event`, and is rejected with nothing is ever accepted.

Each connection runs in its own goroutine. Events are written out through a `Storage`
interface, so JSON logging and the SQLite backend (in progress) can both record the same
event without the connection-handling code caring which one it's talking to.

```json
{"node_id":"honeypot-1","timestamp":"2026-05-25T18:11:52Z","source_ip":"87.251.64.149","source_port":"38396","username":"root","password":"123456","client_version":"SSH-2.0-sshcustom_0.1","session_id":"0d7dd3d2...","country":"Unknown","asn":"Unknown"}
```

## Current status

| Part | Status |
|---|---|
| SSH server, always-reject auth | Done |
| Structured logging + JSON store | Done |
| SQLite persistence | Done |
| GeoIP enrichment (country / ASN) | Done |
| Medium-interaction fake shell (log commands, canned responses only) | Not started |
| Multi-node collectors > central Postgres aggregator > Grafana | Potential Future Addition |

## Findings from 383k login attempts

Median attempts/day: 4,247
Average attempts/day: 5,393
Single-day spike: 21,766

**Credentials Guessed** 

Top Usernames Guessed:
- `root` (229,444 / 382,921)
- `admin`
- `user`
- `ubuntu`
- `debian`

Top Passwords Guessed:
- `123456`
- `1234`
- `password`
- `123`
- `12345678`

49,376 distinct passwords were tried in total.

**Coordinated Attack Cluster**

Four addresses in the same block (`87.251.64.144`, `87.251.64.145`, `87.251.64.147`,
`87.251.64.149`) account for 176,722 attempts (46% of all attempts). All four sharing
the same client string `SSH-2.0-sshcustom_0.1` and primarily targeting `root`. Therefore,
this is likely a single operator running a co-ordinated attack.

**Client-version fingerprints show a mix of tooling.** 

Top Client-version Fingerprints:
- `SSH-2.0-sshcustom_0.1` (176,772 - see above)
- `SSH-2.0-Go` (119,993)
- `libssh2` (59,093)
- `PuTTY` (~16,000)

## Safety

The honeypot never grants access and never executes attacker input. This is obviously a hard constraint for the planned fake-shell
step too.

## Deployment

```bash
# Edit /etc/ssh/sshd_config, set:
Port 62222

# Open the new port in the firewall (adjust for ufw/iptables/whatever's active)
ufw allow 62222/tcp

# Restart sshd
systemctl restart ssh

# In a SEPARATE terminal, before closing this one:
ssh -p 62222 user@vps-ip

# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone the repo
git clone https://github.com/george-593/ssh-honeypot /opt/ssh-honeypot
cd /opt/ssh-honeypot

# Generate the host key
ssh-keygen -t ed25519 -f host_key -N ""

# Name this node
echo "NODE_ID=<name-this-node>" > deploy/.env

# Add MaxMind credentials for GeoIP updates
echo "GEOIPUPDATE_ACCOUNT_ID=<your-maxmind-account-id>" >> deploy/.env
echo "GEOIPUPDATE_LICENSE_KEY=<your-maxmind-license-key>" >> deploy/.env

mkdir -p data

# Build and start
docker compose -f deploy/docker-compose.yml build --pull
docker compose -f deploy/docker-compose.yml up -d

# Add a cronjob to restart the honeypot weekly to receive GeoIP updates
(crontab -l 2>/dev/null; echo "0 4 * * 1 docker compose -f /opt/ssh-honeypot/deploy/docker-compose.yml restart honeypot") | crontab -
```

### Check Running
`ssh test@<vps-ip>`
`docker compose -f deploy/docker-compose.yml logs -f`

### Updating
`chmod +x scripts/update.sh`
`./scripts/update.sh`
`docker compose -f deploy/docker-compose.yml logs -f`
