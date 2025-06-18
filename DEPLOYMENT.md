# MTProto Proxy Docker Deployment

High-performance MTProto proxy deployment optimized for 1vCPU 2GB RAM VPS.

## Quick Deployment

### Method 1: Single Script (Recommended)

```bash
# Download and run the deployment script
curl -sSL https://raw.githubusercontent.com/YOUR_REPO/deploy-mtproto.sh | sudo bash

# Or with custom port
PORT=8443 curl -sSL https://raw.githubusercontent.com/YOUR_REPO/deploy-mtproto.sh | sudo bash
```

### Method 2: Manual Docker Deployment

1. Generate secret:
```bash
docker run --rm nineseconds/mtg:2 generate-secret bing.com
```

2. Create configuration file:
```bash
mkdir -p /etc/mtproto
cat > /etc/mtproto/mtg.toml << EOF
secret = "YOUR_GENERATED_SECRET"
bind-to = "0.0.0.0:443"
stats-bind-to = "127.0.0.1:3129"
multiplex-per-connection = 500
prefer-ip = "prefer-ipv4"
secure-only = true
read-buffer-size = 65536
write-buffer-size = 65536
EOF
```

3. Run container:
```bash
docker run -d \
  --name mtproto-proxy \
  --restart unless-stopped \
  --memory="1g" \
  --cpus="1" \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  -v /etc/mtproto/mtg.toml:/config.toml:ro \
  -p 443:443 \
  nineseconds/mtg:2
```

### Method 3: Docker Compose

1. Clone repository and navigate to directory
2. Generate secret and update `mtg.toml`
3. Run: `docker-compose up -d`

## Performance Optimizations Applied

- BBR congestion control
- TCP Fast Open
- Optimized buffer sizes
- Memory and CPU limits
- Read-only container filesystem
- Minimal logging overhead

## System Requirements

- Ubuntu 18.04+ / Debian 9+ / CentOS 7+
- 1 vCPU minimum
- 2GB RAM recommended
- 2GB free disk space
- Root access

## Management Commands

```bash
# Check status
mtproto-status

# View logs
docker logs mtproto-proxy

# Restart service
docker restart mtproto-proxy

# Stop service
docker stop mtproto-proxy

# Update container
docker pull nineseconds/mtg:2
docker stop mtproto-proxy
docker rm mtproto-proxy
# Re-run the container command
```

## Connection Information

After deployment, you'll receive:
- Server IP
- Port (default 443)
- Secret key
- Telegram connection URL

## Troubleshooting

### Port Issues
- Ensure port 443 is open in firewall
- Check if another service is using the port: `netstat -tlnp | grep :443`

### Container Not Starting
- Check logs: `docker logs mtproto-proxy`
- Verify configuration: `cat /etc/mtproto/mtg.toml`

### Performance Issues
- Monitor resources: `docker stats mtproto-proxy`
- Check system optimizations: `sysctl net.ipv4.tcp_congestion_control`

## Security Notes

- Uses read-only container filesystem
- Runs with security restrictions
- Automatic firewall configuration
- Minimal attack surface 