#!/bin/bash

# MTProto Proxy Docker Deployment Script
# Optimized for 1vCPU 2GB RAM VPS
# High performance single script deployment

set -e

# Configuration
PORT=${PORT:-443}
CLEARTEXT=${CLEARTEXT:-"bing.com"}
CONTAINER_NAME="mtproto-proxy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_requirements() {
    log "Checking system requirements..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
    
    # Check available memory
    MEMORY_MB=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [[ $MEMORY_MB -lt 1024 ]]; then
        warn "Low memory detected: ${MEMORY_MB}MB. Recommended: 2GB+"
    fi
    
    # Check available disk space
    DISK_FREE_GB=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ $DISK_FREE_GB -lt 2 ]]; then
        error "Insufficient disk space. Required: 2GB, Available: ${DISK_FREE_GB}GB"
    fi
    
    log "System requirements check passed"
}

optimize_system() {
    log "Applying system optimizations for low latency..."
    
    # Network optimizations
    cat > /etc/sysctl.d/99-mtproto.conf << EOF
# Network optimizations for MTProto proxy
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 65536 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 9
EOF
    
    sysctl -p /etc/sysctl.d/99-mtproto.conf
    
    # Set CPU governor to performance if available
    if command -v cpupower &> /dev/null; then
        cpupower frequency-set -g performance 2>/dev/null || true
    fi
    
    log "System optimizations applied"
}

install_docker() {
    log "Installing Docker..."
    
    if command -v docker &> /dev/null; then
        log "Docker already installed"
        return
    fi
    
    # Install Docker
    curl -fsSL https://get.docker.com | sh
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    # Verify installation
    if ! command -v docker &> /dev/null; then
        error "Docker installation failed"
    fi
    
    log "Docker installed successfully"
}

configure_firewall() {
    log "Configuring firewall..."
    
    # Configure UFW if available
    if command -v ufw &> /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw allow $PORT
        ufw --force enable
        log "UFW firewall configured"
    # Configure firewalld if available
    elif command -v firewall-cmd &> /dev/null; then
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --permanent --add-port=$PORT/tcp
        firewall-cmd --reload
        log "Firewalld configured"
    # Configure iptables as fallback
    else
        iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
        iptables-save > /etc/iptables.rules 2>/dev/null || true
        log "Iptables configured"
    fi
}

generate_secret() {
    log "Generating MTProto secret..."
    
    # Pull the MTG Docker image
    docker pull nineseconds/mtg:2
    
    # Generate secret
    SECRET=$(docker run --rm nineseconds/mtg:2 generate-secret $CLEARTEXT)
    
    if [[ -z "$SECRET" ]]; then
        error "Failed to generate secret"
    fi
    
    log "Secret generated successfully"
}

create_config() {
    log "Creating MTProto configuration..."
    
    # Create config directory
    mkdir -p /etc/mtproto
    
    # Create configuration file
    cat > /etc/mtproto/mtg.toml << EOF
secret = "$SECRET"
bind-to = "0.0.0.0:$PORT"

# Performance optimizations
stats-bind-to = "127.0.0.1:3129"
multiplex-per-connection = 500
prefer-ip = "prefer-ipv4"
EOF
    
    log "Configuration created"
}

deploy_container() {
    log "Deploying MTProto container..."
    
    # Remove existing container if exists
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
    
    # Run optimized container
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        --memory="1g" \
        --cpus="1" \
        --security-opt no-new-privileges:true \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=100m \
        -v /etc/mtproto/mtg.toml:/config.toml:ro \
        -p $PORT:$PORT \
        --log-driver json-file \
        --log-opt max-size=10m \
        --log-opt max-file=3 \
        nineseconds/mtg:2
    
    # Wait for container to start
    sleep 5
    
    # Check if container is running
    if ! docker ps | grep -q $CONTAINER_NAME; then
        error "Container failed to start"
    fi
    
    log "Container deployed successfully"
}

setup_monitoring() {
    log "Setting up basic monitoring..."
    
    # Create monitoring script
    cat > /usr/local/bin/mtproto-status << 'EOF'
#!/bin/bash
echo "MTProto Proxy Status:"
echo "===================="
echo "Container Status: $(docker ps --format 'table {{.Status}}' --filter name=mtproto-proxy | tail -1)"
echo "Memory Usage: $(docker stats --no-stream --format 'table {{.MemUsage}}' mtproto-proxy | tail -1)"
echo "CPU Usage: $(docker stats --no-stream --format 'table {{.CPUPerc}}' mtproto-proxy | tail -1)"
echo "Port Status: $(netstat -tlnp | grep :443 || echo 'Port not listening')"
EOF
    
    chmod +x /usr/local/bin/mtproto-status
    
    log "Monitoring setup complete. Use 'mtproto-status' to check status"
}

cleanup() {
    log "Cleaning up temporary files..."
    docker system prune -f
    log "Cleanup complete"
}

print_connection_info() {
    log "Deployment completed successfully!"
    echo ""
    echo "========================="
    echo "MTProto Proxy Information"
    echo "========================="
    echo "Server IP: $(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
    echo "Port: $PORT"
    echo "Secret: $SECRET"
    echo ""
    echo "Connection URL for Telegram:"
    echo "tg://proxy?server=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')&port=$PORT&secret=$SECRET"
    echo ""
    echo "Management Commands:"
    echo "  Status:    mtproto-status"
    echo "  Logs:      docker logs mtproto-proxy"
    echo "  Restart:   docker restart mtproto-proxy"
    echo "  Stop:      docker stop mtproto-proxy"
    echo "  Start:     docker start mtproto-proxy"
    echo ""
    echo "Configuration saved to: /etc/mtproto/mtg.toml"
    echo "========================="
}

main() {
    log "Starting MTProto proxy deployment..."
    
    check_requirements
    optimize_system
    install_docker
    configure_firewall
    generate_secret
    create_config
    deploy_container
    setup_monitoring
    cleanup
    print_connection_info
    
    log "Deployment script completed successfully!"
}

# Handle script interruption
trap 'error "Script interrupted"' INT TERM

# Run main function
main "$@" 