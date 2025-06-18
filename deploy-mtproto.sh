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
    log "Applying ultra-low latency system optimizations..."
    
    # Disable exit on error temporarily for sysctl
    set +e
    
    # Ultra-aggressive network optimizations for lowest latency
    cat > /etc/sysctl.d/99-mtproto-ultra.conf << EOF
# Ultra-low latency optimizations for MTProto proxy
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Maximum buffer sizes for high throughput
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 67108864
net.core.wmem_default = 67108864
net.core.netdev_max_backlog = 30000
net.core.netdev_budget = 600

# TCP buffer tuning for ultra-low latency
net.ipv4.tcp_rmem = 8192 131072 134217728
net.ipv4.tcp_wmem = 8192 131072 134217728
net.ipv4.tcp_mem = 786432 1048576 26777216

# Ultra-aggressive TCP settings
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_low_latency = 1

# Minimize TCP delays
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 1440000

# Network interface optimizations
net.core.busy_read = 50
net.core.busy_poll = 50
net.ipv4.tcp_moderate_rcvbuf = 0

# Reduce network latency
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_thin_linear_timeouts = 1

# Memory and CPU optimizations
vm.swappiness = 1
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
kernel.sched_autogroup_enabled = 0
EOF
    
    # Apply sysctl settings and continue even if some fail
    log "Applying network optimizations (ignoring unsupported parameters)..."
    sysctl -p /etc/sysctl.d/99-mtproto-ultra.conf 2>/dev/null || true
    
    # Re-enable exit on error
    set -e
    
    log "Ultra-low latency system optimizations applied"
}

install_docker() {
    log "Installing Docker..."
    
    if command -v docker &> /dev/null; then
        log "Docker already installed"
        # Make sure Docker is running
        systemctl start docker 2>/dev/null || true
        return
    fi
    
    log "Downloading Docker installation script..."
    # Install Docker with timeout
    if ! timeout 300 bash -c 'curl -fsSL https://get.docker.com | sh'; then
        error "Docker installation timed out or failed"
    fi
    
    log "Starting Docker service..."
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    # Wait for Docker to be ready
    log "Waiting for Docker to be ready..."
    for i in {1..30}; do
        if docker info >/dev/null 2>&1; then
            break
        fi
        sleep 2
        if [ $i -eq 30 ]; then
            error "Docker failed to start properly"
        fi
    done
    
    log "Docker installed and started successfully"
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
    log "Creating ultra-performance MTProto configuration..."
    
    # Create config directory
    mkdir -p /etc/mtproto
    
    # Create ultra-optimized configuration file
    cat > /etc/mtproto/mtg.toml << EOF
secret = "$SECRET"
bind-to = "0.0.0.0:$PORT"

# Ultra-performance optimizations
stats-bind-to = "127.0.0.1:3129"

# Maximum connections for single CPU
multiplex-per-connection = 1000
prefer-ip = "prefer-ipv4"

# Ultra-low latency settings
read-buffer-size = 131072
write-buffer-size = 131072

# Disable unnecessary features for speed
secure-only = false
anti-replay-max-size = 1048576

# Connection limits optimized for 2GB RAM
max-clients = 2000
timeout = "60s"

# Performance tuning
workers = 1
EOF
    
    log "Ultra-performance configuration created"
}

deploy_container() {
    log "Deploying ultra-low latency MTProto container..."
    
    # Remove existing container if exists
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
    
    # Run ultra-optimized container with minimal latency
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        --memory="1536m" \
        --memory-swap="1536m" \
        --cpus="1" \
        --cpu-shares=1024 \
        --oom-kill-disable=false \
        --network=host \
        --security-opt no-new-privileges:true \
        --cap-add=NET_ADMIN \
        --cap-add=SYS_NICE \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=200m,nr_inodes=400k \
        -v /etc/mtproto/mtg.toml:/config.toml:ro \
        --sysctl net.core.somaxconn=65535 \
        --sysctl net.ipv4.tcp_keepalive_time=300 \
        --sysctl net.ipv4.tcp_keepalive_intvl=30 \
        --sysctl net.ipv4.tcp_fin_timeout=15 \
        --ulimit nofile=1048576:1048576 \
        --ulimit nproc=65536:65536 \
        --log-driver none \
        nineseconds/mtg:2
    
    # Wait for container to start
    sleep 3
    
    # Verify container is running
    if ! docker ps | grep -q $CONTAINER_NAME; then
        # Fallback to bridge mode if host networking fails
        log "Host networking failed, trying bridge mode..."
        docker run -d \
            --name $CONTAINER_NAME \
            --restart unless-stopped \
            --memory="1536m" \
            --memory-swap="1536m" \
            --cpus="1" \
            --security-opt no-new-privileges:true \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,size=200m \
            -v /etc/mtproto/mtg.toml:/config.toml:ro \
            -p $PORT:$PORT \
            --ulimit nofile=1048576:1048576 \
            --log-driver none \
            nineseconds/mtg:2
        
        sleep 3
        if ! docker ps | grep -q $CONTAINER_NAME; then
            error "Container failed to start"
        fi
    fi
    
    # Set container process priority for lowest latency
    CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER_NAME)
    if [ -n "$CONTAINER_PID" ]; then
        # Set highest priority and real-time scheduling
        chrt -f -p 99 $CONTAINER_PID 2>/dev/null || true
        renice -20 $CONTAINER_PID 2>/dev/null || true
        
        # Set CPU affinity to core 0 for consistency
        taskset -cp 0 $CONTAINER_PID 2>/dev/null || true
    fi
    
    log "Ultra-low latency container deployed successfully"
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

delete_proxy() {
    log "Starting MTProto proxy deletion..."
    
    # Stop and remove container
    if docker ps -a | grep -q $CONTAINER_NAME; then
        log "Stopping and removing container..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
    fi
    
    # Remove Docker image
    if docker images | grep -q "nineseconds/mtg"; then
        log "Removing Docker image..."
        docker rmi nineseconds/mtg:2 2>/dev/null || true
    fi
    
    # Remove configuration files
    if [ -d "/etc/mtproto" ]; then
        log "Removing configuration files..."
        rm -rf /etc/mtproto
    fi
    
    # Remove system optimizations
    if [ -f "/etc/sysctl.d/99-mtproto-ultra.conf" ]; then
        log "Removing system optimizations..."
        rm -f /etc/sysctl.d/99-mtproto-ultra.conf
    fi
    
    # Remove monitoring script
    if [ -f "/usr/local/bin/mtproto-status" ]; then
        log "Removing monitoring script..."
        rm -f /usr/local/bin/mtproto-status
    fi
    
    # Close firewall port
    log "Closing firewall port..."
    if command -v ufw &> /dev/null; then
        ufw delete allow $PORT 2>/dev/null || true
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --remove-port=$PORT/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    else
        iptables -D INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null || true
    fi
    
    # Clean up Docker system
    log "Cleaning up Docker system..."
    docker system prune -af 2>/dev/null || true
    
    log "MTProto proxy completely removed!"
    echo ""
    echo "========================="
    echo "Cleanup Complete"
    echo "========================="
    echo "All MTProto proxy components have been removed:"
    echo "- Container stopped and removed"
    echo "- Docker image removed"
    echo "- Configuration files deleted"
    echo "- System optimizations reverted"
    echo "- Firewall rules removed"
    echo "- Monitoring scripts removed"
    echo "========================="
}

print_connection_info() {
    log "Deployment completed successfully!"
    
    # Get server IP
    SERVER_IP=$(curl -s ipv4.icanhazip.com 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    echo ""
    echo "########################################"
    echo "#        DEPLOYMENT SUCCESSFUL!       #"
    echo "########################################"
    echo ""
    echo " MTProto Proxy is now running!"
    echo ""
    echo " CONNECTION DETAILS:"
    echo "   Server IP: $SERVER_IP"
    echo "   Port: $PORT"
    echo "   Secret: $SECRET"
    echo ""
    echo " TELEGRAM CONNECTION STRING:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "tg://proxy?server=$SERVER_IP&port=$PORT&secret=$SECRET"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo " Copy the connection string above and paste it in Telegram"
    echo ""
    echo "🔧 MANAGEMENT COMMANDS:"
    echo "   Status:    mtproto-status"
    echo "   Logs:      docker logs mtproto-proxy"
    echo "   Restart:   docker restart mtproto-proxy"
    echo "   Stop:      docker stop mtproto-proxy"
    echo "   Start:     docker start mtproto-proxy"
    echo "   DELETE:    sudo ./deploy-mtproto.sh delete"
    echo ""
    echo " Configuration: /etc/mtproto/mtg.toml"
    echo ""
    echo "########################################"
    echo "#         ULTRA-LOW LATENCY           #"
    echo "#       MTPROTO PROXY READY!          #"
    echo "########################################"
}

show_usage() {
    echo "MTProto Proxy Deployment Script"
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  deploy  - Deploy MTProto proxy (default)"
    echo "  delete  - Remove MTProto proxy completely"
    echo "  status  - Show proxy status"
    echo ""
    echo "Examples:"
    echo "  $0          # Deploy proxy"
    echo "  $0 deploy   # Deploy proxy"
    echo "  $0 delete   # Remove proxy"
    echo "  $0 status   # Check status"
}

show_status() {
    if command -v mtproto-status &> /dev/null; then
        mtproto-status
    else
        echo "MTProto proxy not installed or monitoring not available"
        if docker ps | grep -q mtproto-proxy; then
            echo "Container Status: Running"
            docker stats --no-stream --format 'table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}' mtproto-proxy
        else
            echo "Container Status: Not running"
        fi
    fi
}

main() {
    case "${1:-deploy}" in
        deploy)
            log "Starting MTProto proxy deployment..."
            echo "Progress: [1/9] Checking system requirements..."
            check_requirements
            echo "Progress: [2/9] Applying system optimizations..."
            optimize_system
            echo "Progress: [3/9] Installing Docker..."
            install_docker
            echo "Progress: [4/9] Configuring firewall..."
            configure_firewall
            echo "Progress: [5/9] Generating MTProto secret..."
            generate_secret
            echo "Progress: [6/9] Creating configuration..."
            create_config
            echo "Progress: [7/9] Deploying container..."
            deploy_container
            echo "Progress: [8/9] Setting up monitoring..."
            setup_monitoring
            echo "Progress: [9/9] Cleaning up..."
            cleanup
            print_connection_info
            log "Deployment script completed successfully!"
            ;;
        delete|remove|uninstall)
            log "Starting MTProto proxy removal..."
            delete_proxy
            log "Removal completed successfully!"
            ;;
        status)
            show_status
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            error "Unknown command: $1. Use '$0 help' for usage information."
            ;;
    esac
}

# Handle script interruption
trap 'error "Script interrupted"' INT TERM

# Run main function
main "$@" 