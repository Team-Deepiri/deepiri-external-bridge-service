#!/bin/bash

# Deepiri Kafka Operations Helper
# 
# Usage:
#   ./kafka-ops.sh [command]
#
# Commands:
#   start                 Start all services
#   stop                  Stop all services
#   status                Check status of all services
#   logs [service]        View logs (api, worker, kafka, redis, all)
#   metrics               Show current metrics
#   health                Check health endpoints
#   dashboards            Open dashboards (Prometheus, Grafana)
#   load-test             Run k6 load test
#   clean                 Clean up volumes (WARNING: loses data)
#   topics                List Kafka topics
#   consumer-groups       List consumer groups
#   inspect-topic [name]  View messages in topic

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONTAINER_PREFIX="deepiri"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
  echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
  echo -e "${GREEN}✓${NC} $1"
}

log_error() {
  echo -e "${RED}✗${NC} $1"
}

log_warning() {
  echo -e "${YELLOW}⚠${NC} $1"
}

# Start services
start() {
  log_info "Starting Deepiri Kafka services..."
  docker-compose up -d
  
  log_info "Waiting for services to be healthy..."
  sleep 5
  
  # Check if services are ready
  for i in {1..30}; do
    if docker-compose ps | grep -q "healthy"; then
      log_success "Services are healthy"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  
  log_warning "Services may still be starting. Check with: docker-compose ps"
}

# Stop services
stop() {
  log_info "Stopping Deepiri Kafka services..."
  docker-compose down
  log_success "Services stopped"
}

# Status of all services
status() {
  log_info "Service Status:"
  echo ""
  docker-compose ps
  echo ""
  
  # Check endpoints
  log_info "Checking endpoints..."
  
  if curl -s http://localhost:5006/health > /dev/null 2>&1; then
    log_success "API service is responding"
  else
    log_error "API service is not responding"
  fi
  
  if curl -s http://localhost:5007/health > /dev/null 2>&1; then
    log_success "Worker service is responding"
  else
    log_error "Worker service is not responding"
  fi
  
  if curl -s http://localhost:9090 > /dev/null 2>&1; then
    log_success "Prometheus is running"
  else
    log_error "Prometheus is not running"
  fi
  
  if curl -s http://localhost:3000 > /dev/null 2>&1; then
    log_success "Grafana is running"
  else
    log_error "Grafana is not running"
  fi
}

# View logs
logs() {
  local service=${1:-all}
  
  case $service in
    api)
      docker-compose logs -f api
      ;;
    worker)
      docker-compose logs -f worker
      ;;
    kafka)
      docker-compose logs -f kafka
      ;;
    redis)
      docker-compose logs -f redis
      ;;
    all|*)
      docker-compose logs -f
      ;;
  esac
}

# Show metrics
metrics() {
  log_info "Fetching metrics from API service..."
  echo ""
  curl -s http://localhost:5006/metrics | grep -E "^(messages|consumer|dlq|publish)" | head -20
  echo ""
  log_info "Full metrics available at: http://localhost:5006/metrics"
}

# Check health
health() {
  log_info "API Service Health:"
  curl -s http://localhost:5006/health | jq '.' || echo "Error: API service not responding"
  echo ""
  
  log_info "Worker Service Health:"
  curl -s http://localhost:5007/health | jq '.' || echo "Error: Worker service not responding"
  echo ""
  
  log_info "Worker Status:"
  curl -s http://localhost:5007/status | jq '.' || echo "Error: Worker service not responding"
}

# Open dashboards
dashboards() {
  log_info "Opening dashboards..."
  
  if command -v open &> /dev/null; then
    # macOS
    open http://localhost:9090
    sleep 1
    open http://localhost:3000
  elif command -v xdg-open &> /dev/null; then
    # Linux
    xdg-open http://localhost:9090
    sleep 1
    xdg-open http://localhost:3000
  else
    log_warning "Could not auto-open browsers. Visit manually:"
    echo "  Prometheus: http://localhost:9090"
    echo "  Grafana: http://localhost:3000 (admin/admin)"
  fi
}

# Run load test
load_test() {
  if ! command -v k6 &> /dev/null; then
    log_error "k6 is not installed. Install with: brew install k6"
    return 1
  fi
  
  log_info "Starting load test..."
  k6 run load-test.js
}

# Clean up volumes
clean() {
  log_warning "This will delete all data in volumes!"
  read -p "Are you sure? (type 'yes' to confirm): " confirm
  
  if [ "$confirm" = "yes" ]; then
    log_info "Cleaning up..."
    docker-compose down -v
    log_success "Volumes cleaned"
  else
    log_info "Cancelled"
  fi
}

# List Kafka topics
topics() {
  log_info "Kafka Topics:"
  docker exec ${CONTAINER_PREFIX}-kafka kafka-topics \
    --bootstrap-server localhost:29092 \
    --list
}

# List consumer groups
consumer_groups() {
  log_info "Kafka Consumer Groups:"
  docker exec ${CONTAINER_PREFIX}-kafka kafka-consumer-groups \
    --bootstrap-server localhost:29092 \
    --list
}

# Inspect topic messages
inspect_topic() {
  local topic=${1:-integration.webhook.received}
  
  if [ "$topic" = "" ]; then
    log_error "Topic name required. Usage: $0 inspect-topic [topic-name]"
    echo "Available topics:"
    topics
    return 1
  fi
  
  log_info "Messages in topic: $topic (last 5)"
  docker exec ${CONTAINER_PREFIX}-kafka kafka-console-consumer \
    --bootstrap-server localhost:29092 \
    --topic "$topic" \
    --from-beginning \
    --max-messages 5 \
    --property print.timestamp=true \
    --property print.key=true \
    --property key.separator=":" || true
}

# Main
if [ $# -eq 0 ]; then
  cat << EOF
${BLUE}Deepiri Kafka Operations${NC}

Usage: $0 [command]

Commands:
  start              Start all services
  stop               Stop all services
  status             Check status of all services
  logs [service]     View logs (api, worker, kafka, redis, all)
  metrics            Show current metrics
  health             Check health endpoints
  dashboards         Open Prometheus & Grafana
  load-test          Run k6 load test
  topics             List Kafka topics
  consumer-groups    List consumer groups
  inspect-topic      View messages in topic
  clean              Clean up volumes (WARNING: loses data)

Examples:
  $0 start
  $0 logs api
  $0 topics
  $0 inspect-topic integration.webhook.received
EOF
  exit 0
fi

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  status)
    status
    ;;
  logs)
    logs "$2"
    ;;
  metrics)
    metrics
    ;;
  health)
    health
    ;;
  dashboards)
    dashboards
    ;;
  load-test)
    load_test
    ;;
  topics)
    topics
    ;;
  consumer-groups)
    consumer_groups
    ;;
  inspect-topic)
    inspect_topic "$2"
    ;;
  clean)
    clean
    ;;
  *)
    log_error "Unknown command: $1"
    exit 1
    ;;
esac
