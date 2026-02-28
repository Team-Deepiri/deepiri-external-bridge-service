#!/bin/bash
# Performance Testing Quick Start Script
# Usage: bash run-performance-tests.sh

set -e

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║        Kafka Architecture Performance Testing Suite        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is running
echo "📋 Checking prerequisites..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

if ! docker ps &> /dev/null; then
    echo -e "${RED}❌ Docker daemon is not running${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker is running${NC}"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Node.js $(node --version) is available${NC}"
echo ""

# Function to wait for service to be healthy
wait_for_service() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=1

    echo -n "⏳ Waiting for $service (port $port)..."
    while [ $attempt -le $max_attempts ]; do
        if nc -z localhost $port 2>/dev/null; then
            echo -e " ${GREEN}✅${NC}"
            return 0
        fi
        echo -n "."
        sleep 1
        ((attempt++))
    done
    echo -e " ${RED}❌ Timeout${NC}"
    return 1
}

# Function to check if container is running
check_container() {
    local container=$1
    if docker-compose ps $container | grep -q "Up"; then
        return 0
    else
        return 1
    fi
}

# Step 1: Start Docker services
echo "🚀 Step 1: Starting Docker services..."
docker-compose up -d
echo -e "${GREEN}✅ Services started${NC}"
echo ""

# Step 2: Wait for services to be healthy
echo "🏥 Step 2: Waiting for services to be healthy..."
wait_for_service "Kafka" 9092 || exit 1
wait_for_service "API Server" 5006 || exit 1
wait_for_service "Worker" 5007 || exit 1
wait_for_service "Prometheus" 9090 || exit 1
wait_for_service "Grafana" 3000 || exit 1
echo ""

# Step 3: Verify Prometheus targets
echo "📊 Step 3: Verifying Prometheus targets..."
echo "   Open http://localhost:9090/targets in your browser"
echo "   Both 'api' and 'worker' should show GREEN (Up)"
echo ""

# Step 4: Ask user which test to run
echo "📋 Step 4: Select test to run:"
echo ""
echo "   1) Progressive Load Test (5→25→50→100→200 RPS) - ~5 min"
echo "   2) Sustained Load Test (50 RPS for 5 min) - ~5 min"
echo "   3) Latency Breakdown Test (100 samples) - ~2 min"
echo "   4) Run all tests sequentially - ~12 min"
echo "   5) Exit"
echo ""
read -p "Enter choice (1-5): " choice

case $choice in
    1)
        echo ""
        echo -e "${YELLOW}Running Progressive Load Test...${NC}"
        echo "⏱️  This will take approximately 5 minutes"
        echo ""
        echo "Open these in separate browser tabs:"
        echo "  - Prometheus: http://localhost:9090"
        echo "  - Grafana: http://localhost:3000 (admin/admin)"
        echo "  - Press Ctrl+C to stop"
        echo ""
        read -p "Press Enter to start..."
        node scripts/progressive-load-test.js
        ;;
    2)
        echo ""
        echo -e "${YELLOW}Running Sustained Load Test...${NC}"
        echo "⏱️  This will take approximately 5 minutes"
        echo ""
        read -p "Press Enter to start..."
        node scripts/sustained-load-test.js 50 300
        ;;
    3)
        echo ""
        echo -e "${YELLOW}Running Latency Breakdown Test...${NC}"
        echo "⏱️  This will take approximately 2 minutes"
        echo ""
        read -p "Press Enter to start..."
        node scripts/latency-breakdown-test.js 100
        ;;
    4)
        echo ""
        echo -e "${YELLOW}Running all tests sequentially...${NC}"
        echo "⏱️  Total duration: ~12 minutes"
        echo ""
        
        echo "🔹 Test 1/3: Progressive Load Test"
        node scripts/progressive-load-test.js
        echo ""
        echo "⏳ Cooling down for 10 seconds..."
        sleep 10
        
        echo ""
        echo "🔹 Test 2/3: Sustained Load Test"
        node scripts/sustained-load-test.js 50 300
        echo ""
        echo "⏳ Cooling down for 10 seconds..."
        sleep 10
        
        echo ""
        echo "🔹 Test 3/3: Latency Breakdown Test"
        node scripts/latency-breakdown-test.js 100
        
        echo ""
        echo -e "${GREEN}✅ All tests complete!${NC}"
        ;;
    5)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    Test Complete!                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 Next Steps:"
echo "   1. Review the results above"
echo "   2. Check Grafana dashboard: http://localhost:3000"
echo "   3. Query Prometheus: http://localhost:9090"
echo "   4. Create PERFORMANCE_RESULTS.md with your findings"
echo "   5. Generate resume bullets using the results"
echo ""
echo "📄 For more info, see:"
echo "   - PROMETHEUS_QUERIES.md (queries & interpretation)"
echo "   - PERFORMANCE_TESTING.md (detailed guide)"
echo ""
echo "🛑 To stop services:"
echo "   docker-compose down"
echo ""
