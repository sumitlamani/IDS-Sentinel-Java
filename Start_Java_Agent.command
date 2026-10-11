#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "🛡️ Starting Java IDS Agent..."

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "⚠️ Maven (mvn) is not installed."
    if command -v brew &> /dev/null; then
        echo "🍺 Installing Maven via Homebrew..."
        brew install maven
    else
        echo "❌ Homebrew is not installed. Please install Maven manually."
        exit 1
    fi
fi

echo "Choose Mode:"
echo "  1) Live Network Capture (Sniffs actual network packets)"
echo "  2) Demo Attack Simulation (Injects Port Scans, SYN Floods, Xmas Scans for testing)"
read -t 4 -p "Select [1 or 2, default is 1]: " mode

AGENT_ARGS=""
if [ "$1" == "--demo" ] || [ "$mode" == "2" ]; then
    echo "🚨 Launching in DEMO ATTACK mode..."
    AGENT_ARGS="--demo"
else
    echo "🛡️ Launching in LIVE CAPTURE mode..."
fi

echo "✅ Starting the Agent (Requires sudo for network capture)..."
sudo java -jar agent/target/agent-1.0-SNAPSHOT-jar-with-dependencies.jar $AGENT_ARGS "$@"
