#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "🚀 Starting Java IDS Dashboard Server..."

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

echo "✅ Building project and running the Server..."
mvn clean install -DskipTests
mvn -pl server spring-boot:run
