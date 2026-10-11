package com.ids.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;

@Component
public class DatabaseInit {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @PostConstruct
    public void init() {
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'viewer', created_at TEXT DEFAULT (datetime('now')))");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, timestamp TEXT, alert_type TEXT, severity TEXT, source_ip TEXT, dest_ip TEXT, description TEXT, packet_count INTEGER, details TEXT, agent_id TEXT DEFAULT 'local')");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, api_key TEXT UNIQUE NOT NULL, last_seen TEXT, created_at TEXT DEFAULT (datetime('now')))");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS agent_stats (agent_id TEXT PRIMARY KEY, stats_json TEXT, alerts_triggered INTEGER DEFAULT 0)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS config_store (key TEXT PRIMARY KEY, value TEXT)");
    }
}
