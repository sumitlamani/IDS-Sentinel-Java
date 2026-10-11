package com.ids.server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private JdbcTemplate jdbcTemplate;
    private final ObjectMapper mapper = new ObjectMapper();

    @PostMapping("/agents")
    public Map<String, Object> createAgent(@RequestBody Map<String, Object> body) {
        String name = body.getOrDefault("name", "Unnamed Agent").toString();
        String agentId = UUID.randomUUID().toString().substring(0, 8);
        String apiKey = "ak_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        
        jdbcTemplate.update("INSERT INTO agents (id, name, api_key) VALUES (?, ?, ?)", agentId, name, apiKey);
        jdbcTemplate.update("INSERT INTO agent_stats (agent_id, stats_json, alerts_triggered) VALUES (?, ?, 0)", agentId, "{}");
        
        Map<String, Object> res = new HashMap<>();
        res.put("id", agentId); res.put("name", name); res.put("api_key", apiKey);
        return res;
    }

    @GetMapping("/agents")
    public List<Map<String, Object>> getAgents() {
        return jdbcTemplate.queryForList("SELECT id, name, last_seen, created_at FROM agents ORDER BY created_at DESC");
    }

    @PostMapping("/agent/sync")
    public Map<String, Object> syncAgent(@RequestHeader(value = "X-API-Key", required = false) String apiKey, @RequestBody Map<String, Object> payload) throws Exception {
        Map<String, Object> res = new HashMap<>();
        if (apiKey == null) { res.put("error", "missing api key"); return res; }
        
        List<Map<String, Object>> agents = jdbcTemplate.queryForList("SELECT id FROM agents WHERE api_key=?", apiKey);
        if (agents.isEmpty()) { res.put("error", "invalid api key"); return res; }
        
        String agentId = agents.get(0).get("id").toString();
        Map<String, Object> stats = (Map<String, Object>) payload.getOrDefault("stats", new HashMap<>());
        List<Map<String, Object>> alerts = (List<Map<String, Object>>) payload.getOrDefault("alerts", new ArrayList<>());
        int alertsTriggered = (Integer) stats.getOrDefault("alerts_triggered", 0);
        
        jdbcTemplate.update("UPDATE agent_stats SET stats_json=?, alerts_triggered=? WHERE agent_id=?", mapper.writeValueAsString(stats), alertsTriggered, agentId);
        jdbcTemplate.update("UPDATE agents SET last_seen=datetime('now') WHERE id=?", agentId);
        
        for (Map<String, Object> a : alerts) {
            jdbcTemplate.update("INSERT OR IGNORE INTO alerts (id, timestamp, alert_type, severity, source_ip, dest_ip, description, packet_count, details, agent_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                a.get("id"), a.get("timestamp"), a.get("alert_type"), a.get("severity"), a.get("source_ip"), a.get("dest_ip"), a.get("description"), a.get("packet_count"), mapper.writeValueAsString(a.getOrDefault("details", new HashMap<>())), agentId);
        }
        
        res.put("status", "ok");
        res.put("config", getConfig());
        return res;
    }

    @GetMapping("/stream")
    public SseEmitter stream(@RequestParam(value = "agent_id", required = false) String agent_id) {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        ExecutorService sseMvcExecutor = Executors.newSingleThreadExecutor();
        sseMvcExecutor.execute(() -> {
            try {
                if (agent_id == null) {
                    emitter.send(SseEmitter.event().data("{\"error\":\"No agent selected\"}"));
                    return;
                }
                int lastCount = 0;
                try {
                    Integer count = jdbcTemplate.queryForObject("SELECT alerts_triggered FROM agent_stats WHERE agent_id=?", Integer.class, agent_id);
                    if (count != null) lastCount = count;
                } catch(Exception e) {}

                while (true) {
                    List<Map<String, Object>> agentStats = jdbcTemplate.queryForList("SELECT stats_json, alerts_triggered FROM agent_stats WHERE agent_id=?", agent_id);
                    if (agentStats.isEmpty()) {
                        emitter.send(SseEmitter.event().data("{\"error\":\"Agent not found\"}"));
                        Thread.sleep(2000);
                        continue;
                    }
                    
                    Map<String, Object> row = agentStats.get(0);
                    Map<String, Object> stats = mapper.readValue((String)row.get("stats_json"), Map.class);
                    int currCount = (Integer) row.get("alerts_triggered");
                    List<Map<String, Object>> newAlerts = new ArrayList<>();
                    
                    if (currCount > lastCount) {
                        int limit = currCount - lastCount;
                        List<Map<String, Object>> fetchedAlerts = jdbcTemplate.queryForList("SELECT * FROM alerts WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?", agent_id, limit);
                        for (int i = fetchedAlerts.size() - 1; i >= 0; i--) {
                            Map<String, Object> a = new HashMap<>(fetchedAlerts.get(i));
                            a.put("details", mapper.readValue((String)a.get("details"), Map.class));
                            newAlerts.add(a);
                        }
                        lastCount = currCount;
                    }
                    
                    Map<String, Object> eventData = new HashMap<>();
                    eventData.put("stats", stats);
                    eventData.put("new_alerts", newAlerts);
                    emitter.send(SseEmitter.event().data(mapper.writeValueAsString(eventData)));
                    Thread.sleep(1000);
                }
            } catch (Exception ex) {
                emitter.completeWithError(ex);
            }
        });
        return emitter;
    }

    @GetMapping("/alerts")
    public Map<String, Object> getAlerts(@RequestParam(value = "agent_id", required = false) String agent_id, @RequestParam(value = "limit", defaultValue = "50") int limit) {
        Map<String, Object> res = new HashMap<>();
        if (agent_id == null) {
            res.put("alerts", new ArrayList<>());
            res.put("total", 0);
            return res;
        }
        List<Map<String, Object>> alerts = jdbcTemplate.queryForList("SELECT * FROM alerts WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?", agent_id, limit);
        for (Map<String, Object> a : alerts) {
            try {
                a.put("details", mapper.readValue((String)a.get("details"), Map.class));
            } catch (Exception e) {
                a.put("details", new HashMap<>());
            }
        }
        res.put("alerts", alerts);
        res.put("total", alerts.size());
        return res;
    }

    @GetMapping("/config")
    public Map<String, Object> getConfig() {
        Map<String, Object> config = new HashMap<>();
        // Realistic production thresholds to prevent false positives during regular browsing
        config.put("PORT_SCAN_THRESHOLD", 100);
        config.put("PORT_SCAN_WINDOW", 10);
        config.put("DDOS_PPS_THRESHOLD", 5000);
        config.put("SYN_FLOOD_THRESHOLD", 500);
        config.put("ICMP_FLOOD_THRESHOLD", 250);
        config.put("ABNORMAL_PACKET_SIZE", 65000);
        config.put("EMAIL_ENABLED", false);
        config.put("EMAIL_SENDER", "");
        config.put("EMAIL_RECIPIENT", "");
        config.put("EMAIL_COOLDOWN", 300);
        config.put("WEBHOOK_URL", "");
        config.put("IPS_MODE_ENABLED", false);
        config.put("AI_MODE_ENABLED", false);
        config.put("VT_API_KEY", "");
        config.put("GEMINI_API_KEY", "");

        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList("SELECT key, value FROM config_store");
            for (Map<String, Object> r : rows) {
                String key = (String) r.get("key");
                String val = (String) r.get("value");
                if (val != null) {
                    try {
                        config.put(key, mapper.readValue(val, Object.class));
                    } catch (Exception e) {
                        config.put(key, val);
                    }
                }
            }
        } catch (Exception e) {}
        return config;
    }

    @PostMapping("/config")
    public Map<String, Object> updateConfig(@RequestBody Map<String, Object> body) {
        for (Map.Entry<String, Object> entry : body.entrySet()) {
            try {
                String jsonVal = mapper.writeValueAsString(entry.getValue());
                jdbcTemplate.update("INSERT OR REPLACE INTO config_store (key, value) VALUES (?, ?)", entry.getKey(), jsonVal);
            } catch (Exception e) {}
        }
        Map<String, Object> res = new HashMap<>();
        res.put("status", "ok");
        return res;
    }
}
