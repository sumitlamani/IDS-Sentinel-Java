package com.ids.agent;

import java.util.*;
import java.net.http.*;
import java.net.URI;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

public class AgentApplication {
    public static void main(String[] args) throws Exception {
        boolean demoMode = Arrays.asList(args).contains("--demo");
        System.out.println("[*] Starting IDS Java Agent " + (demoMode ? "(DEMO Mode)" : "(LIVE Capture Mode)") + "...");

        HttpClient client = HttpClient.newHttpClient();
        ObjectMapper mapper = new ObjectMapper();

        // 1. Discover capture interface
        PcapNetworkInterface chosenNif = null;
        try {
            for (PcapNetworkInterface d : Pcaps.findAllDevs()) {
                if (!d.isLoopBack() && d.isUp() && d.getName().startsWith("en")) {
                    chosenNif = d;
                    break;
                }
            }
            if (chosenNif == null) {
                List<PcapNetworkInterface> all = Pcaps.findAllDevs();
                if (!all.isEmpty()) chosenNif = all.get(0);
            }
        } catch (Exception e) {
            System.out.println("[!] Notice during interface discovery: " + e.getMessage());
        }

        final PcapNetworkInterface nif = chosenNif;
        final String ifaceName = nif != null ? nif.getName() : "en0";
        if (nif != null) {
            System.out.println("[*] Bound to interface: " + ifaceName);
        } else {
            System.out.println("[!] No capture interface detected.");
        }

        // 2. Register Agent
        Map<String, String> regBody = new HashMap<>();
        regBody.put("name", demoMode ? "Java Agent (Demo)" : "Java Agent (Live)");

        HttpRequest regReq = HttpRequest.newBuilder()
            .uri(URI.create("http://localhost:8080/api/agents"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(regBody)))
            .build();

        String apiKey = null;
        while (apiKey == null) {
            try {
                HttpResponse<String> regRes = client.send(regReq, HttpResponse.BodyHandlers.ofString());
                Map<String, String> agent = mapper.readValue(regRes.body(), Map.class);
                apiKey = agent.get("api_key");
                System.out.println("[*] Registered successfully. API Key: " + apiKey);
            } catch (java.net.ConnectException e) {
                System.out.println("[!] Server not reachable. Retrying in 3 seconds...");
                Thread.sleep(3000);
            } catch (Exception e) {
                System.out.println("[!] Unexpected error: " + e.getMessage());
                Thread.sleep(3000);
            }
        }

        final String finalApiKey = apiKey;
        final long startTime = System.currentTimeMillis();
        final AttackDetector detector = new AttackDetector();

        // 3. Background sync loop (pushes metrics and alerts every 2s)
        Thread syncThread = new Thread(() -> {
            int lastPackets = 0;
            while (true) {
                try {
                    Thread.sleep(2000);
                    int currentPackets = AgentStats.packets;
                    int pps = (currentPackets - lastPackets) / 2;
                    lastPackets = currentPackets;

                    Map<String, Object> payload = new HashMap<>();
                    Map<String, Object> stats = new HashMap<>();
                    stats.put("total_packets", AgentStats.packets);
                    stats.put("packets_per_sec", Math.max(0, pps));
                    stats.put("uptime_seconds", (int)((System.currentTimeMillis() - startTime) / 1000));
                    stats.put("demo_mode", demoMode);
                    stats.put("interface", ifaceName);

                    Map<String, Integer> protoCounts = new HashMap<>();
                    protoCounts.put("TCP", AgentStats.tcpPackets);
                    protoCounts.put("UDP", AgentStats.udpPackets);
                    protoCounts.put("ICMP", AgentStats.icmpPackets);
                    stats.put("protocol_counts", protoCounts);
                    stats.put("alerts_triggered", AgentStats.triggered);

                    // Top talkers (sorted descending, top 8)
                    Map<String, Integer> sortedTalkers = new LinkedHashMap<>();
                    AgentStats.topTalkers.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                        .limit(8)
                        .forEach(e -> sortedTalkers.put(e.getKey(), e.getValue()));
                    stats.put("top_talkers", sortedTalkers);

                    payload.put("stats", stats);

                    List<Map<String, Object>> alertsToSend;
                    synchronized(AgentStats.alerts) {
                        alertsToSend = new ArrayList<>(AgentStats.alerts);
                        AgentStats.alerts.clear();
                    }
                    payload.put("alerts", alertsToSend);

                    HttpRequest syncReq = HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:8080/api/agent/sync"))
                        .header("Content-Type", "application/json")
                        .header("X-API-Key", finalApiKey)
                        .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload)))
                        .build();

                    HttpResponse<String> syncRes = client.send(syncReq, HttpResponse.BodyHandlers.ofString());
                    if (syncRes.statusCode() == 200) {
                        try {
                            Map<String, Object> respMap = mapper.readValue(syncRes.body(), Map.class);
                            if (respMap.containsKey("config")) {
                                detector.updateConfig((Map<String, Object>) respMap.get("config"));
                            }
                        } catch (Exception ex) {}
                    }
                } catch (Exception e) {
                    System.out.println("[!] Sync failed: " + e.getMessage());
                }
            }
        });
        syncThread.setDaemon(true);
        syncThread.start();

        // 4. Demo Simulation Thread (active only if --demo is specified)
        if (demoMode) {
            Thread demoThread = new Thread(() -> {
                Random rand = new Random();
                String[] threatIps = {
                    "185.220.101.5", "45.143.200.12", "194.26.29.112",
                    "91.240.118.172", "193.163.125.8", "198.51.100.42"
                };
                int step = 0;

                while (true) {
                    try {
                        Thread.sleep(4000 + rand.nextInt(4000));
                        AgentStats.packets += (50 + rand.nextInt(150));
                        AgentStats.tcpPackets += (30 + rand.nextInt(100));
                        AgentStats.udpPackets += (10 + rand.nextInt(40));
                        AgentStats.icmpPackets += (2 + rand.nextInt(10));

                        String attacker = threatIps[rand.nextInt(threatIps.length)];
                        String target = "192.168.1.100";
                        AgentStats.topTalkers.merge(attacker, 20 + rand.nextInt(40), Integer::sum);
                        AgentStats.topTalkers.merge(target, 15 + rand.nextInt(30), Integer::sum);

                        Map<String, Object> simAlert = null;
                        switch (step % 6) {
                            case 0:
                                simAlert = AttackDetector.createAlert("PORT_SCAN", "HIGH", attacker, target,
                                    "Aggressive Port Scan: 28 unique destination ports probed in 10s",
                                    28, Map.of("scanned_ports_count", 28));
                                break;
                            case 1:
                                simAlert = AttackDetector.createAlert("SYN_FLOOD", "CRITICAL", attacker, target,
                                    "TCP SYN Flood (DDoS): 1,200 unacknowledged SYN packets/sec detected",
                                    1200, Map.of("syn_rate_per_sec", 1200));
                                break;
                            case 2:
                                simAlert = AttackDetector.createAlert("TCP_XMAS_SCAN", "HIGH", attacker, target,
                                    "Stealth TCP Xmas Scan detected (FIN+PSH+URG flags set) on port 80",
                                    1, Map.of("target_port", 80));
                                break;
                            case 3:
                                simAlert = AttackDetector.createAlert("LAND_ATTACK", "CRITICAL", target, target,
                                    "LAND Attack: Spoofed packet with identical source and destination IP:Port (192.168.1.100:443)",
                                    1, Map.of("port", 443));
                                break;
                            case 4:
                                simAlert = AttackDetector.createAlert("ICMP_FLOOD", "HIGH", attacker, target,
                                    "ICMP Ping Storm / Flood detected (>150 echo requests per second)",
                                    150, Map.of("rate_per_sec", 150));
                                break;
                            case 5:
                                simAlert = AttackDetector.createAlert("DNS_TUNNELING", "HIGH", attacker, target,
                                    "Suspicious DNS tunnel exfiltration payload (780 bytes) via Port 53",
                                    1, Map.of("packet_size", 780));
                                break;
                        }
                        step++;

                        if (simAlert != null) {
                            synchronized(AgentStats.alerts) {
                                AgentStats.triggered++;
                                AgentStats.alerts.add(simAlert);
                            }
                            System.out.println("🚨 [DEMO ATTACK INJECTED] " + simAlert.get("alert_type") + " from " + simAlert.get("source_ip"));
                        }
                    } catch (InterruptedException e) {
                        break;
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            });
            demoThread.setDaemon(true);
            demoThread.start();
        }

        // 5. Live Sniffing Loop
        if (nif == null) {
            System.out.println("[!] No capture interface available. Running in idle state.");
            while (true) Thread.sleep(5000);
        }

        final PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);

        PacketListener listener = packet -> {
            AgentStats.packets++;
            if (packet.contains(TcpPacket.class)) AgentStats.tcpPackets++;
            else if (packet.contains(UdpPacket.class)) AgentStats.udpPackets++;
            else if (packet.contains(IcmpV4CommonPacket.class)) AgentStats.icmpPackets++;

            // Record IP for Top Talkers
            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipPkt = packet.get(IpV4Packet.class);
                String src = ipPkt.getHeader().getSrcAddr().getHostAddress();
                if (src != null && !src.equals("127.0.0.1") && !src.equals("0.0.0.0")) {
                    AgentStats.topTalkers.merge(src, 1, Integer::sum);
                }
            }

            // Inspect packet through AttackDetector engine
            List<Map<String, Object>> detected = detector.inspect(packet);
            if (!detected.isEmpty()) {
                synchronized(AgentStats.alerts) {
                    for (Map<String, Object> a : detected) {
                        AgentStats.triggered++;
                        AgentStats.alerts.add(a);
                        System.out.println("🚨 [ATTACK DETECTED] " + a.get("alert_type") + " from " + a.get("source_ip") + " (" + a.get("severity") + ")");
                    }
                }
            }
        };

        try {
            handle.loop(-1, listener);
        } catch (InterruptedException e) {
            handle.close();
        }
    }
}

class AgentStats {
    static volatile int packets = 0;
    static volatile int tcpPackets = 0;
    static volatile int udpPackets = 0;
    static volatile int icmpPackets = 0;
    static volatile int triggered = 0;
    static final List<Map<String, Object>> alerts = new ArrayList<>();
    static final Map<String, Integer> topTalkers = new java.util.concurrent.ConcurrentHashMap<>();
}
