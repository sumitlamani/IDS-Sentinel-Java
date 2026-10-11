package com.ids.agent;

import org.pcap4j.packet.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class AttackDetector {

    // Realistic production thresholds (prevents false positives during normal browsing/streaming)
    private volatile int portScanThreshold = 100;        // 100 unique destination ports
    private volatile long portScanWindowMs = 10000;      // 10 seconds
    private volatile int synFloodThreshold = 500;        // 500 unacknowledged SYNs in 5s
    private volatile long synFloodWindowMs = 5000;       // 5 seconds
    private volatile int icmpFloodThreshold = 250;       // 250 ICMP echo requests in 5s
    private volatile long icmpFloodWindowMs = 5000;      // 5 seconds
    private volatile int udpFloodThreshold = 1000;       // 1000 UDP packets in 5s (safe for video/VoIP)
    private volatile long udpFloodWindowMs = 5000;       // 5 seconds
    private volatile int httpFloodThreshold = 500;       // 500 HTTP requests in 5s
    private volatile long httpFloodWindowMs = 5000;      // 5 seconds
    private volatile int abnormalPacketSize = 65000;     // 65KB (Ping of Death / MTU evasion)
    private volatile int dnsTunnelPayloadSize = 1200;    // >1200 bytes payload
    private volatile int dnsTunnelCountThreshold = 40;   // >=40 large queries in 10s

    // Alert cooldown per (source_ip + alert_type) in ms to prevent log flooding
    private static final long ALERT_COOLDOWN_MS = 20000; // 20s

    // Known local host IPs to identify and ignore outbound traffic
    private final Set<String> localIps = Collections.newSetFromMap(new ConcurrentHashMap<>());

    // State tracking
    private final Map<String, Deque<PortAttempt>> portScanTracker = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> synTracker = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> icmpTracker = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> udpTracker = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> httpTracker = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> dnsTunnelTracker = new ConcurrentHashMap<>();
    private final Map<String, String> arpTable = new ConcurrentHashMap<>();
    private final Map<String, Long> alertCooldowns = new ConcurrentHashMap<>();

    private static class PortAttempt {
        final int port;
        final long time;
        PortAttempt(int port, long time) { this.port = port; this.time = time; }
    }

    public AttackDetector() {
        discoverLocalIps();
    }

    private void discoverLocalIps() {
        localIps.add("127.0.0.1");
        localIps.add("::1");
        localIps.add("0.0.0.0");
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    String host = addr.getHostAddress();
                    if (host != null) {
                        localIps.add(host);
                        // Also strip IPv6 zone identifiers if any
                        if (host.contains("%")) {
                            localIps.add(host.substring(0, host.indexOf("%")));
                        }
                    }
                }
            }
        } catch (Exception e) {
            // fallback
        }
    }

    public void updateConfig(Map<String, Object> cfg) {
        if (cfg == null) return;
        try {
            if (cfg.containsKey("PORT_SCAN_THRESHOLD")) {
                this.portScanThreshold = ((Number) cfg.get("PORT_SCAN_THRESHOLD")).intValue();
            }
            if (cfg.containsKey("PORT_SCAN_WINDOW")) {
                this.portScanWindowMs = ((Number) cfg.get("PORT_SCAN_WINDOW")).longValue() * 1000L;
            }
            if (cfg.containsKey("SYN_FLOOD_THRESHOLD")) {
                this.synFloodThreshold = ((Number) cfg.get("SYN_FLOOD_THRESHOLD")).intValue();
            }
            if (cfg.containsKey("ICMP_FLOOD_THRESHOLD")) {
                this.icmpFloodThreshold = ((Number) cfg.get("ICMP_FLOOD_THRESHOLD")).intValue();
            }
            if (cfg.containsKey("ABNORMAL_PACKET_SIZE")) {
                this.abnormalPacketSize = ((Number) cfg.get("ABNORMAL_PACKET_SIZE")).intValue();
            }
        } catch (Exception e) {
            // Ignore format mismatch
        }
    }

    private boolean isLocalOrIgnored(String ip) {
        if (ip == null) return true;
        if (localIps.contains(ip)) return true;
        if (ip.startsWith("127.") || ip.equals("0.0.0.0") || ip.startsWith("224.") || ip.startsWith("239.")) return true;
        return false;
    }

    public List<Map<String, Object>> inspect(Packet packet) {
        List<Map<String, Object>> detectedAlerts = new ArrayList<>();
        long now = System.currentTimeMillis();

        String srcIp = null;
        String dstIp = null;

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipPkt = packet.get(IpV4Packet.class);
            srcIp = ipPkt.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipPkt.getHeader().getDstAddr().getHostAddress();
        }

        // 1. Extreme abnormal oversized packet (> 65,000 bytes - Ping of Death / IP fragmentation evasion)
        if (packet.length() > abnormalPacketSize) {
            String s = srcIp != null ? srcIp : "Unknown";
            String d = dstIp != null ? dstIp : "Unknown";
            if (!isLocalOrIgnored(s) && shouldAlert(s, "LARGE_PACKET", now)) {
                detectedAlerts.add(createAlert("LARGE_PACKET", "MEDIUM", s, d,
                        "Oversized anomalous packet detected (" + packet.length() + " bytes) - potential fragmentation evasion",
                        1, Collections.emptyMap()));
            }
        }

        // If source IP is our local machine, it is outbound traffic (user browsing/streaming) - skip incoming attack rules!
        if (isLocalOrIgnored(srcIp)) {
            return detectedAlerts;
        }

        // 2. TCP Attack Inspection
        if (packet.contains(TcpPacket.class) && srcIp != null && dstIp != null) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            TcpPacket.TcpHeader th = tcp.getHeader();
            int srcPort = th.getSrcPort().valueAsInt();
            int dstPort = th.getDstPort().valueAsInt();

            boolean syn = th.getSyn();
            boolean ack = th.getAck();
            boolean fin = th.getFin();
            boolean rst = th.getRst();
            boolean psh = th.getPsh();
            boolean urg = th.getUrg();

            // LAND Attack: Remote spoofed packet where Source IP == Dest IP and Source Port == Dest Port
            if (srcIp.equals(dstIp) && srcPort == dstPort) {
                if (shouldAlert(srcIp, "LAND_ATTACK", now)) {
                    detectedAlerts.add(createAlert("LAND_ATTACK", "CRITICAL", srcIp, dstIp,
                            "LAND attack detected: Identical source and destination (" + srcIp + ":" + srcPort + ")", 1,
                            Map.of("port", srcPort)));
                }
            }

            // TCP Stealth Scans (Classic Nmap attacks)
            // A. Xmas Tree Scan: FIN, PSH, URG all set (RFC 793 violation)
            if (fin && psh && urg && !ack) {
                if (shouldAlert(srcIp, "TCP_XMAS_SCAN", now)) {
                    detectedAlerts.add(createAlert("TCP_XMAS_SCAN", "HIGH", srcIp, dstIp,
                            "TCP Xmas stealth scan detected (FIN+PSH+URG set) targeting port " + dstPort, 1,
                            Map.of("target_port", dstPort)));
                }
            }
            // B. NULL Scan: No flags set
            else if (!syn && !ack && !fin && !rst && !psh && !urg) {
                if (shouldAlert(srcIp, "TCP_NULL_SCAN", now)) {
                    detectedAlerts.add(createAlert("TCP_NULL_SCAN", "HIGH", srcIp, dstIp,
                            "TCP NULL stealth scan detected (Zero flags set) targeting port " + dstPort, 1,
                            Map.of("target_port", dstPort)));
                }
            }

            // Port Scan Detection (Only inbound SYN probes to diverse ports on our system)
            if (syn && !ack) {
                Deque<PortAttempt> attempts = portScanTracker.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
                synchronized (attempts) {
                    attempts.addLast(new PortAttempt(dstPort, now));
                    while (!attempts.isEmpty() && now - attempts.peekFirst().time > portScanWindowMs) {
                        attempts.pollFirst();
                    }
                    Set<Integer> uniquePorts = new HashSet<>();
                    for (PortAttempt pa : attempts) uniquePorts.add(pa.port);

                    if (uniquePorts.size() >= portScanThreshold && shouldAlert(srcIp, "PORT_SCAN", now)) {
                        detectedAlerts.add(createAlert("PORT_SCAN", "HIGH", srcIp, dstIp,
                                "Port scan detected from " + srcIp + " (" + uniquePorts.size() + " ports probed in " + (portScanWindowMs / 1000) + "s)",
                                attempts.size(), Map.of("scanned_ports_count", uniquePorts.size())));
                    }
                }
            }

            // SYN Flood Detection (DDoS)
            if (syn && !ack) {
                Deque<Long> syns = synTracker.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
                synchronized (syns) {
                    syns.addLast(now);
                    while (!syns.isEmpty() && now - syns.peekFirst() > synFloodWindowMs) {
                        syns.pollFirst();
                    }
                    if (syns.size() >= synFloodThreshold && shouldAlert(srcIp, "SYN_FLOOD", now)) {
                        detectedAlerts.add(createAlert("SYN_FLOOD", "CRITICAL", srcIp, dstIp,
                                "TCP SYN Flood (DDoS): " + syns.size() + " SYN packets within 5s from " + srcIp,
                                syns.size(), Map.of("syn_rate_per_sec", syns.size() / 5)));
                    }
                }
            }

            // HTTP Flood (High-rate incoming requests to web ports)
            if (dstPort == 80 || dstPort == 8080 || dstPort == 443) {
                Deque<Long> httpReqs = httpTracker.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
                synchronized (httpReqs) {
                    httpReqs.addLast(now);
                    while (!httpReqs.isEmpty() && now - httpReqs.peekFirst() > httpFloodWindowMs) {
                        httpReqs.pollFirst();
                    }
                    if (httpReqs.size() >= httpFloodThreshold && shouldAlert(srcIp, "HTTP_FLOOD", now)) {
                        detectedAlerts.add(createAlert("HTTP_FLOOD", "HIGH", srcIp, dstIp,
                                "HTTP Flood / High-rate web requests (" + httpReqs.size() + " in 5s) targeting port " + dstPort,
                                httpReqs.size(), Map.of("target_port", dstPort)));
                    }
                }
            }
        }

        // 3. UDP Attack Inspection (UDP Flood & High-Volume DNS Tunneling)
        if (packet.contains(UdpPacket.class) && srcIp != null && dstIp != null) {
            UdpPacket udp = packet.get(UdpPacket.class);
            int dstPort = udp.getHeader().getDstPort().valueAsInt();
            int srcPort = udp.getHeader().getSrcPort().valueAsInt();

            // DNS Tunneling: Requires BOTH oversized payload (>1200 bytes) AND high continuous query bursts
            if ((dstPort == 53 || srcPort == 53) && packet.length() > dnsTunnelPayloadSize) {
                Deque<Long> dnsQueries = dnsTunnelTracker.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
                synchronized (dnsQueries) {
                    dnsQueries.addLast(now);
                    while (!dnsQueries.isEmpty() && now - dnsQueries.peekFirst() > 10000L) {
                        dnsQueries.pollFirst();
                    }
                    if (dnsQueries.size() >= dnsTunnelCountThreshold && shouldAlert(srcIp, "DNS_TUNNELING", now)) {
                        detectedAlerts.add(createAlert("DNS_TUNNELING", "HIGH", srcIp, dstIp,
                                "DNS Tunneling exfiltration detected: " + dnsQueries.size() + " large DNS payloads (>1200 bytes) in 10s from " + srcIp,
                                dnsQueries.size(), Map.of("large_query_count", dnsQueries.size())));
                    }
                }
            }

            // UDP Flood: Exceeding 1,000 UDP packets in 5 seconds
            Deque<Long> udps = udpTracker.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
            synchronized (udps) {
                udps.addLast(now);
                while (!udps.isEmpty() && now - udps.peekFirst() > udpFloodWindowMs) {
                    udps.pollFirst();
                }
                if (udps.size() >= udpFloodThreshold && shouldAlert(srcIp, "UDP_FLOOD", now)) {
                    detectedAlerts.add(createAlert("UDP_FLOOD", "HIGH", srcIp, dstIp,
                            "UDP Flood detected: " + udps.size() + " packets in 5s from " + srcIp,
                            udps.size(), Map.of("packet_count", udps.size())));
                }
            }
        }

        // 4. ICMP Ping Flood Inspection
        if (packet.contains(IcmpV4CommonPacket.class) && srcIp != null && dstIp != null) {
            Deque<Long> icmps = icmpTracker.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
            synchronized (icmps) {
                icmps.addLast(now);
                while (!icmps.isEmpty() && now - icmps.peekFirst() > icmpFloodWindowMs) {
                    icmps.pollFirst();
                }
                if (icmps.size() >= icmpFloodThreshold && shouldAlert(srcIp, "ICMP_FLOOD", now)) {
                    detectedAlerts.add(createAlert("ICMP_FLOOD", "HIGH", srcIp, dstIp,
                            "ICMP Ping Storm / Flood detected: " + icmps.size() + " requests in 5s from " + srcIp,
                            icmps.size(), Map.of("rate_per_sec", icmps.size() / 5)));
                }
            }
        }

        // 5. ARP Spoofing / Poisoning Inspection
        if (packet.contains(ArpPacket.class)) {
            ArpPacket arp = packet.get(ArpPacket.class);
            String arpSrcIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
            String arpSrcMac = arp.getHeader().getSrcHardwareAddr().toString();

            if (!arpSrcMac.equalsIgnoreCase("ff:ff:ff:ff:ff:ff") && !arpSrcMac.equalsIgnoreCase("00:00:00:00:00:00")) {
                String existingMac = arpTable.putIfAbsent(arpSrcIp, arpSrcMac);
                if (existingMac != null && !existingMac.equalsIgnoreCase(arpSrcMac)) {
                    if (shouldAlert(arpSrcIp, "ARP_SPOOF", now)) {
                        detectedAlerts.add(createAlert("ARP_SPOOF", "CRITICAL", arpSrcIp, "Broadcast",
                                "ARP Cache Poisoning detected: IP " + arpSrcIp + " changed MAC from " + existingMac + " to " + arpSrcMac,
                                1, Map.of("old_mac", existingMac, "new_mac", arpSrcMac)));
                    }
                    arpTable.put(arpSrcIp, arpSrcMac);
                }
            }
        }

        return detectedAlerts;
    }

    private boolean shouldAlert(String ip, String alertType, long now) {
        String key = ip + ":" + alertType;
        Long lastTime = alertCooldowns.get(key);
        if (lastTime == null || now - lastTime > ALERT_COOLDOWN_MS) {
            alertCooldowns.put(key, now);
            return true;
        }
        return false;
    }

    public static Map<String, Object> createAlert(String type, String severity, String srcIp, String dstIp,
                                                  String description, int count, Map<String, Object> details) {
        Map<String, Object> alert = new HashMap<>();
        alert.put("id", UUID.randomUUID().toString());
        alert.put("timestamp", Instant.now().toString());
        alert.put("alert_type", type);
        alert.put("severity", severity);
        alert.put("source_ip", srcIp);
        alert.put("dest_ip", dstIp);
        alert.put("description", description);
        alert.put("packet_count", count);
        alert.put("details", details != null ? details : Collections.emptyMap());
        return alert;
    }
}
