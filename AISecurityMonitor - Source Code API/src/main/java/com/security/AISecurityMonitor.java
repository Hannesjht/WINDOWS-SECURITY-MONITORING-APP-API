package com.security;

import com.security.models.*;
import com.security.services.*;
import com.security.services.ml.*;
import com.security.services.api.*;
import com.security.services.scanner.*;
import com.security.services.database.*;
import java.util.*;
import java.util.concurrent.*;

public class AISecurityMonitor {
    private static AISecurityMonitor instance;
    
    // Services
    private NetworkScannerService networkScanner;
    private ThreatDetectionService threatDetector;
    private FirewallService firewallService;
    private MLThreatDetectionService mlDetector;
    private APIIntegrationService apiService;
    private AdvancedPortScanner portScanner;
    private DatabaseService databaseService;
    
    // State
    private volatile boolean isMonitoring = false;
    private ScheduledExecutorService scheduler;
    private Set<String> blockedIPs;
    private List<ConnectionData> recentConnections;
    private Map<String, DeviceInfo> networkDevices;
    private Map<String, Map<String, Object>> threatIntelligenceCache;
    
    private AISecurityMonitor() {
        this.networkScanner = new NetworkScannerService();
        this.threatDetector = new ThreatDetectionService();
        this.firewallService = new FirewallService();
        this.mlDetector = new MLThreatDetectionService();
        this.apiService = new APIIntegrationService();
        this.portScanner = new AdvancedPortScanner();
        this.databaseService = new DatabaseService();
        
        this.blockedIPs = ConcurrentHashMap.newKeySet();
        this.recentConnections = new CopyOnWriteArrayList<>();
        this.networkDevices = new ConcurrentHashMap<>();
        this.threatIntelligenceCache = new ConcurrentHashMap<>();
        this.scheduler = Executors.newScheduledThreadPool(2); // Increased pool size
    }
    
    public static synchronized AISecurityMonitor getInstance() {
        if (instance == null) {
            instance = new AISecurityMonitor();
        }
        return instance;
    }
    
    public void startMonitoring() {
        if (!isMonitoring) {
            isMonitoring = true;
            System.out.println("AI Security Monitor started...");
            
            // Recreate scheduler if it was shutdown
            if (scheduler.isShutdown()) {
                scheduler = Executors.newScheduledThreadPool(2);
            }
            
            // Start monitoring with scheduled executor
            scheduler.scheduleAtFixedRate(() -> {
                if (isMonitoring) {
                    monitorNetwork();
                }
            }, 0, 5, TimeUnit.SECONDS);
        }
    }
    
    public void stopMonitoring() {
        isMonitoring = false;
        System.out.println("AI Security Monitor stopped...");
        // Don't shutdown scheduler here, just stop scheduling new tasks
    }
    
    public void shutdown() {
        isMonitoring = false;
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        databaseService.close();
        apiService.close();
    }
    
    private void monitorNetwork() {
        try {
            System.out.println("Scanning network...");
            
            // 1. Scan for network devices
            Map<String, DeviceInfo> devices = networkScanner.scanNetworkDevices();
            networkDevices.clear();
            networkDevices.putAll(devices);
            
            System.out.println("Found " + devices.size() + " devices");
            
            // 2. Get current connections
            List<ConnectionData> connections = networkScanner.scanConnections();
            
            System.out.println("Found " + connections.size() + " connections");
            
            // 3. Analyze connections with ML and API
            int suspiciousCount = 0;
            int maliciousCount = 0;
            
            for (ConnectionData conn : connections) {
                analyzeConnection(conn);
                
                if ("SUSPICIOUS".equals(conn.getStatus())) {
                    suspiciousCount++;
                } else if ("MALICIOUS".equals(conn.getStatus())) {
                    maliciousCount++;
                }
            }
            
            if (suspiciousCount > 0 || maliciousCount > 0) {
                System.out.println("Detected " + suspiciousCount + " suspicious and " + 
                                 maliciousCount + " malicious connections");
            }
            
        } catch (Exception e) {
            System.err.println("Error in monitorNetwork: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void analyzeConnection(ConnectionData connection) {
        try {
            // Skip loopback and local connections for demo
            if (connection.getRemoteIP().equals("0.0.0.0") || 
                connection.getRemoteIP().equals("127.0.0.1") ||
                connection.getRemoteIP().startsWith("192.168.") ||
                connection.getRemoteIP().startsWith("10.") ||
                connection.getRemoteIP().startsWith("172.")) {
                // These are internal IPs, give them lower scores
                connection.setThreatScore(10.0 + new Random().nextDouble() * 20);
                connection.setStatus("NORMAL");
                return;
            }
            
            // Basic analysis
            double basicScore = threatDetector.analyze(connection);
            
            // ML analysis
            Map<String, Object> features = extractFeatures(connection);
            double mlScore = mlDetector.analyzeWithML(connection, features);
            
            // Calculate final score
            double finalScore = (basicScore * 0.6) + (mlScore * 0.4);
            
            // For demo purposes, make some external IPs appear malicious
            if (shouldSimulateThreat(connection.getRemoteIP())) {
                finalScore = 70.0 + new Random().nextDouble() * 30;
            }
            
            connection.setThreatScore(finalScore);
            
            // Determine status
            if (finalScore > 80) {
                connection.setStatus("MALICIOUS");
                handleThreat(connection);
            } else if (finalScore > 60) {
                connection.setStatus("SUSPICIOUS");
            } else {
                connection.setStatus("NORMAL");
            }
            
            // Log to database
            databaseService.logConnection(connection);
            
            // Store connection
            recentConnections.add(connection);
            if (recentConnections.size() > 100) {
                recentConnections.remove(0);
            }
            
            // Print for debugging (only external IPs with higher scores)
            if (!connection.getRemoteIP().startsWith("192.168.") && 
                !connection.getRemoteIP().equals("127.0.0.1") &&
                !connection.getRemoteIP().equals("0.0.0.0")) {
                System.out.println("Connection: " + connection.getRemoteIP() + 
                                 ":" + connection.getRemotePort() +
                                 " Score: " + String.format("%.1f", finalScore) + 
                                 " Status: " + connection.getStatus());
            }
            
        } catch (Exception e) {
            System.err.println("Error analyzing connection: " + e.getMessage());
        }
    }
    
    private boolean shouldSimulateThreat(String ip) {
        // For demo: make some IPs appear as threats
        String[] demoThreatIPs = {
            "47.246.7.204", "3.173.21.63", "72.145.26.121"
        };
        
        for (String threatIP : demoThreatIPs) {
            if (ip.equals(threatIP)) {
                return new Random().nextInt(10) < 3; // 30% chance
            }
        }
        return false;
    }
    
    private Map<String, Object> extractFeatures(ConnectionData connection) {
        Map<String, Object> features = new HashMap<>();
        
        // Simulate some features
        Random rand = new Random();
        features.put("src_bytes", rand.nextInt(10000));
        features.put("dst_bytes", rand.nextInt(10000));
        features.put("duration", rand.nextInt(100));
        
        // Calculate connection patterns
        long similarConnections = recentConnections.stream()
            .filter(c -> c.getRemoteIP().equals(connection.getRemoteIP()))
            .count();
        
        features.put("count", (double) similarConnections);
        features.put("srv_count", 1.0);
        features.put("same_srv_rate", similarConnections > 0 ? 1.0 : 0.0);
        
        return features;
    }
    
    private void handleThreat(ConnectionData threat) {
        System.out.println("🚨 THREAT DETECTED: " + threat);
        
        // Log threat to database
        databaseService.logThreat(
            "Suspicious Connection",
            threat.getRemoteIP(),
            threat.getLocalIP(),
            "High threat score connection detected: " + threat.getThreatScore() + 
            " on port " + threat.getRemotePort(),
            (int) threat.getThreatScore(),
            "Analyzed"
        );
        
        // Auto-block if score > 90
        if (threat.getThreatScore() > 90) {
            boolean blocked = firewallService.blockIP(threat.getRemoteIP());
            if (blocked) {
                blockedIPs.add(threat.getRemoteIP());
                System.out.println("✅ Blocked IP: " + threat.getRemoteIP());
                
                // Log firewall action
                databaseService.logFirewallAction(
                    threat.getRemoteIP(),
                    "BLOCK",
                    "High threat score: " + threat.getThreatScore(),
                    true
                );
            }
        }
    }
    
    // Getters
    public boolean isMonitoring() { return isMonitoring; }
    public Map<String, DeviceInfo> getNetworkDevices() { return networkDevices; }
    public List<ConnectionData> getRecentConnections() { return recentConnections; }
    public Set<String> getBlockedIPs() { return blockedIPs; }
    
    // NEW: Methods for advanced features
    public Map<String, List<AdvancedPortScanner.PortScanResult>> performPortScan(String network, int start, int end) {
        return portScanner.scanNetworkRange(network, start, end);
    }
    
    public List<Map<String, Object>> getThreatReports() {
        return databaseService.getRecentThreats(50);
    }
    
    public Map<String, Integer> getStatistics() {
        return databaseService.getThreatStatistics();
    }
    
    public Map<String, Object> checkIPReputation(String ip) {
        return apiService.getThreatIntelligence(ip);
    }
}