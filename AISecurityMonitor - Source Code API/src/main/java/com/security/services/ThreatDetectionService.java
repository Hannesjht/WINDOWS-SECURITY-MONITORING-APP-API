package com.security.services;

import com.security.models.ConnectionData;
import java.util.*;

public class ThreatDetectionService {
    
    private Set<Integer> suspiciousPorts;
    private Map<String, Integer> ipReputation;
    
    public ThreatDetectionService() {
        initializeSuspiciousPorts();
        ipReputation = new HashMap<>();
    }
    
    private void initializeSuspiciousPorts() {
        suspiciousPorts = new HashSet<>(Arrays.asList(
            4444,  // Metasploit
            6667,  // IRC
            31337, // Back Orifice
            12345, // NetBus
            54321, // Back Orifice 2000
            22,    // SSH (often attacked)
            3389,  // RDP (often attacked)
            445,   // SMB (exploited by WannaCry)
            135,   // MSRPC
            1433,  // SQL Server
            3306,  // MySQL
            5900   // VNC
        ));
    }
    
    public double analyze(ConnectionData connection) {
        double score = 0.0;
        Random rand = new Random();
        
        // 1. Check for suspicious ports
        if (suspiciousPorts.contains(connection.getRemotePort())) {
            score += 30;
        }
        
        // 2. Check for private IPs (usually safe)
        if (isPrivateIP(connection.getRemoteIP())) {
            score -= 15; // Internal connections are safer
        } else {
            score += 25; // External connections are more suspicious
        }
        
        // 3. Check port ranges
        if (connection.getRemotePort() < 1024) {
            score += 10; // Well-known ports
        }
        
        if (connection.getRemotePort() > 49152) {
            score += 5; // Ephemeral ports
        }
        
        // 4. Check for common attack ports
        if (connection.getRemotePort() == 445 || connection.getRemotePort() == 3389) {
            score += 20; // Common attack vectors
        }
        
        // 5. Check IP reputation
        Integer rep = ipReputation.get(connection.getRemoteIP());
        if (rep != null) {
            score += rep;
        }
        
        // 6. Add some randomness (less than before)
        score += rand.nextDouble() * 10;
        
        // 7. State-based scoring
        if ("ESTABLISHED".equals(connection.getState())) {
            score += 5;
        } else if ("LISTENING".equals(connection.getState())) {
            score -= 5;
        }
        
        return Math.min(100, Math.max(0, score));
    }
    
    private boolean isPrivateIP(String ip) {
        return ip.startsWith("192.168.") || 
               ip.startsWith("10.") || 
               ip.startsWith("172.16.") ||
               ip.startsWith("172.17.") ||
               ip.startsWith("172.18.") ||
               ip.startsWith("172.19.") ||
               ip.startsWith("172.20.") ||
               ip.startsWith("172.21.") ||
               ip.startsWith("172.22.") ||
               ip.startsWith("172.23.") ||
               ip.startsWith("172.24.") ||
               ip.startsWith("172.25.") ||
               ip.startsWith("172.26.") ||
               ip.startsWith("172.27.") ||
               ip.startsWith("172.28.") ||
               ip.startsWith("172.29.") ||
               ip.startsWith("172.30.") ||
               ip.startsWith("172.31.") ||
               ip.equals("127.0.0.1") ||
               ip.equals("0.0.0.0");
    }
    
    public void flagIP(String ip, int severity) {
        ipReputation.put(ip, severity);
    }
}
