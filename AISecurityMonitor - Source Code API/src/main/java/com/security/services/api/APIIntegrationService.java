package com.security.services.api;

import com.security.config.APIConfig;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

public class APIIntegrationService {
    private final VirusTotalAPI virusTotalAPI;
    private final AbuseIPDBAPI abuseIPDBAPI;
    private final ExecutorService executorService;
    private final Map<String, Map<String, Object>> cache;
    private static final int CACHE_TIMEOUT_MINUTES = 30;
    
    public APIIntegrationService() {
        this.virusTotalAPI = new VirusTotalAPI();
        this.abuseIPDBAPI = new AbuseIPDBAPI();
        APIConfig config = APIConfig.getInstance();
        this.executorService = Executors.newFixedThreadPool(config.getScanThreads());
        this.cache = new ConcurrentHashMap<>();
        
        // Schedule cache cleanup
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(this::cleanCache, 1, 1, TimeUnit.HOURS);
    }
    
    public Map<String, Object> getThreatIntelligence(String ip) {
        // Check cache first
        String cacheKey = "threat_" + ip;
        if (cache.containsKey(cacheKey)) {
            Map<String, Object> cached = cache.get(cacheKey);
            if (!isCacheExpired(cached)) {
                cached.put("cached", true);
                return cached;
            }
        }
        
        // Get results from APIs in parallel
        Map<String, Object> result = new HashMap<>();
        result.put("ip_address", ip);
        result.put("timestamp", System.currentTimeMillis());
        
        try {
            Future<Map<String, Object>> vtFuture = executorService.submit(() -> 
                virusTotalAPI.analyzeIP(ip));
            Future<Map<String, Object>> abuseFuture = executorService.submit(() -> 
                abuseIPDBAPI.checkIP(ip));
            
            Map<String, Object> vtResult = vtFuture.get(10, TimeUnit.SECONDS);
            Map<String, Object> abuseResult = abuseFuture.get(10, TimeUnit.SECONDS);
            
            result.put("virustotal", vtResult);
            result.put("abuseipdb", abuseResult);
            
            // Calculate combined threat score
            double threatScore = calculateThreatScore(vtResult, abuseResult);
            result.put("combined_threat_score", threatScore);
            result.put("overall_verdict", getVerdict(threatScore));
            result.put("cached", false);
            
            // Cache the result
            result.put("cache_time", System.currentTimeMillis());
            cache.put(cacheKey, result);
            
        } catch (Exception e) {
            System.err.println("Error getting threat intelligence for " + ip + ": " + e.getMessage());
            result.put("error", e.getMessage());
            result.put("combined_threat_score", 0.0);
            result.put("overall_verdict", "ERROR");
        }
        
        return result;
    }
    
    private double calculateThreatScore(Map<String, Object> vtResult, Map<String, Object> abuseResult) {
        double score = 0.0;
        
        // VirusTotal weighting
        int malicious = (int) vtResult.getOrDefault("malicious", 0);
        int suspicious = (int) vtResult.getOrDefault("suspicious", 0);
        int totalEngines = malicious + suspicious + 
                          (int) vtResult.getOrDefault("harmless", 0) +
                          (int) vtResult.getOrDefault("undetected", 0);
        
        if (totalEngines > 0) {
            score += ((malicious * 1.0 + suspicious * 0.5) / totalEngines) * 50;
        }
        
        // AbuseIPDB weighting
        int confidenceScore = (int) abuseResult.getOrDefault("abuse_confidence_score", 0);
        score += confidenceScore * 0.5;
        
        return Math.min(score, 100.0);
    }
    
    private String getVerdict(double score) {
        if (score >= 75) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 25) return "MEDIUM";
        if (score >= 10) return "LOW";
        return "CLEAN";
    }
    
    private boolean isCacheExpired(Map<String, Object> cachedData) {
        Long cacheTime = (Long) cachedData.get("cache_time");
        if (cacheTime == null) return true;
        long ageMinutes = (System.currentTimeMillis() - cacheTime) / (1000 * 60);
        return ageMinutes > CACHE_TIMEOUT_MINUTES;
    }
    
    private void cleanCache() {
        long now = System.currentTimeMillis();
        cache.entrySet().removeIf(entry -> {
            Map<String, Object> data = entry.getValue();
            Long cacheTime = (Long) data.get("cache_time");
            return cacheTime != null && 
                   (now - cacheTime) > CACHE_TIMEOUT_MINUTES * 60 * 1000;
        });
    }
    
    public void close() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
