// src/main/java/com/security/services/api/VirusTotalAPI.java
package com.security.services.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.config.APIConfig;
import com.security.utils.HTTPClient;

import java.util.HashMap;
import java.util.Map;

public class VirusTotalAPI {
    private final String apiKey;
    private final HTTPClient httpClient;
    private final ObjectMapper objectMapper;
    private final String baseUrl = "https://www.virustotal.com/api/v3/";
    
    public VirusTotalAPI() {
        APIConfig config = APIConfig.getInstance();
        this.apiKey = config.getVirusTotalAPIKey();
        this.httpClient = new HTTPClient(config.getScanTimeout());
        this.objectMapper = new ObjectMapper();
    }
    
    public Map<String, Object> analyzeIP(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        if (apiKey == null || apiKey.isEmpty() || apiKey.startsWith("YOUR_")) {
            return getMockData(ipAddress);
        }
        
        try {
            String url = baseUrl + "ip_addresses/" + ipAddress;
            Map<String, String> headers = new HashMap<>();
            headers.put("x-apikey", apiKey);
            headers.put("Accept", "application/json");
            
            String response = httpClient.get(url, headers);
            JsonNode root = objectMapper.readTree(response);
            
            JsonNode data = root.get("data");
            JsonNode attributes = data.get("attributes");
            JsonNode lastAnalysisStats = attributes.get("last_analysis_stats");
            
            result.put("malicious", lastAnalysisStats.get("malicious").asInt());
            result.put("suspicious", lastAnalysisStats.get("suspicious").asInt());
            result.put("harmless", lastAnalysisStats.get("harmless").asInt());
            result.put("undetected", lastAnalysisStats.get("undetected").asInt());
            result.put("country", attributes.get("country").asText());
            result.put("reputation", attributes.get("reputation").asInt());
            result.put("last_analysis_date", attributes.get("last_analysis_date").asText());
            
        } catch (Exception e) {
            System.err.println("VirusTotal API error for IP " + ipAddress + ": " + e.getMessage());
            return getMockData(ipAddress);
        }
        
        return result;
    }
    
    private Map<String, Object> getMockData(String ipAddress) {
        Map<String, Object> mockData = new HashMap<>();
        mockData.put("malicious", 0);
        mockData.put("suspicious", 0);
        mockData.put("harmless", 0);
        mockData.put("undetected", 0);
        mockData.put("country", "Unknown");
        mockData.put("reputation", 0);
        mockData.put("last_analysis_date", "N/A");
        mockData.put("is_mock", true);
        return mockData;
    }
}
