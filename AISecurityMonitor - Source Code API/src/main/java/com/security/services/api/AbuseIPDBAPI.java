// src/main/java/com/security/services/api/AbuseIPDBAPI.java
package com.security.services.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.config.APIConfig;
import com.security.utils.HTTPClient;

import java.util.HashMap;
import java.util.Map;

public class AbuseIPDBAPI {
    private final String apiKey;
    private final HTTPClient httpClient;
    private final ObjectMapper objectMapper;
    private final String baseUrl = "https://api.abuseipdb.com/api/v2/";
    
    public AbuseIPDBAPI() {
        APIConfig config = APIConfig.getInstance();
        this.apiKey = config.getAbuseIPDBAPIKey();
        this.httpClient = new HTTPClient(config.getScanTimeout());
        this.objectMapper = new ObjectMapper();
    }
    
    public Map<String, Object> checkIP(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        if (apiKey == null || apiKey.isEmpty() || apiKey.startsWith("YOUR_")) {
            return getMockData(ipAddress);
        }
        
        try {
            String url = baseUrl + "check";
            url += "?ipAddress=" + ipAddress + "&maxAgeInDays=90";
            
            Map<String, String> headers = new HashMap<>();
            headers.put("Key", apiKey);
            headers.put("Accept", "application/json");
            
            String response = httpClient.get(url, headers);
            JsonNode root = objectMapper.readTree(response);
            JsonNode data = root.get("data");
            
            result.put("abuse_confidence_score", data.get("abuseConfidenceScore").asInt());
            result.put("total_reports", data.get("totalReports").asInt());
            result.put("last_reported", data.get("lastReportedAt").asText());
            result.put("isp", data.get("isp").asText());
            result.put("domain", data.get("domain").asText());
            result.put("country", data.get("countryCode").asText());
            
        } catch (Exception e) {
            System.err.println("VirusTotal API error for IP " + ipAddress + ": " + e.getMessage());
            return getMockData(ipAddress);
        }
        
        return result;
    }
    
    private Map<String, Object> getMockData(String ipAddress) {
        Map<String, Object> mockData = new HashMap<>();
        mockData.put("abuse_confidence_score", 0);
        mockData.put("total_reports", 0);
        mockData.put("last_reported", "N/A");
        mockData.put("isp", "Unknown");
        mockData.put("domain", "unknown.com");
        mockData.put("country", "Unknown");
        mockData.put("is_mock", true);
        return mockData;
    }
}
