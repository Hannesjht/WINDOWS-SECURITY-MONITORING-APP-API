// src/main/java/com/security/utils/HTTPClient.java
package com.security.utils;

import java.io.*;
import java.net.*;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class HTTPClient {
    private int timeout;
    private static final String USER_AGENT = "AISecurityMonitor/1.0";
    
    public HTTPClient(int timeout) {
        this.timeout = timeout;
    }
    
    public String get(String url, Map<String, String> headers) throws IOException {
        HttpURLConnection connection = null;
        try {
            URL apiUrl = new URL(url);
            connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            connection.setRequestProperty("User-Agent", USER_AGENT);
            
            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    connection.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
            
            int responseCode = connection.getResponseCode();
            
            // Check for rate limiting (HTTP 429 or 503)
            if (responseCode == 429 || responseCode == HttpURLConnection.HTTP_UNAVAILABLE) {
                handleRateLimit(connection);
                throw new IOException("Rate limit exceeded for: " + url);
            }
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return readResponse(connection);
            } else {
                throw new IOException("HTTP Error " + responseCode + " for: " + url);
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
    
    private String readResponse(HttpURLConnection connection) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }
    
    private void handleRateLimit(HttpURLConnection connection) {
        String retryAfter = connection.getHeaderField("Retry-After");
        if (retryAfter != null) {
            try {
                int seconds = Integer.parseInt(retryAfter);
                System.out.println("Rate limited. Waiting " + seconds + " seconds...");
                TimeUnit.SECONDS.sleep(seconds);
            } catch (Exception e) {
                // Ignore
            }
        }
    }
    
    // Add a close method for cleanup
    public void close() {
        // Nothing to close for HttpURLConnection
    }
}
