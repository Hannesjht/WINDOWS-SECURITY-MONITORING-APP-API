// src/main/java/com/security/config/APIConfig.java
package com.security.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class APIConfig {
    private static APIConfig instance;
    private Properties properties;
    
    private APIConfig() {
        properties = new Properties();
        loadConfig();
    }
    
    public static synchronized APIConfig getInstance() {
        if (instance == null) {
            instance = new APIConfig();
        }
        return instance;
    }
    
    private void loadConfig() {
        try (FileInputStream fis = new FileInputStream("config.properties")) {
            properties.load(fis);
        } catch (IOException e) {
            // Load defaults if config file not found
            setDefaults();
        }
    }
    
    private void setDefaults() {
        properties.setProperty("virustotal.api.key", "YOUR_VIRUSTOTAL_API_KEY");
        properties.setProperty("abuseipdb.api.key", "YOUR_ABUSEIPDB_API_KEY");
        properties.setProperty("scan.threads", "100");
        properties.setProperty("scan.timeout", "1000");
    }
    
    public String getVirusTotalAPIKey() {
        String key = properties.getProperty("virustotal.api.key");
        // Check environment variable as fallback
        if (key == null || key.equals("YOUR_VIRUSTOTAL_API_KEY")) {
            return System.getenv("VIRUSTOTAL_API_KEY");
        }
        return key;
    }
    
    public String getAbuseIPDBAPIKey() {
        String key = properties.getProperty("abuseipdb.api.key");
        if (key == null || key.equals("YOUR_ABUSEIPDB_API_KEY")) {
            return System.getenv("ABUSEIPDB_API_KEY");
        }
        return key;
    }
    
    public int getScanThreads() {
        return Integer.parseInt(properties.getProperty("scan.threads", "100"));
    }
    
    public int getScanTimeout() {
        return Integer.parseInt(properties.getProperty("scan.timeout", "1000"));
    }
}
