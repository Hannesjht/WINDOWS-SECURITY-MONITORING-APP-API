package com.security.models;

import java.util.Date;

public class ConnectionData {
    private String protocol;
    private String localIP;
    private String remoteIP;
    private int localPort;
    private int remotePort;
    private String state;
    private Date timestamp;
    private double threatScore;
    private String status;
    
    // Constructor, getters, and setters
    public ConnectionData(String protocol, String localIP, String remoteIP, 
                         int localPort, int remotePort, String state) {
        this.protocol = protocol;
        this.localIP = localIP;
        this.remoteIP = remoteIP;
        this.localPort = localPort;
        this.remotePort = remotePort;
        this.state = state;
        this.timestamp = new Date();
        this.threatScore = 0.0;
        this.status = "NORMAL";
    }
    
    // Getters and setters for all fields
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    
    public String getLocalIP() { return localIP; }
    public void setLocalIP(String localIP) { this.localIP = localIP; }
    
    public String getRemoteIP() { return remoteIP; }
    public void setRemoteIP(String remoteIP) { this.remoteIP = remoteIP; }
    
    public int getLocalPort() { return localPort; }
    public void setLocalPort(int localPort) { this.localPort = localPort; }
    
    public int getRemotePort() { return remotePort; }
    public void setRemotePort(int remotePort) { this.remotePort = remotePort; }
    
    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    
    public Date getTimestamp() { return timestamp; }
    public void setTimestamp(Date timestamp) { this.timestamp = timestamp; }
    
    public double getThreatScore() { return threatScore; }
    public void setThreatScore(double threatScore) { this.threatScore = threatScore; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    @Override
    public String toString() {
        return String.format("%s %s:%d -> %s:%d [%s] Score: %.1f%%", 
            protocol, localIP, localPort, remoteIP, remotePort, state, threatScore);
    }
}
