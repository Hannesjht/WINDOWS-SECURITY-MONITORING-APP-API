package com.security.models;

import java.util.Date;
import java.util.ArrayList;
import java.util.List;

public class DeviceInfo {
    private String ip;
    private String hostname;
    private String macAddress;
    private String os;
    private String deviceType;
    private String status;
    private Date lastSeen;
    private List<Integer> openPorts;
    private List<String> services;
    
    public DeviceInfo() {
        this.openPorts = new ArrayList<>();
        this.services = new ArrayList<>();
        this.lastSeen = new Date();
        this.status = "UNKNOWN";
    }
    
    // Getters and setters
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    
    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }
    
    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }
    
    public String getDeviceType() { return deviceType; }
    public void setDeviceType(String deviceType) { this.deviceType = deviceType; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public Date getLastSeen() { return lastSeen; }
    public void setLastSeen(Date lastSeen) { this.lastSeen = lastSeen; }
    
    public List<Integer> getOpenPorts() { return openPorts; }
    public void setOpenPorts(List<Integer> openPorts) { this.openPorts = openPorts; }
    
    public List<String> getServices() { return services; }
    public void setServices(List<String> services) { this.services = services; }
    
    public void addOpenPort(int port) { openPorts.add(port); }
    public void addService(String service) { services.add(service); }
}
