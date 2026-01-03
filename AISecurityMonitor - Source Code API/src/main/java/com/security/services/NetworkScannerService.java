package com.security.services;

import com.security.models.ConnectionData;
import com.security.models.DeviceInfo;
import java.net.*;
import java.util.*;

public class NetworkScannerService {
    
    public List<ConnectionData> scanConnections() {
        List<ConnectionData> connections = new ArrayList<>();
        
        try {
            // For Windows, use netstat
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                connections.addAll(scanWindowsConnections());
            } else {
                connections.addAll(scanUnixConnections());
            }
            
            // Add some simulated connections for demo
            if (connections.isEmpty()) {
                connections.addAll(generateDemoConnections());
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return connections;
    }
    
    public Map<String, DeviceInfo> scanNetworkDevices() {
        Map<String, DeviceInfo> devices = new HashMap<>();
        
        try {
            // Get local IP
            String localIP = getLocalIP();
            
            // Add local device
            DeviceInfo localDevice = new DeviceInfo();
            localDevice.setIp(localIP);
            localDevice.setHostname(InetAddress.getLocalHost().getHostName());
            localDevice.setDeviceType("Computer");
            localDevice.setStatus("Online");
            devices.put(localIP, localDevice);
            
            // Scan local network (simplified - in reality, you'd scan a range)
            for (int i = 1; i <= 10; i++) {
                String ip = getNetworkPrefix(localIP) + i;
                if (!ip.equals(localIP)) {
                    DeviceInfo device = scanDevice(ip);
                    if (device != null) {
                        devices.put(ip, device);
                    }
                }
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return devices;
    }
    
    private DeviceInfo scanDevice(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            if (address.isReachable(1000)) {
                DeviceInfo device = new DeviceInfo();
                device.setIp(ip);
                device.setHostname(address.getHostName());
                device.setStatus("Online");
                device.setDeviceType(detectDeviceType(ip));
                return device;
            }
        } catch (Exception e) {
            // Device not reachable
        }
        return null;
    }
    
    private List<ConnectionData> scanWindowsConnections() throws Exception {
        List<ConnectionData> connections = new ArrayList<>();
        ProcessBuilder pb = new ProcessBuilder("netstat", "-ano");
        Process process = pb.start();
        
        try (Scanner scanner = new Scanner(process.getInputStream())) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains("TCP")) {
                    ConnectionData conn = parseNetstatLine(line);
                    if (conn != null) {
                        connections.add(conn);
                    }
                }
            }
        }
        
        return connections;
    }
    
    private ConnectionData parseNetstatLine(String line) {
        try {
            String[] parts = line.trim().split("\\s+");
            if (parts.length >= 5) {
                String protocol = parts[0];
                String local = parts[1];
                String remote = parts[2];
                String state = parts[3];
                
                String[] localParts = local.split(":");
                String[] remoteParts = remote.split(":");
                
                if (localParts.length >= 2 && remoteParts.length >= 2) {
                    return new ConnectionData(
                        protocol,
                        localParts[0],
                        remoteParts[0],
                        Integer.parseInt(localParts[1]),
                        Integer.parseInt(remoteParts[1]),
                        state
                    );
                }
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        return null;
    }
    
    private List<ConnectionData> scanUnixConnections() {
        // Similar implementation for Unix systems
        return new ArrayList<>();
    }
    
    private List<ConnectionData> generateDemoConnections() {
        List<ConnectionData> connections = new ArrayList<>();
        Random random = new Random();
        
        String[] demoIPs = {
            "192.168.1." + (random.nextInt(50) + 100),
            "10.0.0." + (random.nextInt(50) + 100),
            "172.16.0." + (random.nextInt(50) + 100)
        };
        
        for (String ip : demoIPs) {
            connections.add(new ConnectionData(
                "TCP",
                "127.0.0.1",
                ip,
                random.nextInt(50000) + 1000,
                random.nextInt(100) + 80,
                "ESTABLISHED"
            ));
        }
        
        return connections;
    }
    
    private String getLocalIP() throws SocketException {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();
            if (ni.isUp() && !ni.isLoopback()) {
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address) {
                        return addr.getHostAddress();
                    }
                }
            }
        }
        return "127.0.0.1";
    }
    
    private String getNetworkPrefix(String ip) {
        String[] parts = ip.split("\\.");
        return parts[0] + "." + parts[1] + "." + parts[2] + ".";
    }
    
    private String detectDeviceType(String ip) {
        // Simple detection - in reality, use more sophisticated methods
        if (ip.endsWith(".1")) return "Router";
        if (ip.endsWith(".100")) return "Server";
        return "Computer";
    }
}
