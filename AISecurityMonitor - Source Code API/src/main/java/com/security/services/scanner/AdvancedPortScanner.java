package com.security.services.scanner;

import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class AdvancedPortScanner {
    private int THREAD_POOL_SIZE = 100;
    private int TIMEOUT = 5000;  // Changed from final, default 5 seconds
    private static final int[] COMMON_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1723, 3306, 3389, 5900, 8080
    };
    
    public AdvancedPortScanner() {
        // Default constructor with default settings
    }
    
    public AdvancedPortScanner(int timeout, int threadPoolSize) {
        this.TIMEOUT = timeout;
        this.THREAD_POOL_SIZE = threadPoolSize;
    }
    
    // Setters for dynamic configuration
    public void setTimeout(int timeout) {
        if (timeout >= 100 && timeout <= 30000) { // Validate range 100ms to 30s
            this.TIMEOUT = timeout;
        }
    }
    
    public void setThreadPoolSize(int threadPoolSize) {
        if (threadPoolSize > 0 && threadPoolSize <= 500) { // Validate range
            this.THREAD_POOL_SIZE = threadPoolSize;
        }
    }
    
    public int getTimeout() {
        return TIMEOUT;
    }
    
    public int getThreadPoolSize() {
        return THREAD_POOL_SIZE;
    }
    
    public Map<String, List<PortScanResult>> scanNetworkRange(String networkPrefix, int start, int end) {
        Map<String, List<PortScanResult>> results = new ConcurrentHashMap<>();
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<?>> futures = new ArrayList<>();
        
        for (int i = start; i <= end; i++) {
            final String ip = networkPrefix + i;
            futures.add(executor.submit(() -> {
                List<PortScanResult> portResults = scanHost(ip);
                if (!portResults.isEmpty()) {
                    results.put(ip, portResults);
                }
            }));
        }
        
        // Wait for all scans to complete
        for (Future<?> future : futures) {
            try {
                future.get();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        executor.shutdown();
        return results;
    }
    
    public List<PortScanResult> scanHost(String ip) {
        return scanHost(ip, COMMON_PORTS);
    }
    
    public List<PortScanResult> scanHost(String ip, int[] ports) {
        List<PortScanResult> results = new ArrayList<>();
        
        // First check if host is alive
        if (!isHostAlive(ip)) {
            return results;
        }
        
        ExecutorService executor = Executors.newFixedThreadPool(50);
        List<Future<PortScanResult>> futures = new ArrayList<>();
        
        // Scan specified ports
        for (int port : ports) {
            final int currentPort = port;
            futures.add(executor.submit(() -> scanPort(ip, currentPort)));
        }
        
        for (Future<PortScanResult> future : futures) {
            try {
                PortScanResult result = future.get(TIMEOUT, TimeUnit.MILLISECONDS);
                if (result != null && result.isOpen()) {
                    results.add(result);
                }
            } catch (TimeoutException e) {
                // Port scan timed out
            } catch (Exception e) {
                // Port is closed or filtered
            }
        }
        
        executor.shutdown();
        return results;
    }
    
    public List<PortScanResult> scanHostWithFullRange(String ip) {
        List<PortScanResult> results = new ArrayList<>();
        
        if (!isHostAlive(ip)) {
            return results;
        }
        
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<PortScanResult>> futures = new ArrayList<>();
        
        // Scan common ports first
        for (int port : COMMON_PORTS) {
            final int currentPort = port;
            futures.add(executor.submit(() -> scanPort(ip, currentPort)));
        }
        
        // Then scan remaining ports 1-1024
        for (int port = 1; port <= 1024; port++) {
            if (!contains(COMMON_PORTS, port)) {
                final int currentPort = port;
                futures.add(executor.submit(() -> scanPort(ip, currentPort)));
            }
        }
        
        // Process results
        for (Future<PortScanResult> future : futures) {
            try {
                PortScanResult result = future.get(TIMEOUT, TimeUnit.MILLISECONDS);
                if (result != null && result.isOpen()) {
                    results.add(result);
                }
            } catch (TimeoutException e) {
                // Skip timed out ports
            } catch (Exception e) {
                // Port is closed or filtered
            }
        }
        
        executor.shutdown();
        return results;
    }
    
    public PortScanResult scanPort(String ip, int port) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(ip, port), TIMEOUT);
            
            // Try to get banner
            String banner = null;
            try {
                socket.setSoTimeout(2000);
                socket.getOutputStream().write("\r\n".getBytes());
                byte[] buffer = new byte[1024];
                int bytesRead = socket.getInputStream().read(buffer);
                if (bytesRead > 0) {
                    banner = new String(buffer, 0, bytesRead).trim();
                }
            } catch (Exception e) {
                // Banner grabbing failed, but port is open
            }
            
            socket.close();
            
            String service = identifyService(port);
            PortScanResult result = new PortScanResult(ip, port, "TCP", "open", service);
            if (banner != null) {
                result.setBanner(banner);
            }
            return result;
            
        } catch (Exception e) {
            // Try UDP scan for specific ports
            if (port == 53 || port == 123 || port == 161) {
                if (scanUDPPort(ip, port)) {
                    String service = identifyService(port);
                    return new PortScanResult(ip, port, "UDP", "open", service);
                }
            }
        }
        return null;
    }
    
    private boolean scanUDPPort(String ip, int port) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(TIMEOUT);
            
            InetAddress address = InetAddress.getByName(ip);
            byte[] buffer = new byte[1024];
            
            // Send empty packet
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, port);
            socket.send(packet);
            
            // Try to receive response
            socket.receive(packet);
            return true;
        } catch (Exception e) {
            // Port might be open but not responding
            return false;
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }
    
    private boolean isHostAlive(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            return address.isReachable(TIMEOUT);
        } catch (Exception e) {
            return false;
        }
    }
    
    private String identifyService(int port) {
        Map<Integer, String> services = new HashMap<>();
        services.put(21, "FTP");
        services.put(22, "SSH");
        services.put(23, "Telnet");
        services.put(25, "SMTP");
        services.put(53, "DNS");
        services.put(80, "HTTP");
        services.put(110, "POP3");
        services.put(135, "MSRPC");
        services.put(139, "NetBIOS");
        services.put(143, "IMAP");
        services.put(443, "HTTPS");
        services.put(445, "SMB");
        services.put(993, "IMAPS");
        services.put(995, "POP3S");
        services.put(1723, "PPTP");
        services.put(3306, "MySQL");
        services.put(3389, "RDP");
        services.put(5900, "VNC");
        services.put(8080, "HTTP-Proxy");
        services.put(8443, "HTTPS-Alt");
        services.put(27017, "MongoDB");
        services.put(6379, "Redis");
        services.put(9200, "Elasticsearch");
        
        return services.getOrDefault(port, "Unknown");
    }
    
    private boolean contains(int[] array, int value) {
        for (int item : array) {
            if (item == value) return true;
        }
        return false;
    }
    
    // Quick scan method for common ports only
    public List<PortScanResult> quickScan(String ip) {
        return scanHost(ip, COMMON_PORTS);
    }
    
    // Method to scan specific port ranges
    public List<PortScanResult> scanPortRange(String ip, int startPort, int endPort) {
        List<PortScanResult> results = new ArrayList<>();
        
        if (!isHostAlive(ip)) {
            return results;
        }
        
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<PortScanResult>> futures = new ArrayList<>();
        
        for (int port = startPort; port <= endPort; port++) {
            final int currentPort = port;
            futures.add(executor.submit(() -> scanPort(ip, currentPort)));
        }
        
        for (Future<PortScanResult> future : futures) {
            try {
                PortScanResult result = future.get(TIMEOUT, TimeUnit.MILLISECONDS);
                if (result != null && result.isOpen()) {
                    results.add(result);
                }
            } catch (TimeoutException e) {
                // Skip timed out ports
            } catch (Exception e) {
                // Port is closed or filtered
            }
        }
        
        executor.shutdown();
        return results;
    }
    
    public static class PortScanResult {
        private String ip;
        private int port;
        private String protocol;
        private String state;
        private String service;
        private String banner;
        private Date timestamp;
        
        public PortScanResult(String ip, int port, String protocol, String state, String service) {
            this.ip = ip;
            this.port = port;
            this.protocol = protocol;
            this.state = state;
            this.service = service;
            this.timestamp = new Date();
        }
        
        // Getters and setters
        public String getIp() { return ip; }
        public int getPort() { return port; }
        public String getProtocol() { return protocol; }
        public String getState() { return state; }
        public String getService() { return service; }
        public String getBanner() { return banner; }
        public Date getTimestamp() { return timestamp; }
        
        public void setBanner(String banner) { this.banner = banner; }
        public boolean isOpen() { return "open".equalsIgnoreCase(state); }
        
        @Override
        public String toString() {
            return String.format("%s:%d [%s] - %s - %s", 
                ip, port, protocol, service, state);
        }
        
        public String toDetailedString() {
            StringBuilder sb = new StringBuilder();
            sb.append("IP: ").append(ip).append("\n");
            sb.append("Port: ").append(port).append("\n");
            sb.append("Protocol: ").append(protocol).append("\n");
            sb.append("Service: ").append(service).append("\n");
            sb.append("State: ").append(state).append("\n");
            if (banner != null && !banner.isEmpty()) {
                sb.append("Banner: ").append(banner).append("\n");
            }
            sb.append("Timestamp: ").append(timestamp);
            return sb.toString();
        }
    }
    
    public void performBannerGrabbing(String ip, int port) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(ip, port), TIMEOUT);
            socket.setSoTimeout(2000);
            
            // Send some data to trigger response
            java.io.OutputStream out = socket.getOutputStream();
            out.write("\r\n".getBytes());
            out.flush();
            
            // Read banner
            java.io.InputStream in = socket.getInputStream();
            byte[] buffer = new byte[1024];
            int bytesRead = in.read(buffer);
            
            if (bytesRead > 0) {
                String banner = new String(buffer, 0, bytesRead).trim();
                System.out.println("Banner for " + ip + ":" + port + ": " + banner);
            }
            
            socket.close();
        } catch (Exception e) {
            // Banner grabbing failed
        }
    }
    
    // Method to get scan statistics
    public Map<String, Object> getScanStatistics(List<PortScanResult> results) {
        Map<String, Object> stats = new HashMap<>();
        
        if (results == null || results.isEmpty()) {
            stats.put("total_ports", 0);
            stats.put("open_ports", 0);
            stats.put("common_services", new ArrayList<>());
            return stats;
        }
        
        int openPorts = 0;
        List<String> commonServices = new ArrayList<>();
        Map<String, Integer> serviceCount = new HashMap<>();
        
        for (PortScanResult result : results) {
            if (result.isOpen()) {
                openPorts++;
                String service = result.getService();
                serviceCount.put(service, serviceCount.getOrDefault(service, 0) + 1);
                
                if (!"Unknown".equals(service)) {
                    commonServices.add(service);
                }
            }
        }
        
        stats.put("total_ports_scanned", results.size());
        stats.put("open_ports", openPorts);
        stats.put("common_services", commonServices);
        stats.put("service_distribution", serviceCount);
        
        return stats;
    }
    
    // Utility method to validate IP address
    public static boolean isValidIP(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                return false;
            }
            
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            }
            
            return !ip.endsWith(".");
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    // Method to get local network IP range
    public static String getLocalNetworkPrefix() {
        try {
            InetAddress localHost = InetAddress.getLocalHost();
            String hostAddress = localHost.getHostAddress();
            String[] parts = hostAddress.split("\\.");
            if (parts.length >= 3) {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".";
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return "192.168.1.";
    }
}
