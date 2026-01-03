package com.security.services;

public class FirewallService {
    
    public boolean blockIP(String ip) {
        System.out.println("Attempting to block IP: " + ip);
        
        try {
            String os = System.getProperty("os.name").toLowerCase();
            
            if (os.contains("win")) {
                return blockIPWindows(ip);
            } else if (os.contains("linux") || os.contains("mac")) {
                return blockIPUnix(ip);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return false;
    }
    
    private boolean blockIPWindows(String ip) {
        try {
            // Windows firewall command
            String cmd = String.format(
                "netsh advfirewall firewall add rule name=\"Block %s\" dir=in action=block remoteip=%s",
                ip, ip
            );
            
            Process p = Runtime.getRuntime().exec(cmd);
            return p.waitFor() == 0;
        } catch (Exception e) {
            System.err.println("Windows firewall command failed. Run as Administrator.");
            return false;
        }
    }
    
    private boolean blockIPUnix(String ip) {
        try {
            // Linux iptables or pf for Mac
            String cmd;
            if (System.getProperty("os.name").toLowerCase().contains("linux")) {
                cmd = String.format("iptables -A INPUT -s %s -j DROP", ip);
            } else {
                cmd = String.format("pfctl -t blocked -T add %s", ip);
            }
            
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            return p.waitFor() == 0;
        } catch (Exception e) {
            System.err.println("Unix firewall command failed. Run with sudo.");
            return false;
        }
    }
    
    public boolean unblockIP(String ip) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            
            if (os.contains("win")) {
                String cmd = String.format(
                    "netsh advfirewall firewall delete rule name=\"Block %s\"",
                    ip
                );
                Process p = Runtime.getRuntime().exec(cmd);
                return p.waitFor() == 0;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
