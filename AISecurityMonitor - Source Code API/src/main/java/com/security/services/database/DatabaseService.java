package com.security.services.database;

import com.security.models.ConnectionData;
import com.security.models.DeviceInfo;
import java.sql.*;
import java.util.*;

public class DatabaseService {
    private Connection dbConnection;  // Changed variable name to avoid conflict
    
    public DatabaseService() {
        initializeDatabase();
    }
    
    private void initializeDatabase() {
        try {
            Class.forName("org.sqlite.JDBC");
            dbConnection = DriverManager.getConnection("jdbc:sqlite:security_monitor.db");
            createTables();
            System.out.println("Database initialized successfully");
        } catch (Exception e) {
            System.err.println("Failed to initialize database: " + e.getMessage());
        }
    }
    
    private void createTables() {
        String[] createTableStatements = {
            "CREATE TABLE IF NOT EXISTS connections (" +
            "    id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP," +
            "    protocol TEXT," +
            "    local_ip TEXT," +
            "    local_port INTEGER," +
            "    remote_ip TEXT," +
            "    remote_port INTEGER," +
            "    state TEXT," +
            "    threat_score REAL," +
            "    status TEXT," +
            "    action_taken TEXT" +
            ")",
            
            "CREATE TABLE IF NOT EXISTS devices (" +
            "    id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "    ip TEXT UNIQUE," +
            "    hostname TEXT," +
            "    mac_address TEXT," +
            "    os TEXT," +
            "    device_type TEXT," +
            "    status TEXT," +
            "    last_seen DATETIME," +
            "    open_ports TEXT," +
            "    services TEXT" +
            ")",
            
            "CREATE TABLE IF NOT EXISTS threats (" +
            "    id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP," +
            "    threat_type TEXT," +
            "    source_ip TEXT," +
            "    target_ip TEXT," +
            "    description TEXT," +
            "    severity INTEGER," +
            "    action_taken TEXT," +
            "    resolved BOOLEAN DEFAULT 0" +
            ")",
            
            "CREATE TABLE IF NOT EXISTS firewall_logs (" +
            "    id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP," +
            "    ip_address TEXT," +
            "    action TEXT," +
            "    reason TEXT," +
            "    success BOOLEAN" +
            ")",
            
            "CREATE TABLE IF NOT EXISTS ml_training_data (" +
            "    id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP," +
            "    protocol_type INTEGER," +
            "    src_bytes REAL," +
            "    dst_bytes REAL," +
            "    duration REAL," +
            "    count INTEGER," +
            "    srv_count INTEGER," +
            "    same_srv_rate REAL," +
            "    diff_srv_rate REAL," +
            "    dst_host_srv_count INTEGER," +
            "    dst_host_same_srv_rate REAL," +
            "    dst_host_diff_srv_rate REAL," +
            "    is_threat BOOLEAN" +
            ")"
        };
        
        try (Statement stmt = dbConnection.createStatement()) {
            for (String sql : createTableStatements) {
                stmt.execute(sql);
            }
        } catch (SQLException e) {
            System.err.println("Failed to create tables: " + e.getMessage());
        }
    }
    
    public void logConnection(ConnectionData connection) {
        String sql = "INSERT INTO connections (protocol, local_ip, local_port, remote_ip, remote_port, state, threat_score, status) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement pstmt = dbConnection.prepareStatement(sql)) {
            pstmt.setString(1, connection.getProtocol());
            pstmt.setString(2, connection.getLocalIP());
            pstmt.setInt(3, connection.getLocalPort());
            pstmt.setString(4, connection.getRemoteIP());
            pstmt.setInt(5, connection.getRemotePort());
            pstmt.setString(6, connection.getState());
            pstmt.setDouble(7, connection.getThreatScore());
            pstmt.setString(8, connection.getStatus());
            
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to log connection: " + e.getMessage());
        }
    }
    
    public void logThreat(String threatType, String sourceIp, String targetIp, 
                         String description, int severity, String action) {
        String sql = "INSERT INTO threats (threat_type, source_ip, target_ip, description, severity, action_taken) " +
                     "VALUES (?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement pstmt = dbConnection.prepareStatement(sql)) {
            pstmt.setString(1, threatType);
            pstmt.setString(2, sourceIp);
            pstmt.setString(3, targetIp);
            pstmt.setString(4, description);
            pstmt.setInt(5, severity);
            pstmt.setString(6, action);
            
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to log threat: " + e.getMessage());
        }
    }
    
    public void logFirewallAction(String ip, String action, String reason, boolean success) {
        String sql = "INSERT INTO firewall_logs (ip_address, action, reason, success) " +
                     "VALUES (?, ?, ?, ?)";
        
        try (PreparedStatement pstmt = dbConnection.prepareStatement(sql)) {
            pstmt.setString(1, ip);
            pstmt.setString(2, action);
            pstmt.setString(3, reason);
            pstmt.setBoolean(4, success);
            
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to log firewall action: " + e.getMessage());
        }
    }
    
    public List<Map<String, Object>> getRecentThreats(int limit) {
        List<Map<String, Object>> threats = new ArrayList<>();
        String sql = "SELECT * FROM threats WHERE resolved = 0 ORDER BY timestamp DESC LIMIT ?";
        
        try (PreparedStatement pstmt = dbConnection.prepareStatement(sql)) {
            pstmt.setInt(1, limit);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                Map<String, Object> threat = new HashMap<>();
                threat.put("id", rs.getInt("id"));
                threat.put("timestamp", rs.getTimestamp("timestamp"));
                threat.put("threat_type", rs.getString("threat_type"));
                threat.put("source_ip", rs.getString("source_ip"));
                threat.put("target_ip", rs.getString("target_ip"));
                threat.put("description", rs.getString("description"));
                threat.put("severity", rs.getInt("severity"));
                threat.put("action_taken", rs.getString("action_taken"));
                threats.add(threat);
            }
        } catch (SQLException e) {
            System.err.println("Failed to get threats: " + e.getMessage());
        }
        
        return threats;
    }
    
    public Map<String, Integer> getThreatStatistics() {
        Map<String, Integer> stats = new HashMap<>();
        String[] queries = {
            "SELECT COUNT(*) as total FROM threats",
            "SELECT COUNT(*) as high FROM threats WHERE severity >= 7",
            "SELECT COUNT(*) as blocked FROM firewall_logs WHERE action = 'BLOCK'",
            "SELECT COUNT(*) as devices FROM devices"
        };
        
        String[] keys = {"total_threats", "high_severity", "blocked_ips", "known_devices"};
        
        try (Statement stmt = dbConnection.createStatement()) {
            for (int i = 0; i < queries.length; i++) {
                ResultSet rs = stmt.executeQuery(queries[i]);
                if (rs.next()) {
                    stats.put(keys[i], rs.getInt(1));
                }
            }
        } catch (SQLException e) {
            System.err.println("Failed to get statistics: " + e.getMessage());
        }
        
        return stats;
    }
    
    public void close() {
        try {
            if (dbConnection != null && !dbConnection.isClosed()) {
                dbConnection.close();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
