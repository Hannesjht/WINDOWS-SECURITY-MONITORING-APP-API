package com.security.gui;

import com.security.services.scanner.AdvancedPortScanner;
import com.security.services.scanner.AdvancedPortScanner.PortScanResult;
import com.security.services.api.APIIntegrationService;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.util.*;
import java.util.List;

public class MainWindow extends JFrame {
    private Properties config;
    private JTabbedPane tabbedPane;
    private JTextArea logArea;
    private JTable scanResultsTable;
    private DefaultTableModel tableModel;
    private AdvancedPortScanner scanner;
    private APIIntegrationService apiService;
    
    // Scanner components
    private JTextField networkPrefixField;
    private JTextField startRangeField;
    private JTextField endRangeField;
    private JButton scanButton;
    private JButton stopButton;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    private SwingWorker<Void, String> currentScanWorker;
    
    public MainWindow() {
        super("AI Security Monitor");
        loadConfig();
        initComponents();
        setupScanner();
        setupAPIService();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setSize(1000, 700);
        setLocationRelativeTo(null);
    }
    
    private void loadConfig() {
        config = new Properties();
        try (FileInputStream fis = new FileInputStream("config.properties")) {
            config.load(fis);
        } catch (IOException e) {
            // Create default config
            config.setProperty("scan.timeout", "5000");
            config.setProperty("scan.threads", "100");
            config.setProperty("scan.range.start", "1");
            config.setProperty("scan.range.end", "255");
            saveConfig();
        }
    }
    
    private void saveConfig() {
        try (FileOutputStream fos = new FileOutputStream("config.properties")) {
            config.store(fos, "AISecurityMonitor Configuration");
        } catch (IOException e) {
            log("Error saving config: " + e.getMessage());
        }
    }
    
    private void initComponents() {
        // Menu Bar
        initMenuBar();
        
        // Main layout
        setLayout(new BorderLayout());
        
        // Tabbed Pane
        tabbedPane = new JTabbedPane();
        
        // Dashboard Tab
        tabbedPane.addTab("Dashboard", createDashboardPanel());
        
        // Scanner Tab
        tabbedPane.addTab("Network Scanner", createScannerPanel());
        
        // Threats Tab
        tabbedPane.addTab("Threat Detection", createThreatsPanel());
        
        // Log Tab
        tabbedPane.addTab("Logs", createLogPanel());
        
        add(tabbedPane, BorderLayout.CENTER);
        
        // Status Bar
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusLabel = new JLabel("Ready");
        statusPanel.add(statusLabel, BorderLayout.WEST);
        
        progressBar = new JProgressBar();
        progressBar.setVisible(false);
        statusPanel.add(progressBar, BorderLayout.CENTER);
        
        add(statusPanel, BorderLayout.SOUTH);
    }
    
    private void initMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        
        // File Menu
        JMenu fileMenu = new JMenu("File");
        JMenuItem reloadConfigItem = new JMenuItem("Reload Config");
        JMenuItem exitItem = new JMenuItem("Exit");
        
        reloadConfigItem.addActionListener(e -> {
            loadConfig();
            JOptionPane.showMessageDialog(this, "Configuration reloaded!");
        });
        exitItem.addActionListener(e -> System.exit(0));
        
        fileMenu.add(reloadConfigItem);
        fileMenu.addSeparator();
        fileMenu.add(exitItem);
        
        // Settings Menu
        JMenu settingsMenu = new JMenu("Settings");
        JMenuItem apiSettingsItem = new JMenuItem("API Configuration");
        JMenuItem scannerSettingsItem = new JMenuItem("Scanner Settings");
        
        apiSettingsItem.addActionListener(e -> openAPISettings());
        scannerSettingsItem.addActionListener(e -> openScannerSettings());
        
        settingsMenu.add(apiSettingsItem);
        settingsMenu.add(scannerSettingsItem);
        
        // Help Menu
        JMenu helpMenu = new JMenu("Help");
        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(e -> showAboutDialog());
        helpMenu.add(aboutItem);
        
        menuBar.add(fileMenu);
        menuBar.add(settingsMenu);
        menuBar.add(helpMenu);
        
        setJMenuBar(menuBar);
    }
    
    private void openAPISettings() {
        APISettingsDialog dialog = new APISettingsDialog(this, config);
        dialog.setVisible(true);
        
        if (dialog.isSaved()) {
            saveConfig();
            JOptionPane.showMessageDialog(this,
                "API settings saved. Some changes may require restart.",
                "Settings Saved",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void openScannerSettings() {
        ScannerSettingsDialog dialog = new ScannerSettingsDialog(this, config);
        dialog.setVisible(true);
        
        if (dialog.isSaved()) {
            saveConfig();
            updateScannerSettings();
            JOptionPane.showMessageDialog(this,
                "Scanner settings updated!",
                "Settings Updated",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void updateScannerSettings() {
        // Update scanner instance with new settings
        if (scanner != null) {
            // Note: AdvancedPortScanner needs setters for timeout
            // You may need to create a new scanner instance
            setupScanner();
        }
        
        // Update UI fields
        startRangeField.setText(config.getProperty("scan.range.start", "1"));
        endRangeField.setText(config.getProperty("scan.range.end", "255"));
    }
    
    private JPanel createDashboardPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Stats panel
        JPanel statsPanel = new JPanel(new GridLayout(2, 3, 10, 10));
        statsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        String[] stats = {"Devices Found", "Open Ports", "Threats Detected", "API Calls", "Scan Duration", "Risk Level"};
        for (String stat : stats) {
            JPanel statPanel = new JPanel(new BorderLayout());
            statPanel.setBorder(BorderFactory.createTitledBorder(stat));
            JLabel valueLabel = new JLabel("0", SwingConstants.CENTER);
            valueLabel.setFont(new Font("Arial", Font.BOLD, 24));
            statPanel.add(valueLabel, BorderLayout.CENTER);
            statsPanel.add(statPanel);
        }
        
        panel.add(statsPanel, BorderLayout.NORTH);
        
        // Quick actions
        JPanel actionsPanel = new JPanel(new FlowLayout());
        JButton quickScanButton = new JButton("Quick Scan");
        JButton checkThreatsButton = new JButton("Check Threats");
        JButton viewLogsButton = new JButton("View Logs");
        
        quickScanButton.addActionListener(e -> tabbedPane.setSelectedIndex(1));
        checkThreatsButton.addActionListener(e -> checkIPThreat("192.168.1.1"));
        viewLogsButton.addActionListener(e -> tabbedPane.setSelectedIndex(3));
        
        actionsPanel.add(quickScanButton);
        actionsPanel.add(checkThreatsButton);
        actionsPanel.add(viewLogsButton);
        
        panel.add(actionsPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createScannerPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Input panel
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Network prefix
        gbc.gridx = 0; gbc.gridy = 0;
        inputPanel.add(new JLabel("Network Prefix:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 0;
        networkPrefixField = new JTextField("192.168.1.", 15);
        inputPanel.add(networkPrefixField, gbc);
        
        // Start range
        gbc.gridx = 0; gbc.gridy = 1;
        inputPanel.add(new JLabel("Start Range:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 1;
        startRangeField = new JTextField(config.getProperty("scan.range.start", "1"), 10);
        inputPanel.add(startRangeField, gbc);
        
        // End range
        gbc.gridx = 2; gbc.gridy = 1;
        inputPanel.add(new JLabel("End Range:"), gbc);
        
        gbc.gridx = 3; gbc.gridy = 1;
        endRangeField = new JTextField(config.getProperty("scan.range.end", "255"), 10);
        inputPanel.add(endRangeField, gbc);
        
        // Button panel
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 4;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        
        scanButton = new JButton("Start Scan");
        scanButton.setPreferredSize(new Dimension(120, 35));
        
        stopButton = new JButton("Stop");
        stopButton.setPreferredSize(new Dimension(120, 35));
        stopButton.setEnabled(false);
        
        JButton settingsButton = new JButton("Settings");
        settingsButton.setPreferredSize(new Dimension(120, 35));
        
        scanButton.addActionListener(this::startScan);
        stopButton.addActionListener(e -> stopScan());
        settingsButton.addActionListener(e -> openScannerSettings());
        
        buttonPanel.add(scanButton);
        buttonPanel.add(stopButton);
        buttonPanel.add(settingsButton);
        
        inputPanel.add(buttonPanel, gbc);
        
        panel.add(inputPanel, BorderLayout.NORTH);
        
        // Results table
        String[] columns = {"IP Address", "Port", "Protocol", "Service", "Status", "Banner"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        scanResultsTable = new JTable(tableModel);
        JScrollPane scrollPane = new JScrollPane(scanResultsTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Scan Results"));
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void startScan(ActionEvent e) {
        String networkPrefix = networkPrefixField.getText();
        String startText = startRangeField.getText();
        String endText = endRangeField.getText();
        
        // Validate input
        if (networkPrefix.isEmpty() || !networkPrefix.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.$")) {
            JOptionPane.showMessageDialog(this,
                "Please enter a valid network prefix (e.g., 192.168.1.)",
                "Invalid Input",
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        int start, end;
        try {
            start = Integer.parseInt(startText);
            end = Integer.parseInt(endText);
            
            if (start < 1 || end > 255 || start > end) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this,
                "Please enter valid range numbers (1-255)",
                "Invalid Range",
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Clear previous results
        tableModel.setRowCount(0);
        
        // Disable scan button, enable stop button
        scanButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("Scanning...");
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        
        // Get timeout from config
        int timeout = Integer.parseInt(config.getProperty("scan.timeout", "5000"));
        
        // Create scanner with configured timeout
        scanner = new AdvancedPortScanner();
        
        // Run scan in background thread
        currentScanWorker = new SwingWorker<Void, String>() {
            private int hostsScanned = 0;
            private int totalHosts = end - start + 1;
            
            @Override
            protected Void doInBackground() throws Exception {
                publish("Starting scan of " + totalHosts + " hosts...");
                
                // Scan each host
                for (int i = start; i <= end && !isCancelled(); i++) {
                    String ip = networkPrefix + i;
                    publish("Scanning " + ip + "...");
                    
                    try {
                        // Use scanner with proper timeout
                        List<PortScanResult> results = scanner.scanHost(ip);
                        
                        // Add results to table
                        for (PortScanResult result : results) {
                            SwingUtilities.invokeLater(() -> {
                                tableModel.addRow(new Object[]{
                                    result.getIp(),
                                    result.getPort(),
                                    result.getProtocol(),
                                    result.getService(),
                                    result.getState(),
                                    result.getBanner() != null ? result.getBanner() : ""
                                });
                            });
                        }
                        
                        hostsScanned++;
                        int progress = (int) ((hostsScanned * 100.0) / totalHosts);
                        setProgress(progress);
                        
                    } catch (Exception ex) {
                        publish("Error scanning " + ip + ": " + ex.getMessage());
                    }
                    
                    // Small delay to prevent overwhelming the system
                    Thread.sleep(50);
                }
                
                return null;
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    statusLabel.setText(message);
                    log(message);
                }
            }
            
            @Override
            protected void done() {
                scanButton.setEnabled(true);
                stopButton.setEnabled(false);
                progressBar.setVisible(false);
                progressBar.setIndeterminate(false);
                
                if (isCancelled()) {
                    statusLabel.setText("Scan cancelled");
                    log("Scan cancelled by user");
                } else {
                    statusLabel.setText("Scan completed. Found " + tableModel.getRowCount() + " open ports.");
                    log("Scan completed. Total open ports found: " + tableModel.getRowCount());
                }
            }
        };
        
        // Add property change listener for progress
        currentScanWorker.addPropertyChangeListener(evt -> {
            if ("progress".equals(evt.getPropertyName())) {
                progressBar.setValue((Integer) evt.getNewValue());
            }
        });
        
        currentScanWorker.execute();
    }
    
    private void stopScan() {
        if (currentScanWorker != null && !currentScanWorker.isDone()) {
            currentScanWorker.cancel(true);
            stopButton.setEnabled(false);
            statusLabel.setText("Stopping scan...");
        }
    }
    
    private void checkIPThreat(String ip) {
        if (apiService == null) {
            apiService = new APIIntegrationService();
        }
        
        SwingWorker<Map<String, Object>, Void> worker = new SwingWorker<>() {
            @Override
            protected Map<String, Object> doInBackground() throws Exception {
                statusLabel.setText("Checking threat intelligence for " + ip + "...");
                return apiService.getThreatIntelligence(ip);
            }
            
            @Override
            protected void done() {
                try {
                    Map<String, Object> result = get();
                    displayThreatResult(result);
                } catch (Exception e) {
                    log("Error checking threat: " + e.getMessage());
                    statusLabel.setText("Error checking threat");
                }
            }
        };
        worker.execute();
    }
    
    private void displayThreatResult(Map<String, Object> result) {
        StringBuilder sb = new StringBuilder();
        sb.append("Threat Intelligence Report:\n");
        sb.append("IP: ").append(result.get("ip_address")).append("\n");
        sb.append("Threat Score: ").append(result.get("combined_threat_score")).append("\n");
        sb.append("Verdict: ").append(result.get("overall_verdict")).append("\n");
        
        JOptionPane.showMessageDialog(this,
            sb.toString(),
            "Threat Report",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    private JPanel createThreatsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JTextArea threatArea = new JTextArea();
        threatArea.setEditable(false);
        threatArea.setText("Threat detection results will appear here...");
        
        panel.add(new JScrollPane(threatArea), BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Application Log"));
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearButton = new JButton("Clear Log");
        JButton saveButton = new JButton("Save Log");
        
        clearButton.addActionListener(e -> logArea.setText(""));
        saveButton.addActionListener(e -> saveLogToFile());
        
        buttonPanel.add(clearButton);
        buttonPanel.add(saveButton);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private void log(String message) {
        String timestamp = new java.text.SimpleDateFormat("HH:mm:ss").format(new Date());
        SwingUtilities.invokeLater(() -> {
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    private void saveLogToFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("security_log.txt"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter writer = new PrintWriter(fileChooser.getSelectedFile())) {
                writer.write(logArea.getText());
                JOptionPane.showMessageDialog(this, "Log saved successfully!");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Error saving log: " + e.getMessage());
            }
        }
    }
    
    private void setupScanner() {
        // Scanner is created dynamically when scanning
        log("Scanner service initialized");
    }
    
    private void setupAPIService() {
        try {
            apiService = new APIIntegrationService();
            log("API service initialized");
        } catch (Exception e) {
            log("Error initializing API service: " + e.getMessage());
        }
    }
    
    private void showAboutDialog() {
        JOptionPane.showMessageDialog(this,
            "AI Security Monitor v1.0\n" +
            "Advanced network security monitoring tool\n" +
            "© 2025 Vorster Security Micro Systems",
            "About",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            MainWindow window = new MainWindow();
            window.setVisible(true);
        });
    }
}
