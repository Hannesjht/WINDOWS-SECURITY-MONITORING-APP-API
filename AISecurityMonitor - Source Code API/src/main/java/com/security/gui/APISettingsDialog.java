package com.security.gui;

import javax.swing.*;
import java.awt.*;
import java.util.Properties;

public class APISettingsDialog extends JDialog {
    private JTextField virusTotalKeyField;
    private JTextField abuseIPDBKeyField;
    private Properties config;
    private boolean saved = false;
    
    public APISettingsDialog(Frame parent, Properties config) {
        super(parent, "API Settings", true);
        this.config = config;
        initComponents();
        loadCurrentSettings();
        pack();
        setLocationRelativeTo(parent);
    }
    
    private void initComponents() {
        setLayout(new BorderLayout());
        
        // Main panel
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        
        // VirusTotal API Key
        gbc.gridx = 0; gbc.gridy = 0;
        mainPanel.add(new JLabel("VirusTotal API Key:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 0;
        virusTotalKeyField = new JPasswordField(30);
        mainPanel.add(virusTotalKeyField, gbc);
        
        // AbuseIPDB API Key
        gbc.gridx = 0; gbc.gridy = 1;
        mainPanel.add(new JLabel("AbuseIPDB API Key:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 1;
        abuseIPDBKeyField = new JPasswordField(30);
        mainPanel.add(abuseIPDBKeyField, gbc);
        
        add(mainPanel, BorderLayout.CENTER);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        JButton cancelButton = new JButton("Cancel");
        
        saveButton.addActionListener(e -> saveSettings());
        cancelButton.addActionListener(e -> setVisible(false));
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        
        add(buttonPanel, BorderLayout.SOUTH);
        
        // Make Enter key save
        getRootPane().setDefaultButton(saveButton);
    }
    
    private void loadCurrentSettings() {
        virusTotalKeyField.setText(config.getProperty("virustotal.api.key", ""));
        abuseIPDBKeyField.setText(config.getProperty("abuseipdb.api.key", ""));
    }
    
    private void saveSettings() {
        config.setProperty("virustotal.api.key", virusTotalKeyField.getText());
        config.setProperty("abuseipdb.api.key", abuseIPDBKeyField.getText());
        saved = true;
        setVisible(false);
    }
    
    public boolean isSaved() {
        return saved;
    }
    
    public Properties getConfig() {
        return config;
    }
}
