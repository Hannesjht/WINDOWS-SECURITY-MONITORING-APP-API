package com.security.gui;

import javax.swing.*;
import java.awt.*;
import java.util.Properties;

public class ScannerSettingsDialog extends JDialog {
    private JTextField timeoutField;
    private JTextField threadsField;
    private JTextField startRangeField;
    private JTextField endRangeField;
    private Properties config;
    private boolean saved = false;
    
    public ScannerSettingsDialog(JFrame parent, Properties config) {
        super(parent, "Scanner Settings", true);
        this.config = config;
        initComponents();
        loadCurrentSettings();
        pack();
        setLocationRelativeTo(parent);
        setSize(400, 250);
    }
    
    private void initComponents() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        
        // Timeout setting
        gbc.gridx = 0; gbc.gridy = 0;
        mainPanel.add(new JLabel("Timeout (ms):"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 0;
        timeoutField = new JTextField(15);
        mainPanel.add(timeoutField, gbc);
        
        // Threads setting
        gbc.gridx = 0; gbc.gridy = 1;
        mainPanel.add(new JLabel("Thread Count:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 1;
        threadsField = new JTextField(15);
        mainPanel.add(threadsField, gbc);
        
        // Start Range
        gbc.gridx = 0; gbc.gridy = 2;
        mainPanel.add(new JLabel("Start IP Range:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 2;
        startRangeField = new JTextField(15);
        mainPanel.add(startRangeField, gbc);
        
        // End Range
        gbc.gridx = 0; gbc.gridy = 3;
        mainPanel.add(new JLabel("End IP Range:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 3;
        endRangeField = new JTextField(15);
        mainPanel.add(endRangeField, gbc);
        
        // Buttons panel
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        JButton saveButton = new JButton("Save");
        saveButton.setPreferredSize(new Dimension(80, 30));
        JButton cancelButton = new JButton("Cancel");
        cancelButton.setPreferredSize(new Dimension(80, 30));
        
        saveButton.addActionListener(e -> saveSettings());
        cancelButton.addActionListener(e -> {
            saved = false;
            setVisible(false);
        });
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        mainPanel.add(buttonPanel, gbc);
        
        // Add main panel to dialog
        add(mainPanel);
        
        // Make Enter key trigger save
        getRootPane().setDefaultButton(saveButton);
    }
    
    private void loadCurrentSettings() {
        timeoutField.setText(config.getProperty("scan.timeout", "5000"));
        threadsField.setText(config.getProperty("scan.threads", "100"));
        startRangeField.setText(config.getProperty("scan.range.start", "1"));
        endRangeField.setText(config.getProperty("scan.range.end", "255"));
    }
    
    private void saveSettings() {
        try {
            // Validate inputs
            int timeout = Integer.parseInt(timeoutField.getText());
            int threads = Integer.parseInt(threadsField.getText());
            int startRange = Integer.parseInt(startRangeField.getText());
            int endRange = Integer.parseInt(endRangeField.getText());
            
            if (timeout < 100 || timeout > 30000) {
                throw new IllegalArgumentException("Timeout must be between 100ms and 30000ms (30 seconds)");
            }
            if (threads < 1 || threads > 500) {
                throw new IllegalArgumentException("Threads must be between 1 and 500");
            }
            if (startRange < 1 || startRange > 254) {
                throw new IllegalArgumentException("Start range must be between 1 and 254");
            }
            if (endRange < startRange || endRange > 255) {
                throw new IllegalArgumentException("End range must be between " + startRange + " and 255");
            }
            
            // Save to config
            config.setProperty("scan.timeout", String.valueOf(timeout));
            config.setProperty("scan.threads", String.valueOf(threads));
            config.setProperty("scan.range.start", String.valueOf(startRange));
            config.setProperty("scan.range.end", String.valueOf(endRange));
            
            saved = true;
            JOptionPane.showMessageDialog(this,
                "Scanner settings saved successfully!",
                "Success",
                JOptionPane.INFORMATION_MESSAGE);
            setVisible(false);
            
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this,
                "Please enter valid numbers for all fields",
                "Invalid Input",
                JOptionPane.ERROR_MESSAGE);
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this,
                e.getMessage(),
                "Invalid Value",
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    public boolean isSaved() {
        return saved;
    }
}
