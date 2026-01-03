package com.security;

import com.security.services.api.APIIntegrationService;
import com.security.gui.MainWindow;
import com.formdev.flatlaf.FlatDarkLaf;
import javax.swing.*;
import java.util.Map;

public class Main {
    public static void main(String[] args) {
        // Set up the look and feel
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // Create and show the main window on the Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            MainWindow window = new MainWindow();
            window.setVisible(true);
            
            // Example usage of APIIntegrationService
            demonstrateAPIService();
        });
    }
    
    private static void demonstrateAPIService() {
        APIIntegrationService apiService = new APIIntegrationService();
        Map<String, Object> threatInfo = apiService.getThreatIntelligence("8.8.8.8");
        
        if (threatInfo != null) {
            System.out.println("Threat score: " + threatInfo.get("combined_threat_score"));
        } else {
            System.out.println("No threat information available.");
        }
    }
}
