package com.security.services.ml;

import com.security.models.ConnectionData;
import weka.classifiers.Classifier;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instances;
import weka.core.SerializationHelper;
import java.io.File;
import java.util.*;

public class MLThreatDetectionService {
    private Classifier classifier;
    private Instances dataset;
    private boolean modelTrained = false;
    
    public MLThreatDetectionService() {
        initializeAttributes();
        loadOrTrainModel();
    }
    
    private void initializeAttributes() {
        ArrayList<Attribute> attributes = new ArrayList<>();
        
        // Network features
        attributes.add(new Attribute("protocol_type")); // TCP=0, UDP=1
        attributes.add(new Attribute("src_bytes"));
        attributes.add(new Attribute("dst_bytes"));
        attributes.add(new Attribute("duration"));
        attributes.add(new Attribute("count"));
        attributes.add(new Attribute("srv_count"));
        attributes.add(new Attribute("same_srv_rate"));
        attributes.add(new Attribute("diff_srv_rate"));
        attributes.add(new Attribute("dst_host_srv_count"));
        attributes.add(new Attribute("dst_host_same_srv_rate"));
        attributes.add(new Attribute("dst_host_diff_srv_rate"));
        
        // Target class: 0=normal, 1=threat
        ArrayList<String> classValues = new ArrayList<>();
        classValues.add("normal");
        classValues.add("threat");
        attributes.add(new Attribute("class", classValues));
        
        dataset = new Instances("NetworkSecurity", attributes, 0);
        dataset.setClassIndex(dataset.numAttributes() - 1);
    }
    
    public double analyzeWithML(ConnectionData connection, Map<String, Object> additionalFeatures) {
        if (!modelTrained) {
            return basicAnalysis(connection);
        }
        
        try {
            double[] instanceValues = extractFeatures(connection, additionalFeatures);
            DenseInstance instance = new DenseInstance(1.0, instanceValues);
            instance.setDataset(dataset);
            
            double[] distribution = classifier.distributionForInstance(instance);
            double threatProbability = distribution[1]; // Probability of being threat
            
            return threatProbability * 100;
        } catch (Exception e) {
            e.printStackTrace();
            return basicAnalysis(connection);
        }
    }
    
    private double[] extractFeatures(ConnectionData connection, Map<String, Object> features) {
        return new double[] {
            connection.getProtocol().equals("TCP") ? 0 : 1,
            ((Number) features.getOrDefault("src_bytes", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("dst_bytes", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("duration", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("count", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("srv_count", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("same_srv_rate", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("diff_srv_rate", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("dst_host_srv_count", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("dst_host_same_srv_rate", 0.0)).doubleValue(),
            ((Number) features.getOrDefault("dst_host_diff_srv_rate", 0.0)).doubleValue(),
            dataset.attribute("class").indexOfValue("normal") // placeholder
        };
    }
    
    private double basicAnalysis(ConnectionData connection) {
        double score = 0.0;
        
        if (connection.getRemotePort() < 1024) score += 20;
        if (connection.getRemotePort() > 49152) score += 10;
        
        return Math.min(100, score);
    }
    
    private void loadOrTrainModel() {
        File modelFile = new File("threat_model.model");
        
        try {
            if (modelFile.exists()) {
                classifier = (Classifier) SerializationHelper.read(modelFile.getPath());
                modelTrained = true;
                System.out.println("ML Model loaded from file");
            } else {
                trainModel();
                SerializationHelper.write(modelFile.getPath(), classifier);
                modelTrained = true;
                System.out.println("ML Model trained and saved");
            }
        } catch (Exception e) {
            System.err.println("Failed to load/train ML model: " + e.getMessage());
        }
    }
    
    private void trainModel() throws Exception {
        classifier = new RandomForest();
        
        // Set options using string array
        String[] options = {"-I", "100", "-depth", "20"};
        ((RandomForest) classifier).setOptions(options);
        
        // Generate synthetic training data
        generateTrainingData();
        
        classifier.buildClassifier(dataset);
    }
    
    private void generateTrainingData() {
        Random rand = new Random(42);
        
        for (int i = 0; i < 1000; i++) {
            double[] values = new double[dataset.numAttributes()];
            
            // Normal connections
            values[0] = rand.nextInt(2); // protocol
            values[1] = rand.nextInt(10000); // src_bytes
            values[2] = rand.nextInt(10000); // dst_bytes
            values[3] = rand.nextInt(100); // duration
            values[4] = rand.nextInt(10); // count
            values[5] = rand.nextInt(5); // srv_count
            values[6] = rand.nextDouble(); // same_srv_rate
            values[7] = rand.nextDouble(); // diff_srv_rate
            values[8] = rand.nextInt(50); // dst_host_srv_count
            values[9] = rand.nextDouble(); // dst_host_same_srv_rate
            values[10] = rand.nextDouble(); // dst_host_diff_srv_rate
            values[11] = dataset.attribute("class").indexOfValue(i % 10 == 0 ? "threat" : "normal");
            
            DenseInstance instance = new DenseInstance(1.0, values);
            instance.setDataset(dataset);
            dataset.add(instance);
        }
    }
    
    public void addTrainingInstance(ConnectionData connection, boolean isThreat, 
                                   Map<String, Object> features) {
        try {
            double[] instanceValues = extractFeatures(connection, features);
            instanceValues[instanceValues.length - 1] = 
                dataset.attribute("class").indexOfValue(isThreat ? "threat" : "normal");
            
            DenseInstance instance = new DenseInstance(1.0, instanceValues);
            instance.setDataset(dataset);
            dataset.add(instance);
            
            // Retrain model periodically
            if (dataset.size() % 100 == 0) {
                retrainModel();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void retrainModel() {
        try {
            classifier.buildClassifier(dataset);
            SerializationHelper.write("threat_model.model", classifier);
            System.out.println("ML Model retrained with " + dataset.size() + " instances");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
