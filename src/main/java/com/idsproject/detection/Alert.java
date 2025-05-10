package main.java.com.idsproject.detection;

/**
 * Classe représentant une alerte générée par le système de détection d'intrusion.
 * Contient toutes les informations pertinentes sur une détection d'attaque.
 */
public class Alert {
    private String sourceAddress;
    private String destinationAddress;
    private int sourcePort;
    private int destinationPort;
    private long timestamp;
    private String attackType;
    private double confidence;
    private String description;
    private String action;
    
    /**
     * Constructeur par défaut
     */
    public Alert() {
    }
    
    /**
     * Constructeur avec tous les paramètres
     */
    public Alert(String sourceAddress, String destinationAddress, int sourcePort, int destinationPort,
                long timestamp, String attackType, double confidence, String description, String action) {
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.timestamp = timestamp;
        this.attackType = attackType;
        this.confidence = confidence;
        this.description = description;
        this.action = action;
    }
    
    // Getters et Setters
    public String getSourceAddress() {
        return sourceAddress;
    }
    
    public void setSourceAddress(String sourceAddress) {
        this.sourceAddress = sourceAddress;
    }
    
    public String getDestinationAddress() {
        return destinationAddress;
    }
    
    public void setDestinationAddress(String destinationAddress) {
        this.destinationAddress = destinationAddress;
    }
    
    public int getSourcePort() {
        return sourcePort;
    }
    
    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }
    
    public int getDestinationPort() {
        return destinationPort;
    }
    
    public void setDestinationPort(int destinationPort) {
        this.destinationPort = destinationPort;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
    
    public String getAttackType() {
        return attackType;
    }
    
    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }
    
    public double getConfidence() {
        return confidence;
    }
    
    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public String getAction() {
        return action;
    }
    
    public void setAction(String action) {
        this.action = action;
    }
    
    /**
     * Génère une représentation en chaîne de caractères de l'alerte
     */
    @Override
    public String toString() {
        return String.format("ALERTE: %s -> %s:%d (%s, confiance: %.2f%%) - %s - Action: %s",
                sourceAddress,
                destinationAddress, destinationPort,
                attackType, confidence * 100,
                description,
                action);
    }
}
