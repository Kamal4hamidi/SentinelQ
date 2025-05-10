package main.java.com.idsproject.rl;

import java.util.Arrays;

/**
 * Représentation de l'état du système pour l'apprentissage par renforcement.
 * Contient les caractéristiques pertinentes pour la prise de décision.
 */
public class State {
    
    // Caractéristiques de l'état
    private double connectionRate;         // Taux de connexions (normalisé)
    private double portDiversity;          // Diversité des ports utilisés (normalisée)
    private double bandwidth;              // Utilisation de la bande passante (normalisée)
    private double attackProbability;      // Probabilité que ce soit une attaque (0-1)
    private double consecutiveAlerts;      // Nombre d'alertes consécutives (normalisé)
    private int attackTypeIndex;           // Index du type d'attaque (0: aucune, 1: DoS, 2: PortScan, 3: BruteForce, etc.)
    
    /**
     * Constructeur par défaut initialisant les caractéristiques à zéro
     */
    public State() {
        this.connectionRate = 0.0;
        this.portDiversity = 0.0;
        this.bandwidth = 0.0;
        this.attackProbability = 0.0;
        this.consecutiveAlerts = 0.0;
        this.attackTypeIndex = 0;
    }
    
    /**
     * Constructeur avec toutes les caractéristiques
     */
    public State(double connectionRate, double portDiversity, double bandwidth,
            double attackProbability, double consecutiveAlerts, int attackTypeIndex) {
        this.connectionRate = connectionRate;
        this.portDiversity = portDiversity;
        this.bandwidth = bandwidth;
        this.attackProbability = attackProbability;
        this.consecutiveAlerts = consecutiveAlerts;
        this.attackTypeIndex = attackTypeIndex;
    }
    
    // Getters et Setters
    
    public double getConnectionRate() {
        return connectionRate;
    }
    
    public void setConnectionRate(double connectionRate) {
        this.connectionRate = clamp(connectionRate, 0.0, 1.0);
    }
    
    public double getPortDiversity() {
        return portDiversity;
    }
    
    public void setPortDiversity(double portDiversity) {
        this.portDiversity = clamp(portDiversity, 0.0, 1.0);
    }
    
    public double getBandwidth() {
        return bandwidth;
    }
    
    public void setBandwidth(double bandwidth) {
        this.bandwidth = clamp(bandwidth, 0.0, 1.0);
    }
    
    public double getAttackProbability() {
        return attackProbability;
    }
    
    public void setAttackProbability(double attackProbability) {
        this.attackProbability = clamp(attackProbability, 0.0, 1.0);
    }
    
    public double getConsecutiveAlerts() {
        return consecutiveAlerts;
    }
    
    public void setConsecutiveAlerts(double consecutiveAlerts) {
        this.consecutiveAlerts = clamp(consecutiveAlerts, 0.0, 1.0);
    }
    
    public int getAttackTypeIndex() {
        return attackTypeIndex;
    }
    
    public void setAttackTypeIndex(int attackTypeIndex) {
        this.attackTypeIndex = Math.max(0, attackTypeIndex);
    }
    
    /**
     * Méthode utilitaire pour limiter une valeur entre un minimum et un maximum
     */
    private double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }
    
    /**
     * Convertit l'état en un vecteur de caractéristiques pour l'apprentissage
     * @return un tableau de valeurs représentant l'état
     */
    public double[] toFeatureVector() {
        double[] features = new double[6];
        features[0] = connectionRate;
        features[1] = portDiversity;
        features[2] = bandwidth;
        features[3] = attackProbability;
        features[4] = consecutiveAlerts;
        features[5] = attackTypeIndex / 10.0; // Normalisation
        return features;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        
        State state = (State) o;
        
        // Comparaison approximative pour les doubles
        if (Math.abs(state.connectionRate - connectionRate) > 0.001) return false;
        if (Math.abs(state.portDiversity - portDiversity) > 0.001) return false;
        if (Math.abs(state.bandwidth - bandwidth) > 0.001) return false;
        if (Math.abs(state.attackProbability - attackProbability) > 0.001) return false;
        if (Math.abs(state.consecutiveAlerts - consecutiveAlerts) > 0.001) return false;
        return state.attackTypeIndex == attackTypeIndex;
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(toFeatureVector());
    }
    
    @Override
    public String toString() {
        return String.format("État [connexions=%.2f, ports=%.2f, bande_passante=%.2f, proba_attaque=%.2f, alertes_consécutives=%.2f, type=%d]",
                connectionRate, portDiversity, bandwidth, attackProbability, consecutiveAlerts, attackTypeIndex);
    }
}
