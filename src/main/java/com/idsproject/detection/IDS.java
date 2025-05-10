package main.java.com.idsproject.detection;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.net.InetAddress;

import main.java.com.idsproject.network.NetworkMonitor;
import main.java.com.idsproject.network.PacketAnalyzer;
import main.java.com.idsproject.rl.QLearning;
import main.java.com.idsproject.rl.State;
import main.java.com.idsproject.rl.Action;

/**
 * Classe principale du Système de Détection d'Intrusion (IDS).
 * Utilise l'apprentissage par renforcement pour améliorer ses décisions au fil du temps.
 */
public class IDS implements NetworkMonitor.PacketListener {

    private final NetworkMonitor networkMonitor;
    private final PacketAnalyzer packetAnalyzer;
    private final QLearning qLearning;
    private final List<AlertListener> alertListeners;
    private final Map<InetAddress, HostState> hostStates;
    
    // Compteurs pour les statistiques
    private int totalPacketsAnalyzed = 0;
    private int alertsGenerated = 0;
    private int falsePositives = 0;
    private int falseNegatives = 0;
    
    /**
     * Constructeur de l'IDS
     * @param networkMonitor le moniteur réseau à utiliser
     * @param qLearning l'algorithme d'apprentissage par renforcement
     */
    public IDS(NetworkMonitor networkMonitor, QLearning qLearning) {
        this.networkMonitor = networkMonitor;
        this.packetAnalyzer = new PacketAnalyzer();
        this.qLearning = qLearning;
        this.alertListeners = new ArrayList<>();
        this.hostStates = new ConcurrentHashMap<>();
        
        // S'enregistre comme écouteur de paquets
        networkMonitor.addPacketListener(this);
    }
    
    /**
     * Méthode appelée lorsqu'un paquet est reçu
     * @param packet le paquet reçu
     */
    @Override
    public void onPacketReceived(NetworkMonitor.NetworkPacket packet) {
        totalPacketsAnalyzed++;
        
        // Analyse le paquet
        PacketAnalyzer.AnalysisResult result = packetAnalyzer.analyzePacket(packet);
        
        // Récupère ou crée l'état de l'hôte
        HostState hostState = hostStates.computeIfAbsent(
                packet.getSourceAddress(), k -> new HostState());
        hostState.updateFeatures(packet, result);
        
        // Convertit l'état de l'hôte en état pour l'apprent
        // Convertit l'état de l'hôte en état pour l'apprentissage par renforcement
        State state = hostState.toRLState();
        
        // Détermine l'action à entreprendre en fonction de l'état actuel
        Action action = qLearning.selectAction(state);
        
        // Exécute l'action sélectionnée
        double reward = executeAction(action, result, packet);
        
        // Met à jour le modèle d'apprentissage par renforcement
        qLearning.update(state, action, reward, state);  // Même état car l'action n'a pas modifié l'état
        
        // Affiche des informations sur le traitement du paquet
        System.out.println("Paquet analysé: " + packet);
        System.out.println("Résultat: " + result);
        System.out.println("Action: " + action + ", Récompense: " + reward);
    }
    
    /**
     * Exécute une action basée sur la décision de l'algorithme d'apprentissage par renforcement
     * @param action l'action à exécuter
     * @param result le résultat de l'analyse du paquet
     * @param packet le paquet réseau analysé
     * @return la récompense associée à l'action entreprise
     */
    private double executeAction(Action action, PacketAnalyzer.AnalysisResult result, NetworkMonitor.NetworkPacket packet) {
        double reward = 0.0;
        
        switch (action) {
            case BLOCK:
                // Bloquer l'adresse IP source (simulé pour ce projet)
                if (result.isAttackDetected() && result.getConfidence() > 0.7) {
                    // Bonne décision de blocage
                    System.out.println("ACTION: Blocage de " + packet.getSourceAddress() + " (haute confiance dans la détection d'attaque)");
                    generateAlert(result, packet, "Blocage");
                    reward = 1.0;
                } else if (result.isAttackDetected()) {
                    // Décision de blocage correcte mais avec une confiance modérée
                    System.out.println("ACTION: Blocage de " + packet.getSourceAddress() + " (confiance modérée dans la détection d'attaque)");
                    generateAlert(result, packet, "Blocage");
                    reward = 0.5;
                } else {
                    // Faux positif - pénalité
                    System.out.println("ACTION: Blocage incorrect de " + packet.getSourceAddress() + " (faux positif)");
                    falsePositives++;
                    reward = -1.0;
                }
                break;
                
            case MONITOR:
                // Surveiller l'adresse IP source
                if (result.isAttackDetected() && result.getConfidence() > 0.3) {
                    // Bonne décision de surveillance pour une attaque potentielle
                    System.out.println("ACTION: Surveillance accrue de " + packet.getSourceAddress());
                    generateAlert(result, packet, "Surveillance");
                    reward = 0.3;
                } else if (!result.isAttackDetected()) {
                    // Bonne décision de surveillance pour un trafic normal
                    reward = 0.1;
                } else {
                    // Attaque avec haute confiance qui aurait dû être bloquée
                    System.out.println("ACTION: Surveillance insuffisante pour une attaque évidente de " + packet.getSourceAddress());
                    falseNegatives++;
                    reward = -0.5;
                }
                break;
                
            case ALLOW:
                // Autoriser le trafic
                if (!result.isAttackDetected()) {
                    // Bonne décision d'autorisation
                    reward = 0.2;
                } else {
                    // Mauvaise décision d'autorisation (attaque non détectée)
                    System.out.println("ACTION: Autorisation incorrecte de " + packet.getSourceAddress() + " (attaque non bloquée)");
                    falseNegatives++;
                    reward = -1.0;
                }
                break;
        }
        
        return reward;
    }
    
    /**
     * Génère une alerte en fonction du résultat de l'analyse
     * @param result le résultat de l'analyse
     * @param packet le paquet concerné
     * @param action l'action entreprise
     */
    private void generateAlert(PacketAnalyzer.AnalysisResult result, NetworkMonitor.NetworkPacket packet, String action) {
        Alert alert = new Alert();
        alert.setSourceAddress(packet.getSourceAddress().getHostAddress());
        alert.setDestinationAddress(packet.getDestinationAddress().getHostAddress());
        alert.setSourcePort(packet.getSourcePort());
        alert.setDestinationPort(packet.getDestinationPort());
        alert.setTimestamp(packet.getTimestamp());
        alert.setAttackType(result.getAttackType());
        alert.setConfidence(result.getConfidence());
        alert.setDescription(result.getDescription());
        alert.setAction(action);
        
        // Notifie tous les écouteurs d'alertes
        for (AlertListener listener : alertListeners) {
            listener.onAlertGenerated(alert);
        }
        
        alertsGenerated++;
    }
    
    /**
     * Ajoute un écouteur d'alertes
     * @param listener l'écouteur à ajouter
     */
    public void addAlertListener(AlertListener listener) {
        alertListeners.add(listener);
    }
    
    /**
     * Retourne le nombre total de paquets analysés
     * @return le nombre de paquets analysés
     */
    public int getTotalPacketsAnalyzed() {
        return totalPacketsAnalyzed;
    }
    
    /**
     * Retourne le nombre d'alertes générées
     * @return le nombre d'alertes
     */
    public int getAlertsGenerated() {
        return alertsGenerated;
    }
    
    /**
     * Retourne le nombre de faux positifs
     * @return le nombre de faux positifs
     */
    public int getFalsePositives() {
        return falsePositives;
    }
    
    /**
     * Retourne le nombre de faux négatifs
     * @return le nombre de faux négatifs
     */
    public int getFalseNegatives() {
        return falseNegatives;
    }
    
    /**
     * Classe interne représentant l'état d'un hôte pour l'apprentissage par renforcement
     */
    private static class HostState {
        private int connectionCount = 0;
        private int uniquePorts = 0;
        private long bandwidth = 0;
        private double lastConfidence = 0.0;
        private String lastAttackType = "None";
        private int consecutiveSuspiciousPackets = 0;
        
        /**
         * Met à jour les caractéristiques de l'état en fonction du paquet et du résultat de l'analyse
         * @param packet le paquet réseau
         * @param result le résultat de l'analyse
         */
        public void updateFeatures(NetworkMonitor.NetworkPacket packet, PacketAnalyzer.AnalysisResult result) {
            connectionCount++;
            uniquePorts = Math.max(uniquePorts, packet.getDestinationPort());
            bandwidth += packet.getSize();
            lastConfidence = result.getConfidence();
            lastAttackType = result.getAttackType();
            
            if (result.isAttackDetected()) {
                consecutiveSuspiciousPackets++;
            } else {
                consecutiveSuspiciousPackets = 0;
            }
        }
        
        /**
         * Convertit l'état de l'hôte en état pour l'apprentissage par renforcement
         * @return l'état pour l'algorithme d'apprentissage par renforcement
         */
        public State toRLState() {
            State state = new State();
            
            // Normalisation des caractéristiques
            state.setConnectionRate(Math.min(1.0, connectionCount / 100.0));
            state.setPortDiversity(Math.min(1.0, uniquePorts / 1000.0));
            state.setBandwidth(Math.min(1.0, bandwidth / 10000000.0)); // 10 MB/s max
            state.setAttackProbability(lastConfidence);
            state.setConsecutiveAlerts(Math.min(1.0, consecutiveSuspiciousPackets / 10.0));
            
            // Encodage one-hot du type d'attaque
            switch (lastAttackType) {
                case "DoS":
                    state.setAttackTypeIndex(1);
                    break;
                case "PortScan":
                    state.setAttackTypeIndex(2);
                    break;
                case "BandwidthAbuse":
                    state.setAttackTypeIndex(3);
                    break;
                default:
                    state.setAttackTypeIndex(0); // None
            }
            
            return state;
        }
    }
    
    /**
     * Interface pour les écouteurs d'alertes
     */
    public interface AlertListener {
        void onAlertGenerated(Alert alert);
    }
}
