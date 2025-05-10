package main.java.com.idsproject.network;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.net.InetAddress;

/**
 * Classe responsable de l'analyse des paquets réseau pour détecter des comportements suspects.
 * Cette classe utilise diverses techniques pour identifier les motifs d'attaque potentiels.
 */
public class PacketAnalyzer {
    
    // Fenêtre de temps pour l'analyse (en millisecondes)
    private static final long TIME_WINDOW = 10000; // 10 secondes
    
    // Seuils de détection
    private static final int CONNECTION_THRESHOLD = 50; // Nombre de connexions par fenêtre de temps
    private static final int PORT_SCAN_THRESHOLD = 15; // Nombre de ports différents scannés
    private static final int BANDWIDTH_THRESHOLD = 10000000; // 10 MB/s
    
    // Stockage des statistiques par adresse IP
    private final Map<InetAddress, HostStats> hostStatsMap = new ConcurrentHashMap<>();
    
    /**
     * Analyse un paquet réseau et détermine s'il fait partie d'une activité suspecte
     * 
     * @param packet Le paquet réseau à analyser
     * @return Un objet AnalysisResult contenant le résultat de l'analyse
     */
    public AnalysisResult analyzePacket(NetworkMonitor.NetworkPacket packet) {
        InetAddress sourceAddress = packet.getSourceAddress();
        
        // Obtient ou crée les statistiques pour cette adresse
        HostStats stats = hostStatsMap.computeIfAbsent(
            sourceAddress, k -> new HostStats());
        
        // Met à jour les statistiques
        stats.addPacket(packet);
        
        // Vérifie les différents types d'attaques potentielles
        boolean isDosAttack = checkForDosAttack(stats);
        boolean isPortScan = checkForPortScan(stats);
        boolean isBandwidthAbuse = checkForBandwidthAbuse(stats);
        
        // Nettoie les anciennes entrées
        cleanupOldEntries();
        
        // Construit le résultat de l'analyse
        AnalysisResult result = new AnalysisResult();
        
        if (isDosAttack) {
            result.setAttackDetected(true);
            result.setAttackType("DoS");
            result.setConfidence(calculateConfidence(stats, "DoS"));
            result.setDescription("Attaque par déni de service détectée - " + 
                    stats.getConnectionCount() + " connexions en " + 
                    (TIME_WINDOW / 1000) + " secondes");
        } else if (isPortScan) {
            result.setAttackDetected(true);
            result.setAttackType("PortScan");
            result.setConfidence(calculateConfidence(stats, "PortScan"));
            result.setDescription("Scan de ports détecté - " + 
                    stats.getUniqueDestinationPorts() + " ports scannés");
        } else if (isBandwidthAbuse) {
            result.setAttackDetected(true);
            result.setAttackType("BandwidthAbuse");
            result.setConfidence(calculateConfidence(stats, "BandwidthAbuse"));
            result.setDescription("Abus de bande passante détecté - " + 
                    (stats.getBandwidth() / 1000000) + " MB/s");
        } else {
            result.setAttackDetected(false);
            result.setAttackType("None");
            result.setConfidence(1.0); // Confiance maximale qu'il n'y a pas d'attaque
            result.setDescription("Trafic normal");
        }
        
        result.setSourceAddress(sourceAddress);
        return result;
    }
    
    /**
     * Vérifie si les statistiques d'un hôte indiquent une attaque par déni de service
     */
    private boolean checkForDosAttack(HostStats stats) {
        return stats.getConnectionCount() > CONNECTION_THRESHOLD;
    }
    
    /**
     * Vérifie si les statistiques d'un hôte indiquent un scan de ports
     */
    private boolean checkForPortScan(HostStats stats) {
        return stats.getUniqueDestinationPorts() > PORT_SCAN_THRESHOLD;
    }
    
    /**
     * Vérifie si les statistiques d'un hôte indiquent un abus de bande passante
     */
    private boolean checkForBandwidthAbuse(HostStats stats) {
        return stats.getBandwidth() > BANDWIDTH_THRESHOLD;
    }
    
    /**
     * Calcule un niveau de confiance pour la détection
     */
    private double calculateConfidence(HostStats stats, String attackType) {
        switch (attackType) {
            case "DoS":
                // Plus le nombre de connexions dépasse le seuil, plus la confiance est élevée
                return Math.min(1.0, (stats.getConnectionCount() - CONNECTION_THRESHOLD) / 
                        (double)(CONNECTION_THRESHOLD * 2));
                
            case "PortScan":
                // Plus le nombre de ports scannés dépasse le seuil, plus la confiance est élevée
                return Math.min(1.0, (stats.getUniqueDestinationPorts() - PORT_SCAN_THRESHOLD) / 
                        (double)(PORT_SCAN_THRESHOLD * 2));
                
            case "BandwidthAbuse":
                // Plus la bande passante dépasse le seuil, plus la confiance est élevée
                return Math.min(1.0, (stats.getBandwidth() - BANDWIDTH_THRESHOLD) / 
                        (double)(BANDWIDTH_THRESHOLD * 2));
                
            default:
                return 0.5; // Valeur par défaut
        }
    }
    
    /**
     * Nettoie les entrées trop anciennes pour être pertinentes
     */
    private void cleanupOldEntries() {
        long currentTime = System.currentTimeMillis();
        hostStatsMap.entrySet().removeIf(entry -> {
            return currentTime - entry.getValue().getLastPacketTime() > TIME_WINDOW * 2;
        });
    }
    
    /**
     * Classe interne pour stocker les statistiques d'un hôte
     */
    private static class HostStats {
        private final AtomicInteger connectionCount = new AtomicInteger(0);
        private final Map<Integer, Boolean> destinationPorts = new HashMap<>();
        private long totalBytes = 0;
        private long firstPacketTime = 0;
        private long lastPacketTime = 0;
        
        public void addPacket(NetworkMonitor.NetworkPacket packet) {
            long currentTime = System.currentTimeMillis();
            
            if (firstPacketTime == 0) {
                firstPacketTime = currentTime;
            }
            
            connectionCount.incrementAndGet();
            destinationPorts.put(packet.getDestinationPort(), true);
            totalBytes += packet.getSize();
            lastPacketTime = currentTime;
        }
        
        public int getConnectionCount() {
            return connectionCount.get();
        }
        
        public int getUniqueDestinationPorts() {
            return destinationPorts.size();
        }
        
        public long getBandwidth() {
            long timespan = lastPacketTime - firstPacketTime;
            if (timespan <= 0) return 0;
            
            // Bande passante en octets par seconde
            return (totalBytes * 1000) / timespan;
        }
        
        public long getLastPacketTime() {
            return lastPacketTime;
        }
    }
    
    /**
     * Classe représentant le résultat d'une analyse de paquet
     */
    public static class AnalysisResult {
        private boolean attackDetected;
        private String attackType;
        private double confidence;
        private String description;
        private InetAddress sourceAddress;
        
        // Getters and setters
        public boolean isAttackDetected() { return attackDetected; }
        public void setAttackDetected(boolean attackDetected) { this.attackDetected = attackDetected; }
        
        public String getAttackType() { return attackType; }
        public void setAttackType(String attackType) { this.attackType = attackType; }
        
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        
        public InetAddress getSourceAddress() { return sourceAddress; }
        public void setSourceAddress(InetAddress sourceAddress) { this.sourceAddress = sourceAddress; }
        
        @Override
        public String toString() {
            return String.format("%s [type=%s, confiance=%.2f%%] - %s",
                    attackDetected ? "ALERTE" : "NORMAL",
                    attackType,
                    confidence * 100,
                    description);
        }
    }
}
