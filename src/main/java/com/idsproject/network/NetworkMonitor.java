package main.java.com.idsproject.network;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Classe responsable de la surveillance du trafic réseau.
 * Capture et analyse les paquets réseau en temps réel.
 */
public class NetworkMonitor {
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final ExecutorService executorService;
    private final Map<InetAddress, ConnectionStats> connectionStatsMap;
    private final List<PacketListener> packetListeners;
    private final int[] monitoredPorts = {80, 443, 22, 21, 25, 3306, 8080}; // Ports couramment utilisés
    private ServerSocket serverSocket;
    
    /**
     * Constructeur initialisant le moniteur réseau
     */
    public NetworkMonitor() {
        this.executorService = Executors.newFixedThreadPool(10);
        this.connectionStatsMap = new ConcurrentHashMap<>();
        this.packetListeners = new ArrayList<>();
    }
    
    /**
     * Démarre la surveillance du réseau sur plusieurs threads
     */
    public void startMonitoring() {
        if (isRunning.compareAndSet(false, true)) {
            System.out.println("Démarrage de la surveillance du réseau...");
            
            for (int port : monitoredPorts) {
                startPortMonitoring(port);
            }
            
            // Démarrer un thread pour analyser les statistiques de connexion périodiquement
            executorService.submit(this::analyzeConnectionStats);
        }
    }
    
    /**
     * Démarre la surveillance d'un port spécifique
     * @param port Le port à surveiller
     */
    private void startPortMonitoring(int port) {
        executorService.submit(() -> {
            try {
                serverSocket = new ServerSocket(port);
                System.out.println("Surveillance du port " + port + " démarrée");
                
                while (isRunning.get()) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        handleConnection(clientSocket);
                    } catch (IOException e) {
                        if (isRunning.get()) {
                            System.err.println("Erreur lors de l'acceptation d'une connexion sur le port " + port + ": " + e.getMessage());
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println("Impossible de surveiller le port " + port + ": " + e.getMessage());
                // Tente un port alternatif pour la démonstration
                if (port < 1024) {
                    startPortMonitoring(port + 8000); // Essaye un port non-privilégié
                }
            }
        });
    }
    
    /**
     * Gère une nouvelle connexion
     * @param clientSocket La socket du client
     */
    private void handleConnection(Socket clientSocket) {
        executorService.submit(() -> {
            try {
                InetAddress clientAddress = clientSocket.getInetAddress();
                int clientPort = clientSocket.getPort();
                
                // Crée ou met à jour les statistiques pour cette adresse IP
                ConnectionStats stats = connectionStatsMap.computeIfAbsent(
                        clientAddress, k -> new ConnectionStats());
                stats.incrementConnectionCount();
                
                // Crée un objet NetworkPacket pour cette connexion
                NetworkPacket packet = new NetworkPacket(
                        clientAddress,
                        clientSocket.getLocalAddress(),
                        clientPort,
                        clientSocket.getLocalPort(),
                        System.currentTimeMillis(),
                        0 // La taille sera mise à jour lorsque les données seront lues
                );
                
                // Notifie les listeners
                notifyPacketReceived(packet);
                
                // En conditions réelles, on lirait les données du socket ici
                // Pour la simulation, on ferme simplement la connexion
                clientSocket.close();
                
            } catch (IOException e) {
                System.err.println("Erreur lors du traitement de la connexion: " + e.getMessage());
            }
        });
    }
    
    /**
     * Analyse périodiquement les statistiques de connexion pour détecter des comportements suspects
     */
    private void analyzeConnectionStats() {
        while (isRunning.get()) {
            try {
                // Pause entre les analyses
                Thread.sleep(5000);
                
                // Analyse les statistiques
                for (Map.Entry<InetAddress, ConnectionStats> entry : connectionStatsMap.entrySet()) {
                    InetAddress address = entry.getKey();
                    ConnectionStats stats = entry.getValue();
                    
                    // Vérifie les comportements suspects (comme un nombre élevé de connexions)
                    if (stats.getConnectionCount() > 50) { // Seuil arbitraire
                        System.out.println("ALERTE: Comportement suspect détecté de " + address + 
                                " - " + stats.getConnectionCount() + " connexions");
                    }
                    
                    // Réinitialise les compteurs pour la prochaine période
                    stats.resetCounters();
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    /**
     * Arrête la surveillance du réseau
     */
    public void stopMonitoring() {
        if (isRunning.compareAndSet(true, false)) {
            System.out.println("Arrêt de la surveillance du réseau...");
            
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    System.err.println("Erreur lors de la fermeture du socket serveur: " + e.getMessage());
                }
            }
            
            executorService.shutdown();
        }
    }
    
    /**
     * Ajoute un écouteur de paquets
     * @param listener L'écouteur à ajouter
     */
    public void addPacketListener(PacketListener listener) {
        packetListeners.add(listener);
    }
    
    /**
     * Notifie tous les écouteurs qu'un paquet a été reçu
     * @param packet Le paquet reçu
     */
    private void notifyPacketReceived(NetworkPacket packet) {
        for (PacketListener listener : packetListeners) {
            listener.onPacketReceived(packet);
        }
    }
    
    /**
     * Interface pour les écouteurs de paquets
     */
    public interface PacketListener {
        void onPacketReceived(NetworkPacket packet);
    }
    
    /**
     * Classe interne pour représenter un paquet réseau
     */
    public static class NetworkPacket {
        private final InetAddress sourceAddress;
        private final InetAddress destinationAddress;
        private final int sourcePort;
        private final int destinationPort;
        private final long timestamp;
        private long size;
        private final Map<String, Object> metadata;
        
        public NetworkPacket(InetAddress sourceAddress, InetAddress destinationAddress, 
                            int sourcePort, int destinationPort, long timestamp, long size) {
            this.sourceAddress = sourceAddress;
            this.destinationAddress = destinationAddress;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.timestamp = timestamp;
            this.size = size;
            this.metadata = new HashMap<>();
        }
        
        // Getters
        public InetAddress getSourceAddress() { return sourceAddress; }
        public InetAddress getDestinationAddress() { return destinationAddress; }
        public int getSourcePort() { return sourcePort; }
        public int getDestinationPort() { return destinationPort; }
        public long getTimestamp() { return timestamp; }
        public long getSize() { return size; }
        
        public void setSize(long size) { this.size = size; }
        
        public void addMetadata(String key, Object value) {
            metadata.put(key, value);
        }
        
        public Object getMetadata(String key) {
            return metadata.get(key);
        }
        
        @Override
        public String toString() {
            return String.format("Paquet [%s:%d -> %s:%d, taille=%d octets, horodatage=%d]",
                    sourceAddress.getHostAddress(), sourcePort,
                    destinationAddress.getHostAddress(), destinationPort,
                    size, timestamp);
        }
    }
    
    /**
     * Classe interne pour suivre les statistiques de connexion par adresse IP
     */
    private static class ConnectionStats {
        private int connectionCount;
        
        public void incrementConnectionCount() {
            connectionCount++;
        }
        
        public int getConnectionCount() {
            return connectionCount;
        }
        
        public void resetCounters() {
            connectionCount = 0;
        }
    }
}
