package main.java.com.idsproject.network;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Classe pour simuler différents types de trafic réseau, incluant du trafic normal et des attaques.
 * Cette classe est utile pour tester et former le système de détection d'intrusion.
 */
public class TrafficSimulator {
    
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final ExecutorService executorService;
    private final Random random = new Random();
    
    // Paramètres de simulation
    private final String[] localHosts = {"127.0.0.1", "localhost"};
    private final int[] commonPorts = {80, 443, 22, 21, 25, 3306, 8080, 8443};
    
    /**
     * Constructeur initialisant le simulateur de trafic
     */
    public TrafficSimulator() {
        this.executorService = Executors.newFixedThreadPool(5);
    }
    
    /**
     * Démarre la simulation de trafic
     */
    public void startSimulation() {
        if (isRunning.compareAndSet(false, true)) {
            System.out.println("Démarrage de la simulation de trafic...");
            simulateNormalTraffic();
        }
    }
    
    /**
     * Simule une attaque par déni de service (DoS)
     * @param targetHost l'hôte cible de l'attaque
     * @param targetPort le port cible de l'attaque
     * @param intensity l'intensité de l'attaque (nombre de connexions)
     */
    public void simulateDoSAttack(String targetHost, int targetPort, int intensity) {
        if (!isRunning.get()) {
            System.out.println("La simulation n'est pas en cours. Démarrez-la d'abord.");
            return;
        }
        
        System.out.println("Simulation d'une attaque DoS vers " + targetHost + ":" + targetPort + 
                " avec une intensité de " + intensity);
        
        executorService.submit(() -> {
            try {
                for (int i = 0; i < intensity && isRunning.get(); i++) {
                    try {
                        Socket socket = new Socket(targetHost, targetPort);
                        // Fermer immédiatement pour simuler une connexion rapide typique des attaques DoS
                        socket.close();
                    } catch (IOException e) {
                        // Ignorer les erreurs car c'est une simulation
                    }
                    
                    // Petite pause entre les connexions
                    Thread.sleep(10);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
    
    /**
     * Simule un scan de ports
     * @param targetHost l'hôte cible du scan
     * @param startPort le port de début pour le scan
     * @param endPort le port de fin pour le scan
     */
    public void simulatePortScan(String targetHost, int startPort, int endPort) {
        if (!isRunning.get()) {
            System.out.println("La simulation n'est pas en cours. Démarrez-la d'abord.");
            return;
        }
        
        System.out.println("Simulation d'un scan de ports sur " + targetHost + 
                " des ports " + startPort + " à " + endPort);
        
        executorService.submit(() -> {
            for (int port = startPort; port <= endPort && isRunning.get(); port++) {
                try {
                    Socket socket = new Socket(targetHost, port);
                    System.out.println("Port " + port + " est ouvert");
                    socket.close();
                } catch (IOException e) {
                    // Port fermé ou inaccessible, c'est normal dans un scan
                }
                
                try {
                    // Pause entre les tentatives de connexion
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
    }
    
    /**
     * Simule une attaque de force brute sur un service spécifique
     * @param targetHost l'hôte cible
     * @param targetPort le port cible (généralement 22 pour SSH, 3306 pour MySQL, etc.)
     * @param attempts le nombre de tentatives de connexion
     */
    public void simulateBruteForce(String targetHost, int targetPort, int attempts) {
        if (!isRunning.get()) {
            System.out.println("La simulation n'est pas en cours. Démarrez-la d'abord.");
            return;
        }
        
        System.out.println("Simulation d'une attaque par force brute vers " + 
                targetHost + ":" + targetPort + " avec " + attempts + " tentatives");
        
        executorService.submit(() -> {
            try {
                for (int i = 0; i < attempts && isRunning.get(); i++) {
                    try {
                        Socket socket = new Socket(targetHost, targetPort);
                        // Dans une vraie attaque, on enverrait des données d'authentification
                        // Ici on se contente de simuler la connexion
                        Thread.sleep(200); // Simuler une tentative d'authentification
                        socket.close();
                    } catch (IOException e) {
                        // Ignorer les erreurs car c'est une simulation
                    }
                    
                    // Pause entre les tentatives
                    Thread.sleep(300);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
    
    /**
     * Simule un trafic réseau normal avec des connexions aléatoires
     */
    private void simulateNormalTraffic() {
        if (!isRunning.get()) {
            return;
        }
        
        System.out.println("Simulation de trafic réseau normal...");
        
        executorService.submit(() -> {
            try {
                while (isRunning.get()) {
                    // Sélectionne un hôte et un port aléatoire
                    String host = localHosts[random.nextInt(localHosts.length)];
                    int port = commonPorts[random.nextInt(commonPorts.length)];
                    
                    try {
                        Socket socket = new Socket(host, port);
                        // Simuler un échange de données normal
                        Thread.sleep(random.nextInt(500) + 100);
                        socket.close();
                    } catch (IOException e) {
                        // Ignorer les erreurs car c'est une simulation
                    }
                    
                    // Pause entre les connexions normales
                    Thread.sleep(random.nextInt(2000) + 1000);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
    
    /**
     * Arrête la simulation de trafic
     */
    public void stopSimulation() {
        if (isRunning.compareAndSet(true, false)) {
            System.out.println("Arrêt de la simulation de trafic...");
            executorService.shutdown();
        }
    }
    
    /**
     * Vérifie si la simulation est en cours
     * @return true si la simulation est en cours, false sinon
     */
    public boolean isRunning() {
        return isRunning.get();
    }
}
