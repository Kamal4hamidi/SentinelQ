package main.java.com.idsproject.ui;

import main.java.com.idsproject.detection.Alert;
import main.java.com.idsproject.detection.IDS;
import main.java.com.idsproject.network.TrafficSimulator;

import java.util.Scanner;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Interface utilisateur en console pour interagir avec le système de détection d'intrusion.
 * Permet à l'utilisateur de contrôler la simulation et de voir les alertes en temps réel.
 */
public class ConsoleUI implements IDS.AlertListener {

    private final IDS ids;
    private final TrafficSimulator trafficSimulator;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Scanner scanner;
    
    /**
     * Constructeur initialisant l'interface console
     * @param ids le système de détection d'intrusion
     * @param trafficSimulator le simulateur de trafic
     */
    public ConsoleUI(IDS ids, TrafficSimulator trafficSimulator) {
        this.ids = ids;
        this.trafficSimulator = trafficSimulator;
        this.scanner = new Scanner(System.in);
        
        // S'enregistre comme écouteur d'alertes
        ids.addAlertListener(this);
    }
    
    /**
     * Démarre l'interface utilisateur en console
     */
    public void start() {
        running.set(true);
        printWelcomeMessage();
        
        // Démarre un thread pour l'interface utilisateur
        Thread uiThread = new Thread(this::runCommandLoop);
        uiThread.setDaemon(true);
        uiThread.start();
    }
    
    /**
     * Affiche le message de bienvenue avec les instructions
     */
    private void printWelcomeMessage() {
        System.out.println("=====================================================");
        System.out.println("  SYSTÈME DE DÉTECTION D'INTRUSION AVEC RL");
        System.out.println("=====================================================");
        System.out.println("Commandes disponibles :");
        System.out.println("  1 - Démarrer la simulation de trafic normal");
        System.out.println("  2 - Simuler une attaque DoS");
        System.out.println("  3 - Simuler un scan de ports");
        System.out.println("  4 - Simuler une attaque par force brute");
        System.out.println("  5 - Afficher les statistiques");
        System.out.println("  6 - Quitter");
        System.out.println("=====================================================");
    }
    
    /**
     * Boucle principale de traitement des commandes utilisateur
     */
    private void runCommandLoop() {
        while (running.get()) {
            System.out.print("\nEntrez une commande (1-6) : ");
            String input = scanner.nextLine().trim();
            
            try {
                int command = Integer.parseInt(input);
                processCommand(command);
            } catch (NumberFormatException e) {
                System.out.println("Commande invalide. Veuillez entrer un nombre entre 1 et 6.");
            }
        }
    }
    
    /**
     * Traite la commande entrée par l'utilisateur
     * @param command le numéro de commande
     */
    private void processCommand(int command) {
        switch (command) {
            case 1:
                startNormalTrafficSimulation();
                break;
            case 2:
                simulateDoSAttack();
                break;
            case 3:
                simulatePortScan();
                break;
            case 4:
                simulateBruteForce();
                break;
            case 5:
                displayStatistics();
                break;
            case 6:
                exit();
                break;
            default:
                System.out.println("Commande inconnue. Veuillez entrer un nombre entre 1 et 6.");
        }
    }
    
    /**
     * Démarre la simulation de trafic normal
     */
    private void startNormalTrafficSimulation() {
        if (!trafficSimulator.isRunning()) {
            System.out.println("Démarrage de la simulation de trafic normal...");
            trafficSimulator.startSimulation();
        } else {
            System.out.println("La simulation est déjà en cours.");
        }
    }
    
    /**
     * Simule une attaque par déni de service
     */
    private void simulateDoSAttack() {
        if (!trafficSimulator.isRunning()) {
            System.out.println("Veuillez d'abord démarrer la simulation de trafic (commande 1).");
            return;
        }
        
        System.out.print("Entrez l'hôte cible (localhost par défaut) : ");
        String host = scanner.nextLine().trim();
        if (host.isEmpty()) {
            host = "localhost";
        }
        
        System.out.print("Entrez le port cible (80 par défaut) : ");
        String portStr = scanner.nextLine().trim();
        int port = portStr.isEmpty() ? 80 : Integer.parseInt(portStr);
        
        System.out.print("Entrez l'intensité de l'attaque (nombre de connexions, 100 par défaut) : ");
        String intensityStr = scanner.nextLine().trim();
        int intensity = intensityStr.isEmpty() ? 100 : Integer.parseInt(intensityStr);
        
        System.out.println("Simulation d'une attaque DoS vers " + host + ":" + port + 
                " avec " + intensity + " connexions...");
        trafficSimulator.simulateDoSAttack(host, port, intensity);
    }
    
    /**
     * Simule un scan de ports
     */
    private void simulatePortScan() {
        if (!trafficSimulator.isRunning()) {
            System.out.println("Veuillez d'abord démarrer la simulation de trafic (commande 1).");
            return;
        }
        
        System.out.print("Entrez l'hôte cible (localhost par défaut) : ");
        String host = scanner.nextLine().trim();
        if (host.isEmpty()) {
            host = "localhost";
        }
        
        System.out.print("Entrez le port de début (1 par défaut) : ");
        String startPortStr = scanner.nextLine().trim();
        int startPort = startPortStr.isEmpty() ? 1 : Integer.parseInt(startPortStr);
        
        System.out.print("Entrez le port de fin (100 par défaut) : ");
        String endPortStr = scanner.nextLine().trim();
        int endPort = endPortStr.isEmpty() ? 100 : Integer.parseInt(endPortStr);
        
        System.out.println("Simulation d'un scan de ports sur " + host + 
                " des ports " + startPort + " à " + endPort + "...");
        trafficSimulator.simulatePortScan(host, startPort, endPort);
    }
    
    /**
     * Simule une attaque par force brute
     */
    private void simulateBruteForce() {
        if (!trafficSimulator.isRunning()) {
            System.out.println("Veuillez d'abord démarrer la simulation de trafic (commande 1).");
            return;
        }
        
        System.out.print("Entrez l'hôte cible (localhost par défaut) : ");
        String host = scanner.nextLine().trim();
        if (host.isEmpty()) {
            host = "localhost";
        }
        
        System.out.print("Entrez le port cible (22 par défaut pour SSH) : ");
        String portStr = scanner.nextLine().trim();
        int port = portStr.isEmpty() ? 22 : Integer.parseInt(portStr);
        
        System.out.print("Entrez le nombre de tentatives (50 par défaut) : ");
        String attemptsStr = scanner.nextLine().trim();
        int attempts = attemptsStr.isEmpty() ? 50 : Integer.parseInt(attemptsStr);
        
        System.out.println("Simulation d'une attaque par force brute vers " + host + ":" + port + 
                " avec " + attempts + " tentatives...");
        trafficSimulator.simulateBruteForce(host, port, attempts);
    }
    
    /**
     * Affiche les statistiques du système de détection d'intrusion
     */
    private void displayStatistics() {
        System.out.println("\n=====================================================");
        System.out.println("  STATISTIQUES DU SYSTÈME");
        System.out.println("=====================================================");
        System.out.println("Paquets analysés : " + ids.getTotalPacketsAnalyzed());
        System.out.println("Alertes générées : " + ids.getAlertsGenerated());
        System.out.println("Faux positifs    : " + ids.getFalsePositives());
        System.out.println("Faux négatifs    : " + ids.getFalseNegatives());
        System.out.println("Précision        : " + calculateAccuracy() + "%");
        System.out.println("=====================================================");
    }
    
    /**
     * Calcule la précision du système de détection
     * @return la précision en pourcentage
     */
    private double calculateAccuracy() {
        int totalAlerts = ids.getAlertsGenerated();
        int falsePositives = ids.getFalsePositives();
        int falseNegatives = ids.getFalseNegatives();
        
        if (totalAlerts == 0) {
            return 100.0;
        }
        
        // Calcule la précision comme le pourcentage d'alertes correctes
        double correctAlerts = totalAlerts - falsePositives;
        double accuracy = (correctAlerts / totalAlerts) * 100;
        
        // Ajuste pour les faux négatifs
        if (falseNegatives > 0) {
            accuracy = accuracy * (1 - (falseNegatives / (double)(falseNegatives + totalAlerts)));
        }
        
        return Math.round(accuracy * 100) / 100.0;
    }
    
    /**
     * Quitte l'application
     */
    private void exit() {
        System.out.println("Arrêt du système...");
        running.set(false);
        
        // Arrêt propre des composants
        if (trafficSimulator.isRunning()) {
            trafficSimulator.stopSimulation();
        }
        
        System.out.println("Au revoir !");
    }
    
    /**
     * Méthode appelée lorsqu'une alerte est générée
     * @param alert l'alerte générée
     */
    @Override
    public void onAlertGenerated(Alert alert) {
        System.out.println("\n*** ALERTE ***");
        System.out.println(alert.toString());
    }
}