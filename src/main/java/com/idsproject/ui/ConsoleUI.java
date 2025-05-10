package main.java.com.idsproject.ui;

import main.java.com.idsproject.detection.IDS;
import main.java.com.idsproject.network.TrafficSimulator;
import java.util.Scanner;

/**
 * Interface en ligne de commande pour interagir avec le système de détection d'intrusion
 */
public class ConsoleUI {
    private final IDS ids;
    private final TrafficSimulator trafficSimulator;
    private final Scanner scanner;

    public ConsoleUI(IDS ids, TrafficSimulator trafficSimulator) {
        this.ids = ids;
        this.trafficSimulator = trafficSimulator;
        this.scanner = new Scanner(System.in);
    }

    public void start() {
        System.out.println("\n=== Interface Console du Système de Détection d'Intrusion ===");
        
        while (true) {
            printMenu();
            String choice = scanner.nextLine();
            
            switch (choice) {
                case "1":
                    startMonitoring();
                    break;
                case "2":
                    simulateNormalTraffic();
                    break;
                case "3":
                    simulateAttack();
                    break;
                case "4":
                    showStatistics();
                    break;
                case "5":
                    System.out.println("Arrêt du système...");
                    return;
                default:
                    System.out.println("Option invalide. Veuillez réessayer.");
            }
        }
    }

    private void printMenu() {
        System.out.println("\nOptions disponibles:");
        System.out.println("1. Démarrer la surveillance réseau");
        System.out.println("2. Simuler du trafic normal");
        System.out.println("3. Simuler une attaque");
        System.out.println("4. Afficher les statistiques");
        System.out.println("5. Quitter");
        System.out.print("Votre choix: ");
    }

    private void startMonitoring() {
        System.out.println("\nSurveillance réseau démarrée...");
        System.out.println("Appuyez sur Entrée pour arrêter.");
        new Thread(() -> {
            try {
                Thread.sleep(1000); // Simulation de surveillance
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        scanner.nextLine();
    }

    private void simulateNormalTraffic() {
        System.out.print("Durée de simulation (secondes): ");
        int duration = Integer.parseInt(scanner.nextLine());
        trafficSimulator.startSimulation();
        System.out.println("Simulation de trafic normal démarrée pour " + duration + " secondes");
    }

    private void simulateAttack() {
        System.out.println("\nTypes d'attaque disponibles:");
        System.out.println("1. Attaque DoS");
        System.out.println("2. Scan de ports");
        System.out.println("3. Force brute");
        System.out.print("Votre choix: ");
        
        String attackType = scanner.nextLine();
        System.out.print("Adresse IP cible: ");
        String target = scanner.nextLine();
        
        switch (attackType) {
            case "1":
                trafficSimulator.simulateDoSAttack(target, 80, 100);
                break;
            case "2":
                trafficSimulator.simulatePortScan(target, 1, 100);
                break;
            case "3":
                trafficSimulator.simulateBruteForce(target, 22, 50);
                break;
            default:
                System.out.println("Type d'attaque invalide");
        }
    }

    private void showStatistics() {
        System.out.println("\n=== Statistiques ===");
        System.out.println("Paquets analysés: " + ids.getTotalPacketsAnalyzed());
        System.out.println("Alertes générées: " + ids.getAlertsGenerated());
        System.out.println("Faux positifs: " + ids.getFalsePositives());
        System.out.println("Faux négatifs: " + ids.getFalseNegatives());
    }
}