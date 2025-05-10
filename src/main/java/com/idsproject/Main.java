package main.java.com.idsproject;

import main.java.com.idsproject.detection.IDS;
import main.java.com.idsproject.network.NetworkMonitor;
import main.java.com.idsproject.network.TrafficSimulator;
import main.java.com.idsproject.rl.QLearning;
import main.java.com.idsproject.ui.ConsoleUI;
import main.java.com.idsproject.ui.SimpleGUI;

/**
 * Point d'entrée principal de l'application de Détection d'Intrusion avec Apprentissage par Renforcement.
 * Cette classe initialise tous les composants nécessaires et démarre le système.
 * 
 * @author [Votre Nom]
 * @version 1.0
 */
public class Main {

    private static final boolean USE_GUI = true; // Définir sur false pour utiliser l'interface console

    public static void main(String[] args) {
        System.out.println("Démarrage du Système de Détection d'Intrusion avec Apprentissage par Renforcement...");
        
        // Initialisation des composants
        NetworkMonitor networkMonitor = new NetworkMonitor();
        TrafficSimulator trafficSimulator = new TrafficSimulator();
        QLearning qLearning = new QLearning(0.1, 0.9, 0.3); // alpha, gamma, epsilon
        IDS ids = new IDS(networkMonitor, qLearning);
        
        // Démarrage du moniteur réseau
        networkMonitor.startMonitoring();
        
        // Lancement de l'interface utilisateur
        if (USE_GUI) {
            SimpleGUI gui = new SimpleGUI(ids, trafficSimulator);
            gui.display();
        } else {
            ConsoleUI consoleUI = new ConsoleUI(ids, trafficSimulator);
            consoleUI.start();
        }
        
        System.out.println("Système démarré avec succès.");
    }
}
