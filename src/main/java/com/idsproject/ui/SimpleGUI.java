package main.java.com.idsproject.ui;

import main.java.com.idsproject.detection.Alert;
import main.java.com.idsproject.detection.IDS;
import main.java.com.idsproject.network.TrafficSimulator;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/**
 * Interface graphique simple pour le système de détection d'intrusion.
 * Fournit une visualisation en temps réel des alertes et des contrôles pour la simulation.
 */
public class SimpleGUI implements IDS.AlertListener {

    private final IDS ids;
    private final TrafficSimulator trafficSimulator;
    private final List<Alert> alerts;
    
    // Composants de l'interface graphique
    private JFrame frame;
    private JTextArea logArea;
    private JLabel statusLabel;
    private JLabel statsLabel;
    private JButton startStopButton;
    private JButton dosButton;
    private JButton portScanButton;
    private JButton bruteForceButton;
    
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
    
    /**
     * Constructeur initialisant l'interface graphique
     * @param ids le système de détection d'intrusion
     * @param trafficSimulator le simulateur de trafic
     */
    public SimpleGUI(IDS ids, TrafficSimulator trafficSimulator) {
        this.ids = ids;
        this.trafficSimulator = trafficSimulator;
        this.alerts = new CopyOnWriteArrayList<>();
        
        // S'enregistre comme écouteur d'alertes
        ids.addAlertListener(this);
    }
    
    /**
     * Crée et affiche l'interface graphique
     */
    public void display() {
        // Crée le frame Swing dans l'EDT (Event Dispatch Thread)
        SwingUtilities.invokeLater(() -> {
            createFrame();
            updateStats(); // Met à jour les statistiques initiales
            
            // Démarre un thread pour mettre à jour les statistiques périodiquement
            Thread statsThread = new Thread(this::statsUpdateLoop);
            statsThread.setDaemon(true);
            statsThread.start();
        });
    }
    
    /**
     * Crée le frame principal et ses composants
     */
    private void createFrame() {
        frame = new JFrame("Système de Détection d'Intrusion avec Apprentissage par Renforcement");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(900, 600);
        frame.setLocationRelativeTo(null); // Centre la fenêtre
        
        // Gestion de la fermeture propre
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (trafficSimulator.isRunning()) {
                    trafficSimulator.stopSimulation();
                }
                System.exit(0);
            }
        });
        
        // Crée le panneau principal avec une bordure
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Panneau supérieur avec titre et statuts
        JPanel topPanel = createTopPanel();
        mainPanel.add(topPanel, BorderLayout.NORTH);
        
        // Panneau central avec la zone de log
        JPanel centerPanel = createCenterPanel();
        mainPanel.add(centerPanel, BorderLayout.CENTER);
        
        // Panneau inférieur avec les boutons de contrôle
        JPanel bottomPanel = createBottomPanel();
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        frame.add(mainPanel);
        frame.setVisible(true);
    }
    
    /**
     * Crée le panneau supérieur avec le titre et les informations de statut
     * @return le panneau supérieur
     */
    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        
        // Titre
        JLabel titleLabel = new JLabel("Système de Détection d'Intrusion avec RL");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        panel.add(titleLabel, BorderLayout.NORTH);
        
        // Panneau de statut
        JPanel statusPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        
        // Statut de la simulation
        statusLabel = new JLabel("Simulation: Arrêtée");
        statusLabel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Statut"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));
        statusPanel.add(statusLabel);
        
        // Statistiques
        statsLabel = new JLabel("Paquets: 0 | Alertes: 0 | Précision: 0%");
        statsLabel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Statistiques"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));
        statusPanel.add(statsLabel);
        
        panel.add(statusPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Crée le panneau central avec la zone de log
     * @return le panneau central
     */
    private JPanel createCenterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Zone de log
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        
        // Défilement automatique
        DefaultCaret caret = (DefaultCaret) logArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Journal des événements"));
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Crée le panneau inférieur avec les boutons de contrôle
     * @return le panneau inférieur
     */
    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 2, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        
        // Bouton Démarrer/Arrêter
        startStopButton = new JButton("Démarrer simulation");
        startStopButton.addActionListener(e -> toggleSimulation());
        
        // Bouton Simuler DoS
        dosButton = new JButton("Simuler attaque DoS");
        dosButton.setEnabled(false);
        dosButton.addActionListener(e -> simulateDoSAttack());
        
        // Bouton Simuler scan de ports
        portScanButton = new JButton("Simuler scan de ports");
        portScanButton.setEnabled(false);
        portScanButton.addActionListener(e -> simulatePortScan());
        
        // Bouton Simuler force brute
        bruteForceButton = new JButton("Simuler attaque par force brute");
        bruteForceButton.setEnabled(false);
        bruteForceButton.addActionListener(e -> simulateBruteForce());
        
        panel.add(startStopButton);
        panel.add(dosButton);
        panel.add(portScanButton);
        panel.add(bruteForceButton);
        
        return panel;
    }
    
    /**
     * Démarre ou arrête la simulation
     */
    private void toggleSimulation() {
        if (trafficSimulator.isRunning()) {
            // Arrêter la simulation
            trafficSimulator.stopSimulation();
            startStopButton.setText("Démarrer simulation");
            statusLabel.setText("Simulation: Arrêtée");
            dosButton.setEnabled(false);
            portScanButton.setEnabled(false);
            bruteForceButton.setEnabled(false);
            log("Simulation arrêtée");
        } else {
            // Démarrer la simulation
            trafficSimulator.startSimulation();
            startStopButton.setText("Arrêter simulation");
            statusLabel.setText("Simulation: En cours");
            dosButton.setEnabled(true);
            portScanButton.setEnabled(true);
            bruteForceButton.setEnabled(true);
            log("Simulation démarrée - Trafic réseau normal");
        }
    }
    
    /**
     * Simule une attaque par déni de service
     */
    private void simulateDoSAttack() {
        // Crée une boîte de dialogue pour configurer l'attaque
        JTextField hostField = new JTextField("localhost");
        JTextField portField = new JTextField("80");
        JTextField intensityField = new JTextField("100");
        
        JPanel panel = new JPanel(new GridLayout(0, 1));
        panel.add(new JLabel("Hôte cible:"));
        panel.add(hostField);
        panel.add(new JLabel("Port cible:"));
        panel.add(portField);
        panel.add(new JLabel("Intensité (nombre de connexions):"));
        panel.add(intensityField);
        
        int result = JOptionPane.showConfirmDialog(frame, panel, 
                "Configuration de l'attaque DoS", JOptionPane.OK_CANCEL_OPTION);
        
        if (result == JOptionPane.OK_OPTION) {
            try {
                String host = hostField.getText();
                int port = Integer.parseInt(portField.getText());
                int intensity = Integer.parseInt(intensityField.getText());
                
                log("Simulation d'une attaque DoS vers " + host + ":" + port + 
                        " avec " + intensity + " connexions");
                trafficSimulator.simulateDoSAttack(host, port, intensity);
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(frame, 
                        "Valeurs numériques invalides", 
                        "Erreur", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Simule un scan de ports
     */
    private void simulatePortScan() {
        // Crée une boîte de dialogue pour configurer le scan
        JTextField hostField = new JTextField("localhost");
        JTextField startPortField = new JTextField("1");
        JTextField endPortField = new JTextField("100");
        
        JPanel panel = new JPanel(new GridLayout(0, 1));
        panel.add(new JLabel("Hôte cible:"));
        panel.add(hostField);
        panel.add(new JLabel("Port de début:"));
        panel.add(startPortField);
        panel.add(new JLabel("Port de fin:"));
        panel.add(endPortField);
        
        int result = JOptionPane.showConfirmDialog(frame, panel, 
                "Configuration du scan de ports", JOptionPane.OK_CANCEL_OPTION);
        
        if (result == JOptionPane.OK_OPTION) {
            try {
                String host = hostField.getText();
                int startPort = Integer.parseInt(startPortField.getText());
                int endPort = Integer.parseInt(endPortField.getText());
                
                log("Simulation d'un scan de ports sur " + host + 
                        " des ports " + startPort + " à " + endPort);
                trafficSimulator.simulatePortScan(host, startPort, endPort);
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(frame, 
                        "Valeurs numériques invalides", 
                        "Erreur", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Simule une attaque par force brute
     */
    private void simulateBruteForce() {
        // Crée une boîte de dialogue pour configurer l'attaque
        JTextField hostField = new JTextField("localhost");
        JTextField portField = new JTextField("22");
        JTextField attemptsField = new JTextField("50");
        
        JPanel panel = new JPanel(new GridLayout(0, 1));
        panel.add(new JLabel("Hôte cible:"));
        panel.add(hostField);
        panel.add(new JLabel("Port cible (22=SSH, 3306=MySQL, etc.):"));
        panel.add(portField);
        panel.add(new JLabel("Nombre de tentatives:"));
        panel.add(attemptsField);
        
        int result = JOptionPane.showConfirmDialog(frame, panel, 
                "Configuration de l'attaque par force brute", JOptionPane.OK_CANCEL_OPTION);
        
        if (result == JOptionPane.OK_OPTION) {
            try {
                String host = hostField.getText();
                int port = Integer.parseInt(portField.getText());
                int attempts = Integer.parseInt(attemptsField.getText());
                
                log("Simulation d'une attaque par force brute vers " + host + ":" + port + 
                        " avec " + attempts + " tentatives");
                trafficSimulator.simulateBruteForce(host, port, attempts);
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(frame, 
                        "Valeurs numériques invalides", 
                        "Erreur", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Ajoute une entrée au journal des événements
     * @param message le message à journaliser
     */
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = timeFormat.format(new Date());
            logArea.append("[" + timestamp + "] " + message + "\n");
        });
    }
    
    /**
     * Met à jour les statistiques affichées
     */
    private void updateStats() {
        int packetsAnalyzed = ids.getTotalPacketsAnalyzed();
        int alertsGenerated = ids.getAlertsGenerated();
        
        // Calcule la précision
        double accuracy = 0.0;
        if (alertsGenerated > 0) {
            int falsePositives = ids.getFalsePositives();
            int falseNegatives = ids.getFalseNegatives();
            double correctAlerts = alertsGenerated - falsePositives;
            accuracy = (correctAlerts / alertsGenerated) * 100;
            
            // Ajuste pour les faux négatifs
            if (falseNegatives > 0) {
                accuracy = accuracy * (1 - (falseNegatives / (double)(falseNegatives + alertsGenerated)));
            }
        } else {
            accuracy = 100.0;
        }
        
        String statsText = String.format("Paquets: %d | Alertes: %d | Précision: %.1f%%",
                packetsAnalyzed, alertsGenerated, accuracy);
        
        SwingUtilities.invokeLater(() -> {
            statsLabel.setText(statsText);
        });
    }
    
    /**
     * Boucle de mise à jour des statistiques
     */
    private void statsUpdateLoop() {
        while (true) {
            try {
                Thread.sleep(2000); // Mise à jour toutes les 2 secondes
                updateStats();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    /**
     * Méthode appelée lorsqu'une alerte est générée
     * @param alert l'alerte générée
     */
    @Override
    public void onAlertGenerated(Alert alert) {
        alerts.add(alert);
        log("*** ALERTE *** " + alert.toString());
    }
}
