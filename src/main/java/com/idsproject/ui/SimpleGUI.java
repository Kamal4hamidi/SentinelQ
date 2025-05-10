package main.java.com.idsproject.ui;

import main.java.com.idsproject.detection.IDS;
import main.java.com.idsproject.network.TrafficSimulator;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

/**
 * Interface graphique simple pour le système de détection d'intrusion
 */
public class SimpleGUI {
    private final IDS ids;
    private final TrafficSimulator trafficSimulator;
    private JFrame frame;
    private JTextArea logArea;

    public SimpleGUI(IDS ids, TrafficSimulator trafficSimulator) {
        this.ids = ids;
        this.trafficSimulator = trafficSimulator;
    }

    public void display() {
        frame = new JFrame("Système de Détection d'Intrusion");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 600);
        
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Zone de logs
        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Panel de contrôle
        JPanel controlPanel = new JPanel(new GridLayout(1, 4));
        
        JButton startBtn = new JButton("Démarrer surveillance");
        startBtn.addActionListener(this::startMonitoring);
        
        JButton normalBtn = new JButton("Trafic normal");
        normalBtn.addActionListener(this::simulateNormalTraffic);
        
        JButton attackBtn = new JButton("Simuler attaque");
        attackBtn.addActionListener(this::showAttackMenu);
        
        JButton statsBtn = new JButton("Statistiques");
        statsBtn.addActionListener(this::showStatistics);
        
        controlPanel.add(startBtn);
        controlPanel.add(normalBtn);
        controlPanel.add(attackBtn);
        controlPanel.add(statsBtn);
        
        mainPanel.add(controlPanel, BorderLayout.SOUTH);
        frame.add(mainPanel);
        frame.setVisible(true);
    }

    private void startMonitoring(ActionEvent e) {
        logMessage("Surveillance réseau démarrée...");
        new Thread(() -> {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }

    private void simulateNormalTraffic(ActionEvent e) {
        String duration = JOptionPane.showInputDialog(frame, "Durée de simulation (secondes):", "10");
        if (duration != null) {
            trafficSimulator.startSimulation();
            logMessage("Simulation de trafic normal démarrée pour " + duration + " secondes");
        }
    }

    private void showAttackMenu(ActionEvent e) {
        String[] options = {"Attaque DoS", "Scan de ports", "Force brute"};
        String attackType = (String) JOptionPane.showInputDialog(
            frame,
            "Choisissez le type d'attaque:",
            "Simulation d'attaque",
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]);
        
        if (attackType != null) {
            String target = JOptionPane.showInputDialog(frame, "Adresse IP cible:", "127.0.0.1");
            if (target != null) {
                switch (attackType) {
                    case "Attaque DoS":
                        trafficSimulator.simulateDoSAttack(target, 80, 100);
                        logMessage("Attaque DoS simulée vers " + target);
                        break;
                    case "Scan de ports":
                        trafficSimulator.simulatePortScan(target, 1, 100);
                        logMessage("Scan de ports simulé sur " + target);
                        break;
                    case "Force brute":
                        trafficSimulator.simulateBruteForce(target, 22, 50);
                        logMessage("Attaque par force brute simulée sur " + target);
                        break;
                }
            }
        }
    }

    private void showStatistics(ActionEvent e) {
        String stats = String.format(
            "=== Statistiques ===\n" +
            "Paquets analysés: %d\n" +
            "Alertes générées: %d\n" +
            "Faux positifs: %d\n" +
            "Faux négatifs: %d",
            ids.getTotalPacketsAnalyzed(),
            ids.getAlertsGenerated(),
            ids.getFalsePositives(),
            ids.getFalseNegatives());
        
        logMessage(stats);
    }

    private void logMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
}