package test.java.com.idsproject;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;

/**
 * Générateur de données de test pour le système de détection d'intrusion.
 * Cette classe crée des fichiers CSV simulant du trafic réseau normal et malveillant.
 */
public class TestDataGenerator {

    private static final String NORMAL_TRAFFIC_FILE = "data/normal_traffic.csv";
    private static final String ATTACK_PATTERNS_FILE = "data/attack_patterns.csv";
    private static final String[] LOCAL_IPS = {"192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"};
    private static final String[] EXTERNAL_IPS = {"8.8.8.8", "93.184.216.34", "172.217.22.14", "151.101.0.123", "204.79.197.200"};
    private static final String[] ATTACK_SOURCE_IPS = {"45.227.253.83", "103.9.76.208", "91.134.183.59", "185.156.73.54"};
    private static final int[] COMMON_PORTS = {80, 443, 22, 25, 143, 110, 53, 3306, 8080};
    
    private static final Random random = new Random();
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    /**
     * Point d'entrée pour générer les fichiers de test
     */
    public static void main(String[] args) {
        generateNormalTrafficData(500); // 500 entrées de trafic normal
        generateAttackPatternsData(100); // 100 entrées d'attaques
        System.out.println("Génération des données de test terminée.");
    }
    
    /**
     * Génère un fichier CSV de trafic réseau normal
     * @param count nombre d'entrées à générer
     */
    public static void generateNormalTrafficData(int count) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(NORMAL_TRAFFIC_FILE))) {
            // En-tête du fichier CSV
            writer.write("timestamp,source_ip,destination_ip,source_port,destination_port,protocol,bytes,packets,flags\n");
            
            LocalDateTime timestamp = LocalDateTime.now().minusDays(1);
            
            for (int i = 0; i < count; i++) {
                // Incrémente le timestamp pour chaque entrée
                timestamp = timestamp.plusMinutes(random.nextInt(5)).plusSeconds(random.nextInt(60));
                
                String sourceIp;
                String destinationIp;
                
                // 80% du trafic est local vers externe, 20% externe vers local
                if (random.nextDouble() < 0.8) {
                    sourceIp = LOCAL_IPS[random.nextInt(LOCAL_IPS.length)];
                    destinationIp = EXTERNAL_IPS[random.nextInt(EXTERNAL_IPS.length)];
                } else {
                    sourceIp = EXTERNAL_IPS[random.nextInt(EXTERNAL_IPS.length)];
                    destinationIp = LOCAL_IPS[random.nextInt(LOCAL_IPS.length)];
                }
                
                int sourcePort = 49152 + random.nextInt(16383); // Ports éphémères
                int destinationPort = COMMON_PORTS[random.nextInt(COMMON_PORTS.length)];
                
                // Pour le trafic entrant, inverse les ports
                if (sourceIp.startsWith("192.168.")) {
                    int temp = sourcePort;
                    sourcePort = destinationPort;
                    destinationPort = temp;
                }
                
                String protocol = random.nextDouble() < 0.7 ? "TCP" : "UDP";
                int bytes = random.nextInt(1500) + 40; // Entre 40 et 1540 octets
                int packets = 1 + random.nextInt(4); // Entre 1 et 5 paquets
                
                // Drapeaux TCP (SYN, ACK, etc.)
                String flags = "";
                if (protocol.equals("TCP")) {
                    if (random.nextDouble() < 0.3) flags = "SYN";
                    else if (random.nextDouble() < 0.6) flags = "ACK";
                    else flags = "ACK,PSH";
                }
                
                // Écriture de la ligne
                String line = String.format("%s,%s,%s,%d,%d,%s,%d,%d,%s\n",
                        timestamp.format(formatter),
                        sourceIp,
                        destinationIp,
                        sourcePort,
                        destinationPort,
                        protocol,
                        bytes,
                        packets,
                        flags);
                
                writer.write(line);
            }
            
            System.out.println("Fichier de trafic normal généré : " + NORMAL_TRAFFIC_FILE);
            
        } catch (IOException e) {
            System.err.println("Erreur lors de la génération du fichier de trafic normal : " + e.getMessage());
        }
    }
    
    /**
     * Génère un fichier CSV de motifs d'attaques
     * @param count nombre d'entrées à générer
     */
    public static void generateAttackPatternsData(int count) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(ATTACK_PATTERNS_FILE))) {
            // En-tête du fichier CSV
            writer.write("timestamp,source_ip,destination_ip,source_port,destination_port,protocol,bytes,packets,flags,attack_type,severity\n");
            
            LocalDateTime timestamp = LocalDateTime.now().minusHours(12);
            
            for (int i = 0; i < count; i++) {
                // Incrémente le timestamp pour chaque entrée
                timestamp = timestamp.plusSeconds(random.nextInt(300)); // Max 5 minutes entre les attaques
                
                String sourceIp = ATTACK_SOURCE_IPS[random.nextInt(ATTACK_SOURCE_IPS.length)];
                String destinationIp = LOCAL_IPS[random.nextInt(LOCAL_IPS.length)];
                
                int sourcePort = 49152 + random.nextInt(16383); // Ports éphémères
                int destinationPort;
                
                String protocol;
                String attackType;
                int severity;
                String flags = "";
                int bytes;
                int packets;
                
                // Détermine le type d'attaque
                double attackRand = random.nextDouble();
                if (attackRand < 0.4) {
                    // DoS Attack
                    attackType = "DoS";
                    destinationPort = random.nextDouble() < 0.7 ? 80 : 443; // Cible souvent les serveurs web
                    protocol = random.nextDouble() < 0.8 ? "TCP" : "UDP";
                    severity = 3 + random.nextInt(3); // Sévérité de 3 à 5
                    bytes = 40 + random.nextInt(100); // Paquets de petite taille
                    packets = 10 + random.nextInt(90); // Beaucoup de paquets
                    if (protocol.equals("TCP")) {
                        flags = random.nextDouble() < 0.7 ? "SYN" : "ACK";
                    }
                } else if (attackRand < 0.7) {
                    // Port Scan
                    attackType = "PortScan";
                    destinationPort = random.nextInt(65535); // Scan de ports aléatoire
                    protocol = "TCP";
                    severity = 2 + random.nextInt(2); // Sévérité de 2 à 3
                    bytes = 40 + random.nextInt(20); // Petits paquets SYN
                    packets = 1 + random.nextInt(2); // 1-2 paquets par tentative
                    flags = "SYN";
                } else {
                    // Brute Force
                    attackType = "BruteForce";
                    destinationPort = random.nextDouble() < 0.7 ? 22 : 3389; // SSH ou RDP
                    protocol = "TCP";
                    severity = 3 + random.nextInt(3); // Sévérité de 3 à 5
                    bytes = 60 + random.nextInt(200); // Paquets de taille moyenne
                    packets = 2 + random.nextInt(4); // Quelques paquets par tentative
                    flags = "ACK,PSH";
                }
                
                // Écriture de la ligne
                String line = String.format("%s,%s,%s,%d,%d,%s,%d,%d,%s,%s,%d\n",
                        timestamp.format(formatter),
                        sourceIp,
                        destinationIp,
                        sourcePort,
                        destinationPort,
                        protocol,
                        bytes,
                        packets,
                        flags,
                        attackType,
                        severity);
                
                writer.write(line);
            }
            
            System.out.println("Fichier de motifs d'attaques généré : " + ATTACK_PATTERNS_FILE);
            
        } catch (IOException e) {
            System.err.println("Erreur lors de la génération du fichier de motifs d'attaques : " + e.getMessage());
        }
    }
}
