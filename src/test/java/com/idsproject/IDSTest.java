package test.java.com.idsproject;

import main.java.com.idsproject.detection.IDS;
import main.java.com.idsproject.network.NetworkMonitor;
import main.java.com.idsproject.network.PacketAnalyzer;
import main.java.com.idsproject.rl.QLearning;
import main.java.com.idsproject.network.NetworkMonitor.NetworkPacket;
import java.net.InetAddress;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class IDSTest {
    private IDS ids;
    private NetworkMonitor monitor;
    private QLearning qLearning;
    
    @BeforeEach
    public void setUp() throws Exception {
        monitor = new NetworkMonitor();
        qLearning = new QLearning(0.1, 0.9, 0.3);
        ids = new IDS(monitor, qLearning);
    }
    
    @Test
    public void testDosAttackDetection() throws Exception {
        InetAddress testAddress = InetAddress.getByName("192.168.1.1");
        NetworkPacket packet = new NetworkPacket(
            testAddress,
            InetAddress.getByName("192.168.1.2"),
            1234,
            80,
            System.currentTimeMillis(),
            100
        );
        
        // Simuler une attaque DoS (plus de 50 paquets)
        for (int i = 0; i < 60; i++) {
            ids.onPacketReceived(packet);
        }
        
        assertTrue(ids.getAlertsGenerated() > 0);
    }
    
    @Test
    public void testNormalTraffic() throws Exception {
        InetAddress testAddress = InetAddress.getByName("192.168.1.1");
        NetworkPacket packet = new NetworkPacket(
            testAddress,
            InetAddress.getByName("192.168.1.2"),
            1234,
            80,
            System.currentTimeMillis(),
            100
        );
        
        // Simuler du trafic normal
        for (int i = 0; i < 10; i++) {
            ids.onPacketReceived(packet);
        }
        
        assertEquals(0, ids.getAlertsGenerated());
    }
    
    @Test
    public void testPortScanDetection() throws Exception {
        InetAddress testAddress = InetAddress.getByName("192.168.1.1");
        
        // Simuler un scan de ports (plus de 15 ports différents)
        for (int port = 1; port <= 20; port++) {
            NetworkPacket packet = new NetworkPacket(
                testAddress,
                InetAddress.getByName("192.168.1.2"),
                1234,
                port,
                System.currentTimeMillis(),
                100
            );
            ids.onPacketReceived(packet);
        }
        
        assertTrue(ids.getAlertsGenerated() > 0);
    }
}