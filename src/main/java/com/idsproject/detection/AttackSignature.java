package main.java.com.idsproject.detection;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Classe contenant les signatures d'attaques courantes pour aider à la détection.
 * Ces signatures sont utilisées pour identifier des motifs connus d'attaques.
 */
public class AttackSignature {
    
    // Map des signatures d'attaques par type
    private static final Map<String, Pattern[]> ATTACK_SIGNATURES = new HashMap<>();
    
    static {
        // Signatures pour les attaques DoS
        Pattern[] dosPatterns = {
            Pattern.compile(".*SYN flood.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*connection overflow.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*ICMP flood.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*UDP flood.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*HTTP flood.*", Pattern.CASE_INSENSITIVE)
        };
        ATTACK_SIGNATURES.put("DoS", dosPatterns);
        
        // Signatures pour les scans de ports
        Pattern[] portScanPatterns = {
            Pattern.compile(".*port scan.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*nmap.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*sequential port.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*service discovery.*", Pattern.CASE_INSENSITIVE)
        };
        ATTACK_SIGNATURES.put("PortScan", portScanPatterns);
        
        // Signatures pour les attaques par force brute
        Pattern[] bruteForcePatterns = {
            Pattern.compile(".*multiple login attempts.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*authentication failure.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*password guessing.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*dictionary attack.*", Pattern.CASE_INSENSITIVE)
        };
        ATTACK_SIGNATURES.put("BruteForce", bruteForcePatterns);
        
        // Signatures pour les injections SQL
        Pattern[] sqlInjectionPatterns = {
            Pattern.compile(".*'\\s*OR\\s*'1'='1.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*';\\s*DROP\\s+TABLE.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*UNION\\s+SELECT.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*--\\s*$", Pattern.CASE_INSENSITIVE)
        };
        ATTACK_SIGNATURES.put("SQLInjection", sqlInjectionPatterns);
    }
    
    /**
     * Vérifie si un texte contient une signature d'attaque connue
     * @param text le texte à vérifier
     * @param attackType le type d'attaque à vérifier
     * @return true si une signature d'attaque est trouvée, false sinon
     */
    public static boolean matchesSignature(String text, String attackType) {
        if (text == null || attackType == null) {
            return false;
        }
        
        Pattern[] patterns = ATTACK_SIGNATURES.get(attackType);
        if (patterns == null) {
            return false;
        }
        
        for (Pattern pattern : patterns) {
            if (pattern.matcher(text).matches()) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Détecte le type d'attaque en fonction des signatures connues
     * @param text le texte à analyser
     * @return le type d'attaque détecté ou null si aucune correspondance n'est trouvée
     */
    public static String detectAttackType(String text) {
        if (text == null) {
            return null;
        }
        
        for (Map.Entry<String, Pattern[]> entry : ATTACK_SIGNATURES.entrySet()) {
            String attackType = entry.getKey();
            Pattern[] patterns = entry.getValue();
            
            for (Pattern pattern : patterns) {
                if (pattern.matcher(text).matches()) {
                    return attackType;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Ajoute une nouvelle signature d'attaque
     * @param attackType le type d'attaque
     * @param signatureRegex l'expression régulière de la signature
     */
    public static void addSignature(String attackType, String signatureRegex) {
        if (attackType == null || signatureRegex == null) {
            return;
        }
        
        Pattern[] existingPatterns = ATTACK_SIGNATURES.get(attackType);
        Pattern newPattern = Pattern.compile(signatureRegex, Pattern.CASE_INSENSITIVE);
        
        if (existingPatterns == null) {
            // Nouveau type d'attaque
            ATTACK_SIGNATURES.put(attackType, new Pattern[]{newPattern});
        } else {
            // Ajouter à un type existant
            Pattern[] newPatterns = new Pattern[existingPatterns.length + 1];
            System.arraycopy(existingPatterns, 0, newPatterns, 0, existingPatterns.length);
            newPatterns[existingPatterns.length] = newPattern;
            ATTACK_SIGNATURES.put(attackType, newPatterns);
        }
    }
}
