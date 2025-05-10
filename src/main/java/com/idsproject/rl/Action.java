package main.java.com.idsproject.rl;

/**
 * Énumération des actions possibles que le système peut entreprendre.
 * Ces actions sont utilisées par l'algorithme d'apprentissage par renforcement.
 */
public enum Action {
    
    /**
     * Autoriser le trafic réseau
     */
    ALLOW("Autoriser"),
    
    /**
     * Surveiller le trafic réseau (niveau de vigilance accru)
     */
    MONITOR("Surveiller"),
    
    /**
     * Bloquer le trafic réseau (considéré comme malveillant)
     */
    BLOCK("Bloquer");
    
    private final String description;
    
    /**
     * Constructeur de l'énumération
     * @param description description textuelle de l'action
     */
    Action(String description) {
        this.description = description;
    }
    
    /**
     * Retourne la description de l'action
     * @return la description textuelle
     */
    public String getDescription() {
        return description;
    }
    
    @Override
    public String toString() {
        return description;
    }
}
