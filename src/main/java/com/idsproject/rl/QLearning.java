package main.java.com.idsproject.rl;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Implémentation de l'algorithme Q-Learning pour l'apprentissage par renforcement.
 * Cette classe gère la prise de décision adaptative basée sur les expériences passées.
 */
public class QLearning {

    // Paramètres d'apprentissage
    private final double alpha; // Taux d'apprentissage
    private final double gamma; // Facteur d'actualisation
    private final double epsilon; // Paramètre d'exploration
    
    // Table Q stockant les valeurs de qualité pour chaque paire état-action
    private final Map<StateActionPair, Double> qTable;
    
    private final Random random;
    
    /**
     * Constructeur avec paramètres d'apprentissage
     * @param alpha le taux d'apprentissage (0 < alpha <= 1)
     * @param gamma le facteur d'actualisation (0 <= gamma < 1)
     * @param epsilon le paramètre d'exploration (0 <= epsilon <= 1)
     */
    public QLearning(double alpha, double gamma, double epsilon) {
        this.alpha = alpha;
        this.gamma = gamma;
        this.epsilon = epsilon;
        this.qTable = new HashMap<>();
        this.random = new Random();
    }
    
    /**
     * Sélectionne une action basée sur l'état actuel en utilisant la politique epsilon-greedy
     * @param state l'état actuel
     * @return l'action sélectionnée
     */
    public Action selectAction(State state) {
        // Exploration avec probabilité epsilon
        if (random.nextDouble() < epsilon) {
            return Action.values()[random.nextInt(Action.values().length)];
        }
        
        // Exploitation avec probabilité (1-epsilon)
        return getBestAction(state);
    }
    
    /**
     * Met à jour la table Q en fonction de la récompense reçue
     * @param state l'état actuel
     * @param action l'action effectuée
     * @param reward la récompense reçue
     * @param nextState l'état suivant
     */
    public void update(State state, Action action, double reward, State nextState) {
        StateActionPair pair = new StateActionPair(state, action);
        
        // Obtient la valeur Q actuelle (0 si elle n'existe pas encore)
        double currentQ = qTable.getOrDefault(pair, 0.0);
        
        // Calcule la valeur maximale de Q pour le prochain état
        Action bestNextAction = getBestAction(nextState);
        StateActionPair nextPair = new StateActionPair(nextState, bestNextAction);
        double maxNextQ = qTable.getOrDefault(nextPair, 0.0);
        
        // Formule de mise à jour Q = Q + α * (r + γ * max(Q') - Q)
        double newQ = currentQ + alpha * (reward + gamma * maxNextQ - currentQ);
        
        // Met à jour la table Q
        qTable.put(pair, newQ);
    }
    
    /**
     * Retourne la meilleure action pour un état donné selon la table Q
     * @param state l'état pour lequel trouver la meilleure action
     * @return la meilleure action
     */
    public Action getBestAction(State state) {
        Action bestAction = Action.ALLOW; // Action par défaut
        double bestQ = Double.NEGATIVE_INFINITY;
        
        // Parcourt toutes les actions possibles
        for (Action action : Action.values()) {
            StateActionPair pair = new StateActionPair(state, action);
            double q = qTable.getOrDefault(pair, 0.0);
            
            if (q > bestQ) {
                bestQ = q;
                bestAction = action;
            }
        }
        
        return bestAction;
    }
    
    /**
     * Retourne la valeur Q pour une paire état-action
     * @param state l'état
     * @param action l'action
     * @return la valeur Q
     */
    public double getQValue(State state, Action action) {
        StateActionPair pair = new StateActionPair(state, action);
        return qTable.getOrDefault(pair, 0.0);
    }
    
    /**
     * Retourne la taille de la table Q
     * @return le nombre d'entrées dans la table Q
     */
    public int getQTableSize() {
        return qTable.size();
    }
    
    /**
     * Classe interne représentant une paire état-action
     */
    private static class StateActionPair {
        private final State state;
        private final Action action;
        
        public StateActionPair(State state, Action action) {
            this.state = state;
            this.action = action;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            
            StateActionPair that = (StateActionPair) o;
            return state.equals(that.state) && action == that.action;
        }
        
        @Override
        public int hashCode() {
            int result = state.hashCode();
            result = 31 * result + action.hashCode();
            return result;
        }
    }
}
