import math
from collections import defaultdict
from river.tree import HoeffdingAdaptiveTreeClassifier

class AdaptiveEntropyHAT(HoeffdingAdaptiveTreeClassifier):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.feature_usage = defaultdict(int)  # Store how often features are used
        self.decay_rate = 0.95  # Factor to gradually reduce old feature weights

    def _entropy(self, class_counts):
        """Calculate entropy of class distribution"""
        total = sum(class_counts.values())
        if total == 0:
            return 0  # Prevent division by zero
        return -sum((count / total) * math.log2(count / total) for count in class_counts.values() if count > 0)

    def _find_best_split(self, node, parent, parent_branch):
        """Combine adaptive feature selection with entropy-based splitting"""

        best_split = None
        best_score = float("-inf")

        # Apply decay to feature importance to prevent old features from dominating
        for feature in list(self.feature_usage.keys()):
            self.feature_usage[feature] *= self.decay_rate

        # Compute entropy before split
        parent_entropy = self._entropy(node.class_distribution)

        for feature in node.split_suggestions:
            # Compute weighted entropy for child nodes
            total_instances = sum(node.class_distribution.values())
            weighted_entropy = 0

            for child_stats in feature.children_stats:
                child_entropy = self._entropy(child_stats)
                child_weight = sum(child_stats.values()) / total_instances
                weighted_entropy += child_weight * child_entropy

            # Compute Information Gain
            information_gain = parent_entropy - weighted_entropy

            # Apply adaptive feature selection weight boost
            adaptive_weight = self.feature_usage[feature.feature] * 0.1
            score = information_gain + adaptive_weight

            if score > best_score:
                best_score = score
                best_split = feature

        # Update feature usage counter for adaptive learning
        if best_split:
            self.feature_usage[best_split.feature] += 1  # Increase importance

        return best_split
