from collections import defaultdict
from river.tree import HoeffdingAdaptiveTreeClassifier

class AdaptiveFeatureHAT(HoeffdingAdaptiveTreeClassifier):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.feature_usage = defaultdict(int)  # Store how often features are used
        self.decay_rate = 0.95  # Factor to gradually reduce old feature weights

    def _find_best_split(self, node, parent, parent_branch):
        """Modify feature selection to prioritize frequently used features"""
        
        best_split = None
        best_score = float("-inf")  # Track highest scoring split
        
        # Apply decay to old feature weights (gradually reduce unused features)
        for feature in list(self.feature_usage.keys()):
            self.feature_usage[feature] *= self.decay_rate
        
        for feature in node.split_suggestions:
            # Compute importance score: Information gain + feature usage boost
            score = feature.merit + self.feature_usage[feature.feature] * 0.1

            if score > best_score:
                best_score = score
                best_split = feature

        # Update feature usage counter
        if best_split:
            self.feature_usage[best_split.feature] += 1  # Increase importance

        return best_split
