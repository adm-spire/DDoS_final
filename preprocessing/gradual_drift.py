from collections import deque
import numpy as np
from river.tree import HoeffdingAdaptiveTreeClassifier

class SlidingWindowHAT_v1(HoeffdingAdaptiveTreeClassifier):
    def __init__(self, window_size=50, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.feature_window = {}  # Store feature distributions
        self.window_size = window_size  # Number of past values to track

    def _update_node(self, node, x, y):
        """Detect gradual drift using a sliding window before using ADWIN"""

        for feature, value in x.items():
            if feature not in self.feature_window:
                self.feature_window[feature] = deque(maxlen=self.window_size)
            
            self.feature_window[feature].append(value)  # Add new value
            
            # Compute rolling variance to detect slow drift
            if len(self.feature_window[feature]) == self.window_size:
                variance = np.var(self.feature_window[feature])
                if variance > 0.1:  # Threshold for detecting gradual drift
                    print(f"Gradual drift detected in feature {feature}! Resetting subtree.")
                    return self._new_leaf()  # Reset affected node

        return super()._update_node(node, x, y)
