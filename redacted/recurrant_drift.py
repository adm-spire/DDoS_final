from collections import deque
from river.tree import HoeffdingAdaptiveTreeClassifier
class RecurrentDriftMitigation(HoeffdingAdaptiveTreeClassifier):
    def __init__(self, window_size=1000, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recent_data = deque(maxlen=window_size)  # Sliding window buffer

    def learn_one(self, x, y):
        """Train the model while maintaining a sliding window"""
        self.recent_data.append((x, y))  # Store data in buffer

        # If recurrent concept is detected, train with past samples
        if self.detect_recurrence():
            print("Recurrent drift detected! Reusing past data.")
            for x_past, y_past in self.recent_data:
                super().learn_one(x_past, y_past)  # Re-train with past data

        super().learn_one(x, y)  # Train with current data

    def detect_recurrence(self):
        """Simple heuristic: If model's accuracy drops below threshold, check stored samples"""
        recent_predictions = [self.predict_one(x) for x, _ in self.recent_data]
        recent_labels = [y for _, y in self.recent_data]
        accuracy = sum(p == l for p, l in zip(recent_predictions, recent_labels)) / len(recent_labels)
        return accuracy > 0.8  # Threshold can be tuned
