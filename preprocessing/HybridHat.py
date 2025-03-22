from preprocessing.entropy_adaptive import AdaptiveEntropyHAT
from preprocessing.gradual_drift import SlidingWindowHAT_v1


class HybridHAT(AdaptiveEntropyHAT, SlidingWindowHAT_v1):
    def __init__(self, *args, **kwargs):
        super().__init__(
            grace_period=500,       #  Increase to delay premature splits
            delta=1e-06,             #  Slightly loosen significance level to avoid overfitting splits
            tau=0.10,                #  Increase to reduce sensitivity to small tie-breaks
            max_depth=10,            #  Reduce depth to prevent excessive tree growth
            leaf_prediction="mc",  #  Use majority class voting instead of Naïve Bayes (less prone to overfitting)
            bootstrap_sampling=False,  #  Turn off to prevent reinforcement of biased samples
            drift_window_threshold=500,  #  Increase for better drift detection (less aggressive pruning)
            max_size=800,            #  Reduce tree memory size for compactness
            stop_mem_management=False,
            remove_poor_attrs=True,   #  Enable removing useless attributes to reduce overfitting
            *args,
            **kwargs
        )


