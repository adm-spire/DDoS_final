from preprocessing.entropy_adaptive import AdaptiveEntropyHAT
from preprocessing.gradual_drift import SlidingWindowHAT_v1
class HybridHAT(AdaptiveEntropyHAT, SlidingWindowHAT_v1):
    def __init__(self, *args, **kwargs):
        super().__init__(
            grace_period=1000,        #  Further increase to delay splitting & prevent early overfitting
            delta=1e-05,              #  Loosen significance level slightly to avoid excessive splits
            tau=0.15,                 #  Reduce sensitivity to marginal tie-breaks
            max_depth=8,              #  Slightly lower tree depth to prevent unnecessary complexity
            leaf_prediction="mc",     #  Keep majority class voting (less prone to overfitting)
            bootstrap_sampling=False, #  Keep disabled to avoid reinforcing bias
            drift_window_threshold=800, #  Further increase to reduce false drift detections
            max_size=600,             #  Reduce tree memory size further for efficiency
            stop_mem_management=False,
            remove_poor_attrs=True,   #  Keep enabled to reduce reliance on irrelevant features
            
            
            *args,
            **kwargs
        )



