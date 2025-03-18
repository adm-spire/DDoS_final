# model.py
from preprocessing.entropy_adaptive import AdaptiveEntropyHAT
from preprocessing.gradual_drift import SlidingWindowHAT_v1



class HybridHAT(AdaptiveEntropyHAT,SlidingWindowHAT_v1):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)