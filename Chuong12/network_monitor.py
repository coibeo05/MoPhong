# network_monitor.py
from typing import List, Dict
from kfsensor_simulator import NetworkObservation
from fuzzy_inference    import MamdaniFIS

class NetworkMonitor:
    """
    Giám sát mạng real-time và đưa ra cảnh báo
    Kết hợp KFSensor + Fuzzy Inference System
    """
    def __init__(self):
        self.fis     = MamdaniFIS()
        self.results : List[Dict] = []

    def monitor(self,
                observations: List[NetworkObservation]) -> List[Dict]:
        print(f"\n{'─'*70}")
        print(f"{'Obs':>4} | {'RTIPA':>6} {'UARPP':>6} "
              f"{'RARPP':>6} | {'SAP':>6} | {'Level':>7} | Action")
        print(f"{'─'*70}")

        for obs in observations:
            result = self.fis.compute(obs.rtipa, obs.uarpp, obs.rarpp)
            result["obs_id"]      = obs.obs_id
            result["attack_type"] = obs.attack_type
            result["description"] = obs.description
            self.results.append(result)

            print(f"{obs.obs_id:>4} | "
                  f"{obs.rtipa:>6.1f} {obs.uarpp:>6.1f} "
                  f"{obs.rarpp:>6.1f} | "
                  f"{result['SAP']:>5.1f}% | "
                  f"{result['level']:>7} | "
                  f"{result['action']}")

        print(f"{'─'*70}")
        return self.results

    def summary(self):
        high   = sum(1 for r in self.results if r["level"] == "HIGH")
        medium = sum(1 for r in self.results if r["level"] == "MEDIUM")
        low    = sum(1 for r in self.results if r["level"] == "LOW")
        print(f"\n[Monitor] Summary: "
              f"HIGH={high} | MEDIUM={medium} | LOW={low}")