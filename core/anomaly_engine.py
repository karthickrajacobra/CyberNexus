import math
from datetime import datetime, timezone


class AnomalyEngine:
    """
    CyberNexus Ω - Anomaly Detection Engine

    Detects abnormal activity by comparing observed
    behaviour against a learned baseline.

    This is a defensive analytics module.
    It does not execute attacks or modify systems.
    """

    ENGINE_NAME = "CyberNexus Anomaly Engine"
    ENGINE_VERSION = "1.0"

    def __init__(self):
        self.status = "READY"

    # =========================================================
    # UTILITY
    # =========================================================

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    def _safe_float(self, value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    # =========================================================
    # STATISTICAL HELPERS
    # =========================================================

    def calculate_mean(self, values):
        """
        Calculate arithmetic mean.
        """

        if not values:
            return 0.0

        numbers = [
            self._safe_float(value)
            for value in values
        ]

        return sum(numbers) / len(numbers)

    def calculate_std(self, values):
        """
        Calculate population standard deviation.
        """

        if not values:
            return 0.0

        numbers = [
            self._safe_float(value)
            for value in values
        ]

        mean = self.calculate_mean(numbers)

        variance = sum(
            (value - mean) ** 2
            for value in numbers
        ) / len(numbers)

        return math.sqrt(variance)

    def calculate_z_score(
        self,
        observed,
        mean,
        std
    ):
        """
        Calculate Z-score.
        """

        observed = self._safe_float(observed)
        mean = self._safe_float(mean)
        std = self._safe_float(std)

        if std == 0:
            if observed == mean:
                return 0.0

            return 999.0

        return (
            (observed - mean)
            / std
        )

    # =========================================================
    # BASELINE CREATION
    # =========================================================

    def build_baseline(
        self,
        login_counts=None,
        request_counts=None,
        data_transfer_mb=None,
        session_durations=None
    ):
        """
        Build a statistical baseline from historical activity.
        """

        login_counts = login_counts or []
        request_counts = request_counts or []
        data_transfer_mb = data_transfer_mb or []
        session_durations = session_durations or []

        baseline = {
            "login_activity": {
                "mean": round(
                    self.calculate_mean(login_counts),
                    4
                ),
                "std": round(
                    self.calculate_std(login_counts),
                    4
                )
            },

            "request_activity": {
                "mean": round(
                    self.calculate_mean(request_counts),
                    4
                ),
                "std": round(
                    self.calculate_std(request_counts),
                    4
                )
            },

            "data_transfer_mb": {
                "mean": round(
                    self.calculate_mean(data_transfer_mb),
                    4
                ),
                "std": round(
                    self.calculate_std(data_transfer_mb),
                    4
                )
            },

            "session_duration": {
                "mean": round(
                    self.calculate_mean(session_durations),
                    4
                ),
                "std": round(
                    self.calculate_std(session_durations),
                    4
                )
            }
        }

        return baseline

    # =========================================================
    # METRIC ANALYSIS
    # =========================================================

    def _analyze_metric(
        self,
        metric_name,
        observed,
        baseline_metric
    ):
        """
        Analyze one metric against baseline.
        """

        observed = self._safe_float(observed)

        mean = self._safe_float(
            baseline_metric.get(
                "mean",
                0
            )
        )

        std = self._safe_float(
            baseline_metric.get(
                "std",
                0
            )
        )

        z_score = self.calculate_z_score(
            observed,
            mean,
            std
        )

        absolute_difference = abs(
            observed - mean
        )

        if mean != 0:

            percentage_change = (
                absolute_difference
                / abs(mean)
            ) * 100

        else:

            percentage_change = (
                100
                if observed != 0
                else 0
            )

        absolute_z = abs(z_score)

        if absolute_z >= 4:

            anomaly_level = "CRITICAL"

        elif absolute_z >= 3:

            anomaly_level = "HIGH"

        elif absolute_z >= 2:

            anomaly_level = "MEDIUM"

        else:

            anomaly_level = "LOW"

        if anomaly_level == "CRITICAL":

            score = 95

        elif anomaly_level == "HIGH":

            score = 75

        elif anomaly_level == "MEDIUM":

            score = 50

        else:

            score = 10

        return {
            "metric": metric_name,
            "observed": round(
                observed,
                4
            ),
            "baseline_mean": round(
                mean,
                4
            ),
            "baseline_std": round(
                std,
                4
            ),
            "z_score": round(
                z_score,
                4
            ),
            "percentage_change": round(
                percentage_change,
                2
            ),
            "anomaly_level": anomaly_level,
            "anomaly_score": score
        }

    # =========================================================
    # PATTERN ANALYSIS
    # =========================================================

    def _analyze_patterns(
        self,
        observed_activity
    ):
        """
        Detect rule-based behavioural anomalies
        that statistics alone may miss.
        """

        indicators = []
        score = 0

        failed_logins = self._safe_float(
            observed_activity.get(
                "failed_logins",
                0
            )
        )

        privilege_escalation = bool(
            observed_activity.get(
                "privilege_escalation",
                False
            )
        )

        unknown_device = bool(
            observed_activity.get(
                "unknown_device",
                False
            )
        )

        suspicious_url = bool(
            observed_activity.get(
                "suspicious_url",
                False
            )
        )

        suspicious_file = bool(
            observed_activity.get(
                "suspicious_file",
                False
            )
        )

        rapid_requests = self._safe_float(
            observed_activity.get(
                "rapid_requests",
                0
            )
        )

        data_transfer = self._safe_float(
            observed_activity.get(
                "data_transfer_mb",
                0
            )
        )

        # -----------------------------------------------------
        # FAILED LOGINS
        # -----------------------------------------------------

        if failed_logins >= 10:

            score += 25

            indicators.append(
                "Excessive failed login activity."
            )

        elif failed_logins >= 5:

            score += 12

            indicators.append(
                "Elevated failed login activity."
            )

        # -----------------------------------------------------
        # PRIVILEGE ESCALATION
        # -----------------------------------------------------

        if privilege_escalation:

            score += 25

            indicators.append(
                "Privilege escalation behaviour detected."
            )

        # -----------------------------------------------------
        # UNKNOWN DEVICE
        # -----------------------------------------------------

        if unknown_device:

            score += 10

            indicators.append(
                "Activity originated from an unknown device."
            )

        # -----------------------------------------------------
        # SUSPICIOUS URL
        # -----------------------------------------------------

        if suspicious_url:

            score += 15

            indicators.append(
                "Suspicious URL activity detected."
            )

        # -----------------------------------------------------
        # SUSPICIOUS FILE
        # -----------------------------------------------------

        if suspicious_file:

            score += 15

            indicators.append(
                "Suspicious file activity detected."
            )

        # -----------------------------------------------------
        # RAPID REQUESTS
        # -----------------------------------------------------

        if rapid_requests >= 100:

            score += 20

            indicators.append(
                "Abnormally high request volume detected."
            )

        elif rapid_requests >= 50:

            score += 10

            indicators.append(
                "Elevated request volume detected."
            )

        # -----------------------------------------------------
        # DATA TRANSFER
        # -----------------------------------------------------

        if data_transfer >= 1000:

            score += 25

            indicators.append(
                "Large outbound data transfer detected."
            )

        elif data_transfer >= 500:

            score += 15

            indicators.append(
                "Elevated outbound data transfer detected."
            )

        return {
            "score": min(
                score,
                100
            ),
            "indicators": indicators
        }

    # =========================================================
    # RISK LEVEL
    # =========================================================

    def _risk_level(self, score):

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 35:
            return "MEDIUM"

        return "LOW"

    # =========================================================
    # MAIN ANALYSIS
    # =========================================================

    def analyze(
        self,
        baseline,
        observed_activity
    ):
        """
        Compare observed activity against baseline.
        """

        if not baseline:

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "NO_BASELINE",
                "message": (
                    "A behavioural baseline is required."
                ),
                "timestamp": self._timestamp()
            }

        if not observed_activity:

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "NO_DATA",
                "message": (
                    "Observed activity is required."
                ),
                "timestamp": self._timestamp()
            }

        metric_results = []

        # -----------------------------------------------------
        # LOGIN ACTIVITY
        # -----------------------------------------------------

        metric_results.append(
            self._analyze_metric(
                "login_activity",
                observed_activity.get(
                    "login_count",
                    0
                ),
                baseline.get(
                    "login_activity",
                    {}
                )
            )
        )

        # -----------------------------------------------------
        # REQUEST ACTIVITY
        # -----------------------------------------------------

        metric_results.append(
            self._analyze_metric(
                "request_activity",
                observed_activity.get(
                    "request_count",
                    0
                ),
                baseline.get(
                    "request_activity",
                    {}
                )
            )
        )

        # -----------------------------------------------------
        # DATA TRANSFER
        # -----------------------------------------------------

        metric_results.append(
            self._analyze_metric(
                "data_transfer_mb",
                observed_activity.get(
                    "data_transfer_mb",
                    0
                ),
                baseline.get(
                    "data_transfer_mb",
                    {}
                )
            )
        )

        # -----------------------------------------------------
        # SESSION DURATION
        # -----------------------------------------------------

        metric_results.append(
            self._analyze_metric(
                "session_duration",
                observed_activity.get(
                    "session_duration",
                    0
                ),
                baseline.get(
                    "session_duration",
                    {}
                )
            )
        )

        # -----------------------------------------------------
        # STATISTICAL SCORE
        # -----------------------------------------------------

        statistical_scores = [
            item["anomaly_score"]
            for item in metric_results
        ]

        statistical_score = max(
            statistical_scores
        ) if statistical_scores else 0

        # -----------------------------------------------------
        # RULE-BASED PATTERNS
        # -----------------------------------------------------

        pattern_result = self._analyze_patterns(
            observed_activity
        )

        pattern_score = pattern_result[
            "score"
        ]

        # -----------------------------------------------------
        # COMBINED SCORE
        # -----------------------------------------------------

        combined_score = round(
            (
                statistical_score * 0.6
            )
            +
            (
                pattern_score * 0.4
            )
        )

        combined_score = min(
            combined_score,
            100
        )

        # -----------------------------------------------------
        # MULTI-SIGNAL BONUS
        # -----------------------------------------------------

        anomaly_metrics = sum(
            1
            for item in metric_results
            if item["anomaly_score"] >= 50
        )

        if anomaly_metrics >= 3:

            combined_score = min(
                combined_score + 10,
                100
            )

        elif anomaly_metrics >= 2:

            combined_score = min(
                combined_score + 5,
                100
            )

        # -----------------------------------------------------
        # FINAL LEVEL
        # -----------------------------------------------------

        risk_level = self._risk_level(
            combined_score
        )

        # -----------------------------------------------------
        # ABNORMAL METRICS
        # -----------------------------------------------------

        abnormal_metrics = [
            item
            for item in metric_results
            if item["anomaly_level"] != "LOW"
        ]

        # -----------------------------------------------------
        # SUMMARY
        # -----------------------------------------------------

        if abnormal_metrics:

            summary = (
                f"CyberNexus detected "
                f"{len(abnormal_metrics)} abnormal "
                f"behaviour metric(s)."
            )

        elif pattern_result["indicators"]:

            summary = (
                "Rule-based suspicious behaviour "
                "indicators were detected."
            )

        else:

            summary = (
                "Observed activity is within the "
                "established behavioural baseline."
            )

        # -----------------------------------------------------
        # RECOMMENDATIONS
        # -----------------------------------------------------

        recommendations = []

        if risk_level in {
            "CRITICAL",
            "HIGH"
        }:

            recommendations.append(
                "Investigate the anomalous activity immediately."
            )

            recommendations.append(
                "Correlate authentication, endpoint, "
                "and network telemetry."
            )

        elif risk_level == "MEDIUM":

            recommendations.append(
                "Review the anomalous activity and "
                "monitor for recurrence."
            )

        else:

            recommendations.append(
                "Continue normal security monitoring."
            )

        if (
            observed_activity.get(
                "privilege_escalation",
                False
            )
        ):

            recommendations.append(
                "Review privileged account activity."
            )

        if (
            observed_activity.get(
                "unknown_device",
                False
            )
        ):

            recommendations.append(
                "Validate the device identity and "
                "authentication context."
            )

        if (
            observed_activity.get(
                "suspicious_url",
                False
            )
        ):

            recommendations.append(
                "Investigate suspicious URL activity."
            )

        if (
            observed_activity.get(
                "suspicious_file",
                False
            )
        ):

            recommendations.append(
                "Investigate suspicious file activity "
                "and preserve evidence."
            )

        if (
            self._safe_float(
                observed_activity.get(
                    "data_transfer_mb",
                    0
                )
            ) >= 500
        ):

            recommendations.append(
                "Review outbound data transfers "
                "for possible unauthorized activity."
            )

        return {
            "success": True,
            "engine": self.ENGINE_NAME,
            "version": self.ENGINE_VERSION,
            "status": "ANALYZED",
            "timestamp": self._timestamp(),

            "anomaly": {
                "score": combined_score,
                "risk_level": risk_level,
                "statistical_score": statistical_score,
                "pattern_score": pattern_score
            },

            "metrics": metric_results,

            "abnormal_metrics": abnormal_metrics,

            "pattern_analysis": pattern_result,

            "summary": summary,

            "recommendations": list(
                dict.fromkeys(
                    recommendations
                )
            )
        }


def build_anomaly_baseline(
    login_counts=None,
    request_counts=None,
    data_transfer_mb=None,
    session_durations=None
):
    """
    Convenience function for baseline creation.
    """

    engine = AnomalyEngine()

    return engine.build_baseline(
        login_counts=login_counts,
        request_counts=request_counts,
        data_transfer_mb=data_transfer_mb,
        session_durations=session_durations
    )


def analyze_anomaly(
    baseline,
    observed_activity
):
    """
    Convenience function for anomaly analysis.
    """

    engine = AnomalyEngine()

    return engine.analyze(
        baseline=baseline,
        observed_activity=observed_activity
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - ANOMALY ENGINE TEST")
    print("=" * 70)

    engine = AnomalyEngine()

    # ---------------------------------------------------------
    # NORMAL HISTORICAL BASELINE
    # ---------------------------------------------------------

    baseline = engine.build_baseline(

        login_counts=[
            4,
            5,
            4,
            6,
            5,
            4,
            5,
            6,
            5,
            4
        ],

        request_counts=[
            20,
            25,
            22,
            24,
            21,
            23,
            26,
            22,
            24,
            21
        ],

        data_transfer_mb=[
            100,
            120,
            110,
            105,
            115,
            125,
            108,
            112,
            118,
            109
        ],

        session_durations=[
            30,
            35,
            32,
            31,
            34,
            33,
            29,
            36,
            32,
            31
        ]
    )

    # ---------------------------------------------------------
    # DISPLAY BASELINE
    # ---------------------------------------------------------

    print("\n[1] BEHAVIOURAL BASELINE")
    print("-" * 70)

    for metric, values in baseline.items():

        print(
            f"{metric:<22} "
            f"Mean: {values['mean']:<10} "
            f"Std: {values['std']}"
        )

    # ---------------------------------------------------------
    # NORMAL ACTIVITY TEST
    # ---------------------------------------------------------

    normal_activity = {

        "login_count": 5,

        "request_count": 23,

        "data_transfer_mb": 110,

        "session_duration": 32,

        "failed_logins": 1,

        "privilege_escalation": False,

        "unknown_device": False,

        "suspicious_url": False,

        "suspicious_file": False,

        "rapid_requests": 20
    }

    print("\n[2] NORMAL ACTIVITY TEST")
    print("-" * 70)

    normal_result = engine.analyze(
        baseline=baseline,
        observed_activity=normal_activity
    )

    print(
        "Status       :",
        normal_result.get("status")
    )

    print(
        "Anomaly Score:",
        normal_result[
            "anomaly"
        ]["score"]
    )

    print(
        "Risk Level   :",
        normal_result[
            "anomaly"
        ]["risk_level"]
    )

    print(
        "Summary      :",
        normal_result.get("summary")
    )

    # ---------------------------------------------------------
    # SUSPICIOUS ACTIVITY TEST
    # ---------------------------------------------------------

    suspicious_activity = {

        "login_count": 30,

        "request_count": 180,

        "data_transfer_mb": 1800,

        "session_duration": 180,

        "failed_logins": 12,

        "privilege_escalation": True,

        "unknown_device": True,

        "suspicious_url": True,

        "suspicious_file": True,

        "rapid_requests": 150
    }

    print("\n[3] SUSPICIOUS ACTIVITY TEST")
    print("-" * 70)

    suspicious_result = engine.analyze(
        baseline=baseline,
        observed_activity=suspicious_activity
    )

    print(
        "Status       :",
        suspicious_result.get("status")
    )

    print(
        "Anomaly Score:",
        suspicious_result[
            "anomaly"
        ]["score"]
    )

    print(
        "Risk Level   :",
        suspicious_result[
            "anomaly"
        ]["risk_level"]
    )

    print(
        "Statistical  :",
        suspicious_result[
            "anomaly"
        ]["statistical_score"]
    )

    print(
        "Pattern Score:",
        suspicious_result[
            "anomaly"
        ]["pattern_score"]
    )

    print(
        "Summary      :",
        suspicious_result.get("summary")
    )

    # ---------------------------------------------------------
    # ABNORMAL METRICS
    # ---------------------------------------------------------

    print("\n[4] ABNORMAL METRICS")
    print("-" * 70)

    for metric in suspicious_result.get(
        "abnormal_metrics",
        []
    ):

        print(
            f" - {metric['metric']}: "
            f"{metric['anomaly_level']} "
            f"(Z={metric['z_score']})"
        )

    # ---------------------------------------------------------
    # PATTERN INDICATORS
    # ---------------------------------------------------------

    print("\n[5] PATTERN INDICATORS")
    print("-" * 70)

    for indicator in suspicious_result[
        "pattern_analysis"
    ]["indicators"]:

        print(
            " -",
            indicator
        )

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    print("\n[6] RECOMMENDATIONS")
    print("-" * 70)

    for recommendation in suspicious_result[
        "recommendations"
    ]:

        print(
            " -",
            recommendation
        )

    # ---------------------------------------------------------
    # EMPTY BASELINE TEST
    # ---------------------------------------------------------

    print("\n[7] EMPTY BASELINE TEST")
    print("-" * 70)

    empty_baseline_result = engine.analyze(
        baseline=None,
        observed_activity=normal_activity
    )

    print(
        "Status       :",
        empty_baseline_result.get(
            "status"
        )
    )

    print(
        "Message      :",
        empty_baseline_result.get(
            "message"
        )
    )

    # ---------------------------------------------------------
    # EMPTY ACTIVITY TEST
    # ---------------------------------------------------------

    print("\n[8] EMPTY ACTIVITY TEST")
    print("-" * 70)

    empty_activity_result = engine.analyze(
        baseline=baseline,
        observed_activity=None
    )

    print(
        "Status       :",
        empty_activity_result.get(
            "status"
        )
    )

    print(
        "Message      :",
        empty_activity_result.get(
            "message"
        )
    )

    # ---------------------------------------------------------
    # FINAL
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("ANOMALY ENGINE TEST COMPLETED")
    print("=" * 70)