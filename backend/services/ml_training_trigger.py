# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
ML Training Trigger Service

Event-driven training for the ML alert classifier.
Training is BATCH-TRIGGERED, not continuous.

Trigger conditions:
1. Bucket reaches N new labeled alerts (default: 50)
2. Time window expires (nightly if bucket not empty)
3. Confidence drift detected (ML prediction vs analyst verdict mismatch rate)

Rules:
- Inference stays real-time
- Training is batch-triggered only
- ML can only nudge Riggs confidence, never decide
- ML influence capped to ±15-20%
"""

import logging
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class TrainingTriggerConfig:
    """Configuration for training triggers."""
    # Bucket size trigger: retrain when this many new labeled alerts accumulate
    min_bucket_size: int = 50

    # Time window trigger: hours since last training before checking bucket
    max_hours_since_training: int = 24

    # Minimum bucket size for time-based trigger (don't train on 1-2 alerts)
    min_bucket_for_time_trigger: int = 10

    # Drift detection: retrain if mismatch rate exceeds this threshold
    drift_threshold: float = 0.25  # 25% mismatch rate

    # Minimum predictions for drift calculation
    min_predictions_for_drift: int = 20

    # Days of data to use for training
    training_days_back: int = 90


# Default config
DEFAULT_CONFIG = TrainingTriggerConfig()


# =============================================================================
# TRAINING BUCKET TRACKER
# =============================================================================

class TrainingBucketTracker:
    """
    Tracks resolved alerts since last training for batch retraining.

    The "bucket" is the count of new labeled alerts since the last
    successful training run.
    """

    def __init__(self, config: TrainingTriggerConfig = None):
        self.config = config or DEFAULT_CONFIG
        self._last_check: Optional[datetime] = None

    async def get_bucket_status(self) -> Dict[str, Any]:
        """
        Get current training bucket status.

        Returns:
            Dict with bucket_size, last_training, should_train, reason
        """
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            return {"error": "Database not connected", "should_train": False}

        try:
            async with postgres_db.tenant_acquire() as conn:
                # Get last training timestamp from ml_training_runs
                last_training = await conn.fetchrow("""
                    SELECT trained_at, samples_used, accuracy
                    FROM ml_training_runs
                    WHERE status = 'success'
                    ORDER BY trained_at DESC
                    LIMIT 1
                """)

                last_trained_at = last_training['trained_at'] if last_training else None

                # Count resolved alerts since last training
                if last_trained_at:
                    bucket_size = await conn.fetchval("""
                        SELECT COUNT(*)
                        FROM alerts
                        WHERE status = 'resolved'
                          AND disposition IS NOT NULL
                          AND resolved_at > $1
                    """, last_trained_at)
                else:
                    # No training yet - count all resolved alerts
                    bucket_size = await conn.fetchval("""
                        SELECT COUNT(*)
                        FROM alerts
                        WHERE status = 'resolved'
                          AND disposition IS NOT NULL
                    """)

                # Calculate hours since last training
                hours_since = None
                if last_trained_at:
                    delta = datetime.now(timezone.utc) - last_trained_at.replace(tzinfo=timezone.utc)
                    hours_since = delta.total_seconds() / 3600

                # Determine if we should train
                should_train, reason = self._evaluate_triggers(
                    bucket_size=bucket_size,
                    hours_since_training=hours_since,
                    last_trained_at=last_trained_at
                )

                return {
                    "bucket_size": bucket_size,
                    "last_training": last_trained_at.isoformat() if last_trained_at else None,
                    "hours_since_training": round(hours_since, 1) if hours_since else None,
                    "last_accuracy": float(last_training['accuracy']) if last_training and last_training['accuracy'] else None,
                    "should_train": should_train,
                    "reason": reason,
                    "config": {
                        "min_bucket_size": self.config.min_bucket_size,
                        "max_hours": self.config.max_hours_since_training,
                        "drift_threshold": self.config.drift_threshold
                    }
                }

        except Exception as e:
            logger.error(f"[ML_TRIGGER] Error getting bucket status: {e}")
            return {"error": str(e), "should_train": False}

    def _evaluate_triggers(
        self,
        bucket_size: int,
        hours_since_training: Optional[float],
        last_trained_at: Optional[datetime]
    ) -> Tuple[bool, str]:
        """
        Evaluate all trigger conditions.

        Returns:
            Tuple of (should_train, reason)
        """
        # Trigger 1: Bucket size threshold
        if bucket_size >= self.config.min_bucket_size:
            return True, f"bucket_full ({bucket_size} >= {self.config.min_bucket_size} alerts)"

        # Trigger 2: Time window + minimum bucket
        if hours_since_training is not None:
            if (hours_since_training >= self.config.max_hours_since_training and
                bucket_size >= self.config.min_bucket_for_time_trigger):
                return True, f"time_window ({hours_since_training:.0f}h elapsed, {bucket_size} alerts pending)"

        # Trigger 3: No training ever and we have enough data
        if last_trained_at is None and bucket_size >= self.config.min_bucket_for_time_trigger:
            return True, f"initial_training ({bucket_size} alerts available)"

        # No trigger met
        return False, "waiting (bucket not full, time window not elapsed)"

    async def check_drift(self) -> Dict[str, Any]:
        """
        Check for confidence drift between ML predictions and analyst verdicts.

        Returns drift metrics and whether drift threshold is exceeded.
        """
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            return {"error": "Database not connected", "drift_detected": False}

        try:
            async with postgres_db.tenant_acquire() as conn:
                # Get recent predictions vs actual dispositions
                # This requires we log predictions somewhere (ml_predictions table)
                results = await conn.fetch("""
                    SELECT
                        mp.predicted_disposition,
                        mp.confidence,
                        a.disposition as actual_disposition
                    FROM ml_predictions mp
                    JOIN alerts a ON mp.alert_id = a.id
                    WHERE a.status = 'resolved'
                      AND a.disposition IS NOT NULL
                      AND mp.created_at > NOW() - INTERVAL '7 days'
                """)

                if len(results) < self.config.min_predictions_for_drift:
                    return {
                        "drift_detected": False,
                        "reason": f"insufficient_data ({len(results)} < {self.config.min_predictions_for_drift})",
                        "predictions_checked": len(results)
                    }

                # Calculate mismatch rate
                mismatches = 0
                high_confidence_mismatches = 0

                for r in results:
                    predicted = r['predicted_disposition']
                    actual = r['actual_disposition']
                    confidence = r['confidence']

                    # Normalize dispositions for comparison
                    predicted_cat = self._categorize_disposition(predicted)
                    actual_cat = self._categorize_disposition(actual)

                    if predicted_cat != actual_cat:
                        mismatches += 1
                        if confidence > 0.7:
                            high_confidence_mismatches += 1

                mismatch_rate = mismatches / len(results)
                high_conf_mismatch_rate = high_confidence_mismatches / len(results)

                drift_detected = mismatch_rate >= self.config.drift_threshold

                return {
                    "drift_detected": drift_detected,
                    "mismatch_rate": round(mismatch_rate, 3),
                    "high_confidence_mismatch_rate": round(high_conf_mismatch_rate, 3),
                    "predictions_checked": len(results),
                    "total_mismatches": mismatches,
                    "threshold": self.config.drift_threshold,
                    "reason": f"drift_detected ({mismatch_rate:.1%} > {self.config.drift_threshold:.0%})" if drift_detected else "no_drift"
                }

        except Exception as e:
            # Table might not exist yet - that's fine
            if "ml_predictions" in str(e):
                return {
                    "drift_detected": False,
                    "reason": "no_prediction_history",
                    "predictions_checked": 0
                }
            logger.error(f"[ML_TRIGGER] Error checking drift: {e}")
            return {"error": str(e), "drift_detected": False}

    def _categorize_disposition(self, disposition: str) -> str:
        """Categorize disposition into benign/suspicious/malicious."""
        if not disposition:
            return "unknown"
        disposition = disposition.lower()
        if disposition in ('benign', 'false_positive'):
            return "benign"
        elif disposition in ('suspicious', 'inconclusive'):
            return "suspicious"
        elif disposition in ('malicious', 'true_positive'):
            return "malicious"
        return "unknown"


# =============================================================================
# TRAINING RUNNER
# =============================================================================

async def run_triggered_training(force: bool = False) -> Dict[str, Any]:
    """
    Run training if triggers are met (or forced).

    This is the main entry point for batch training.

    Args:
        force: If True, train regardless of trigger status

    Returns:
        Dict with training result or skip reason
    """
    from services.ml_classifier import get_ml_classifier
    from services.postgres_db import postgres_db

    tracker = TrainingBucketTracker()

    # Check if we should train
    if not force:
        status = await tracker.get_bucket_status()

        if status.get("error"):
            return {"status": "error", "error": status["error"]}

        if not status["should_train"]:
            # Also check drift
            drift = await tracker.check_drift()
            if drift.get("drift_detected"):
                logger.info(f"[ML_TRIGGER] Drift detected: {drift['reason']}")
            else:
                return {
                    "status": "skipped",
                    "reason": status["reason"],
                    "bucket_size": status["bucket_size"],
                    "hours_since_training": status["hours_since_training"]
                }

    # Run training
    logger.info("[ML_TRIGGER] Training triggered, starting batch training...")

    try:
        classifier = get_ml_classifier()
        result = await classifier.train(days_back=DEFAULT_CONFIG.training_days_back)

        if result.get("status") == "insufficient_data":
            return {
                "status": "skipped",
                "reason": "insufficient_data",
                "samples_found": result.get("samples_found"),
                "samples_needed": result.get("samples_needed")
            }

        # Log training run
        await _log_training_run(
            status="success",
            samples_used=result.get("training_samples", 0),
            accuracy=result.get("accuracy"),
            trigger_reason=force and "manual" or "triggered"
        )

        logger.info(f"[ML_TRIGGER] Training completed: {result.get('training_samples')} samples, {result.get('accuracy', 0):.1%} accuracy")

        return {
            "status": "trained",
            "samples_used": result.get("training_samples"),
            "accuracy": result.get("accuracy"),
            "model_version": result.get("version")
        }

    except Exception as e:
        logger.error(f"[ML_TRIGGER] Training failed: {e}")
        await _log_training_run(status="failed", error=str(e))
        return {"status": "error", "error": str(e)}


async def _log_training_run(
    status: str,
    samples_used: int = 0,
    accuracy: float = None,
    trigger_reason: str = None,
    error: str = None
):
    """Log a training run to the database."""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        return

    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute("""
                INSERT INTO ml_training_runs (
                    trained_at, status, samples_used, accuracy,
                    trigger_reason, error_message
                ) VALUES (NOW(), $1, $2, $3, $4, $5)
            """, status, samples_used, accuracy, trigger_reason, error)
    except Exception as e:
        logger.warning(f"[ML_TRIGGER] Failed to log training run: {e}")


async def log_prediction(
    alert_id: str,
    predicted_disposition: str,
    confidence: float,
    model_version: str
):
    """
    Log an ML prediction for drift detection.

    Call this after each prediction to enable drift monitoring.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        return

    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute("""
                INSERT INTO ml_predictions (
                    alert_id, predicted_disposition, confidence,
                    model_version, created_at
                ) VALUES ($1, $2, $3, $4, NOW())
                ON CONFLICT (alert_id) DO UPDATE SET
                    predicted_disposition = $2,
                    confidence = $3,
                    model_version = $4,
                    created_at = NOW()
            """, alert_id, predicted_disposition, confidence, model_version)
    except Exception as e:
        # Don't fail on logging errors
        logger.debug(f"[ML_TRIGGER] Failed to log prediction: {e}")


async def record_analyst_feedback(
    alert_id: str,
    analyst_disposition: str,
    resolved_by: str,
    investigation_id: str = None
):
    """
    Record analyst feedback for ML learning.

    Call this when an analyst resolves an alert/investigation to update
    the ml_predictions table with the actual outcome. This enables:
    1. Drift detection (compare ML prediction vs actual)
    2. Model accuracy tracking
    3. Training data improvement

    Args:
        alert_id: Alert ID that was resolved
        analyst_disposition: Final disposition (true_positive, false_positive, etc.)
        resolved_by: Username of analyst who resolved
        investigation_id: Optional investigation ID if resolved via investigation
    """
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        return {"recorded": False, "reason": "no_database"}

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Update the prediction with actual disposition
            result = await conn.execute("""
                UPDATE ml_predictions
                SET actual_disposition = $1,
                    resolved_by = $2,
                    resolved_at = NOW(),
                    investigation_id = $3
                WHERE alert_id = $4
            """, analyst_disposition, resolved_by, investigation_id, alert_id)

            rows_affected = int(result.split()[-1]) if result else 0

            if rows_affected > 0:
                logger.info(
                    f"[ML_FEEDBACK] Recorded analyst feedback for alert {alert_id}: "
                    f"{analyst_disposition} (by {resolved_by})"
                )

                # Check drift after recording feedback
                tracker = TrainingBucketTracker()
                drift = await tracker.check_drift()

                return {
                    "recorded": True,
                    "alert_id": alert_id,
                    "disposition": analyst_disposition,
                    "drift_status": drift
                }
            else:
                # No ML prediction was made for this alert
                logger.debug(f"[ML_FEEDBACK] No ML prediction found for alert {alert_id}")
                return {
                    "recorded": False,
                    "reason": "no_prediction_found",
                    "alert_id": alert_id
                }

    except Exception as e:
        logger.warning(f"[ML_FEEDBACK] Failed to record feedback: {e}")
        return {"recorded": False, "error": str(e)}


async def get_ml_accuracy_report(days_back: int = 30) -> Dict[str, Any]:
    """
    Generate an ML accuracy report comparing predictions to analyst verdicts.

    Returns:
        Dict with accuracy metrics, confusion matrix, and recommendations
    """
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        return {"error": "Database not connected"}

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get all predictions with feedback
            results = await conn.fetch("""
                SELECT
                    predicted_disposition,
                    actual_disposition,
                    confidence,
                    model_version,
                    created_at,
                    resolved_at
                FROM ml_predictions
                WHERE actual_disposition IS NOT NULL
                  AND created_at > NOW() - INTERVAL '%s days'
                ORDER BY created_at DESC
            """ % days_back)

            if not results:
                return {
                    "status": "no_data",
                    "predictions_with_feedback": 0,
                    "message": "No predictions with analyst feedback yet"
                }

            # Calculate metrics
            total = len(results)
            correct = 0
            by_disposition = {}
            confidence_buckets = {"high": {"correct": 0, "total": 0}, "medium": {"correct": 0, "total": 0}, "low": {"correct": 0, "total": 0}}

            for r in results:
                predicted = r['predicted_disposition']
                actual = r['actual_disposition']
                conf = r['confidence']

                # Normalize for comparison
                pred_cat = _categorize_disposition(predicted)
                actual_cat = _categorize_disposition(actual)

                is_correct = pred_cat == actual_cat
                if is_correct:
                    correct += 1

                # Track by disposition
                if actual not in by_disposition:
                    by_disposition[actual] = {"correct": 0, "total": 0}
                by_disposition[actual]["total"] += 1
                if is_correct:
                    by_disposition[actual]["correct"] += 1

                # Track by confidence bucket
                if conf >= 0.8:
                    bucket = "high"
                elif conf >= 0.5:
                    bucket = "medium"
                else:
                    bucket = "low"
                confidence_buckets[bucket]["total"] += 1
                if is_correct:
                    confidence_buckets[bucket]["correct"] += 1

            accuracy = correct / total if total > 0 else 0

            # Calculate per-bucket accuracy
            for bucket in confidence_buckets:
                b = confidence_buckets[bucket]
                b["accuracy"] = b["correct"] / b["total"] if b["total"] > 0 else None

            # Calculate per-disposition accuracy
            for disp in by_disposition:
                d = by_disposition[disp]
                d["accuracy"] = d["correct"] / d["total"] if d["total"] > 0 else None

            return {
                "status": "success",
                "period_days": days_back,
                "total_predictions": total,
                "overall_accuracy": round(accuracy, 3),
                "by_confidence": confidence_buckets,
                "by_disposition": by_disposition,
                "recommendations": _generate_recommendations(accuracy, confidence_buckets, by_disposition)
            }

    except Exception as e:
        logger.error(f"[ML_FEEDBACK] Error generating accuracy report: {e}")
        return {"error": str(e)}


def _categorize_disposition(disposition: str) -> str:
    """Categorize disposition into benign/suspicious/malicious for comparison."""
    if not disposition:
        return "unknown"
    disposition = disposition.lower()
    if disposition in ('benign', 'false_positive', 'benign_activity'):
        return "benign"
    elif disposition in ('suspicious', 'inconclusive', 'needs_escalation'):
        return "suspicious"
    elif disposition in ('malicious', 'true_positive', 'verified_malicious'):
        return "malicious"
    return "unknown"


def _generate_recommendations(
    accuracy: float,
    confidence_buckets: Dict,
    by_disposition: Dict
) -> List[str]:
    """Generate recommendations based on accuracy analysis."""
    recommendations = []

    if accuracy < 0.6:
        recommendations.append("Overall accuracy is low - consider retraining with more recent data")

    # Check high-confidence accuracy
    high = confidence_buckets.get("high", {})
    if high.get("accuracy") and high["accuracy"] < 0.8:
        recommendations.append(
            f"High-confidence predictions are only {high['accuracy']:.0%} accurate - "
            "model may be overconfident"
        )

    # Check for bias in specific dispositions
    for disp, stats in by_disposition.items():
        if stats.get("total", 0) >= 5 and stats.get("accuracy", 1) < 0.5:
            recommendations.append(
                f"Poor accuracy on '{disp}' alerts ({stats['accuracy']:.0%}) - "
                "may need more training examples"
            )

    if not recommendations:
        recommendations.append("Model performance is healthy")

    return recommendations


# =============================================================================
# SCHEDULED TRIGGER CHECK
# =============================================================================

class MLTrainingScheduler:
    """
    Background scheduler that checks training triggers periodically.

    Runs nightly to check if time-based trigger should fire.
    """

    def __init__(self, check_interval_hours: int = 6):
        self.check_interval = check_interval_hours * 3600  # Convert to seconds
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Start the scheduler."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info(f"[ML_SCHEDULER] Started (checking every {self.check_interval // 3600}h)")

    async def stop(self):
        """Stop the scheduler."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[ML_SCHEDULER] Stopped")

    async def _run_loop(self):
        """Main scheduler loop."""
        while self._running:
            try:
                await asyncio.sleep(self.check_interval)

                if not self._running:
                    break

                logger.info("[ML_SCHEDULER] Checking training triggers...")
                result = await run_triggered_training(force=False)

                if result["status"] == "trained":
                    logger.info(f"[ML_SCHEDULER] Auto-training completed: {result}")
                elif result["status"] == "skipped":
                    logger.debug(f"[ML_SCHEDULER] Training skipped: {result['reason']}")
                else:
                    logger.warning(f"[ML_SCHEDULER] Training result: {result}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[ML_SCHEDULER] Error in scheduler loop: {e}")
                await asyncio.sleep(60)  # Brief pause on error


# Singleton scheduler instance
_scheduler: Optional[MLTrainingScheduler] = None


def get_training_scheduler() -> MLTrainingScheduler:
    """Get or create the training scheduler singleton."""
    global _scheduler
    if _scheduler is None:
        _scheduler = MLTrainingScheduler()
    return _scheduler


# Singleton tracker instance
_tracker: Optional[TrainingBucketTracker] = None


def get_bucket_tracker() -> TrainingBucketTracker:
    """Get or create the bucket tracker singleton."""
    global _tracker
    if _tracker is None:
        _tracker = TrainingBucketTracker()
    return _tracker
