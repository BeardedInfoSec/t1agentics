# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
ML Alert Classifier API Routes

Endpoints for training, managing, and querying the ML alert classifier.
The ML layer provides confidence scores that INFORM Riggs, not replace his reasoning.

Training Model:
- Training is BATCH-TRIGGERED, not continuous
- Triggers: bucket size, time window, or drift detection
- Inference stays real-time
- ML influence capped at ±15%
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks, Depends
from dependencies.auth import get_current_user
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ml", tags=["ML Classifier"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Request/Response Models
# ============================================================================

class TrainRequest(BaseModel):
    """Request to train the ML classifier"""
    force: bool = Field(default=False, description="Force training regardless of trigger status")


class PredictRequest(BaseModel):
    """Request to predict disposition for an alert"""
    alert_id: str = Field(..., description="Alert ID to predict")


class PredictBatchRequest(BaseModel):
    """Request to predict dispositions for multiple alerts"""
    alert_ids: List[str] = Field(..., description="Alert IDs to predict", max_items=100)


class MLPredictionResponse(BaseModel):
    """ML prediction result"""
    alert_id: str
    disposition: str
    confidence: float
    probabilities: Dict[str, float]
    features_used: List[str]
    model_version: str


# ============================================================================
# STATUS & BUCKET ENDPOINTS
# ============================================================================

@router.get("/status")
async def get_ml_status():
    """
    Get the current status of the ML classifier.

    Returns model info, training bucket status, and readiness.
    """
    from services.ml_classifier import get_ml_classifier
    from services.ml_training_trigger import get_bucket_tracker

    try:
        classifier = get_ml_classifier()
        model_info = classifier.get_model_info()

        # Get training bucket status
        tracker = get_bucket_tracker()
        bucket_status = await tracker.get_bucket_status()

        return {
            "status": "ready" if model_info.get('ready') else "not_trained",
            "model": model_info,
            "training_bucket": bucket_status
        }
    except Exception as e:
        logger.error(f"Failed to get ML status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/bucket")
async def get_training_bucket():
    """
    Get training bucket status.

    Shows how many new alerts have accumulated since last training,
    and whether any training triggers are met.
    """
    from services.ml_training_trigger import get_bucket_tracker

    try:
        tracker = get_bucket_tracker()
        return await tracker.get_bucket_status()
    except Exception as e:
        logger.error(f"Failed to get bucket status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/drift")
async def check_drift():
    """
    Check for confidence drift between ML predictions and analyst verdicts.

    Returns drift metrics and whether threshold is exceeded.
    """
    from services.ml_training_trigger import get_bucket_tracker

    try:
        tracker = get_bucket_tracker()
        return await tracker.check_drift()
    except Exception as e:
        logger.error(f"Failed to check drift: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# TRAINING ENDPOINTS
# ============================================================================

@router.post("/train")
async def train_classifier(request: TrainRequest):
    """
    Train the ML classifier (batch-triggered).

    Training only runs if triggers are met:
    - Bucket reaches threshold (50 new alerts)
    - Time window elapsed (24h) with minimum bucket
    - Drift detected
    - Or force=True

    This is NOT continuous training - it's event-driven batches.
    """
    from services.ml_training_trigger import run_triggered_training

    try:
        result = await run_triggered_training(force=request.force)

        if result["status"] == "skipped":
            return {
                "status": "skipped",
                "message": f"Training not triggered: {result['reason']}",
                **result
            }
        elif result["status"] == "error":
            raise HTTPException(status_code=500, detail=result.get("error", "Training failed"))
        else:
            return {
                "status": "trained",
                "message": "ML classifier trained successfully",
                **result
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"ML training failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/training/history")
async def get_training_history(
    limit: int = Query(default=10, ge=1, le=100)
):
    """
    Get history of ML training runs.

    Shows when training occurred, trigger reasons, and accuracy.
    """
    from services.postgres_db import postgres_db

    try:
        if not postgres_db.pool:
            return {"error": "Database not connected", "runs": []}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    trained_at, status, samples_used, accuracy,
                    trigger_reason, error_message, model_version,
                    training_duration_ms
                FROM ml_training_runs
                ORDER BY trained_at DESC
                LIMIT $1
            """, limit)

            return {
                "runs": [
                    {
                        "trained_at": r['trained_at'].isoformat() if r['trained_at'] else None,
                        "status": r['status'],
                        "samples_used": r['samples_used'],
                        "accuracy": float(r['accuracy']) if r['accuracy'] else None,
                        "trigger_reason": r['trigger_reason'],
                        "error": r['error_message'],
                        "model_version": r['model_version'],
                        "duration_ms": r['training_duration_ms']
                    }
                    for r in rows
                ]
            }

    except Exception as e:
        logger.error(f"Failed to get training history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# PREDICTION ENDPOINTS
# ============================================================================

@router.post("/predict")
async def predict_single(request: PredictRequest):
    """
    Get ML prediction for a single alert.

    Returns the predicted disposition and confidence score.
    Prediction is logged for drift detection.
    """
    from services.ml_classifier import get_ml_classifier
    from services.ml_training_trigger import log_prediction
    from services.postgres_db import postgres_db
    import json

    try:
        classifier = get_ml_classifier()

        if not classifier.is_ready():
            raise HTTPException(
                status_code=400,
                detail="ML classifier not trained. Call POST /api/v1/ml/train with force=true first."
            )

        # Fetch alert
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id::text = $1 OR alert_id = $1",
                request.alert_id
            )

            if not row:
                raise HTTPException(status_code=404, detail="Alert not found")

            alert = dict(row)
            if isinstance(alert.get('raw_event'), str):
                try:
                    alert['raw_event'] = json.loads(alert['raw_event'])
                except:
                    pass

        # Get prediction
        prediction = classifier.predict(alert)

        if not prediction:
            raise HTTPException(status_code=500, detail="Prediction failed")

        # Log prediction for drift detection
        await log_prediction(
            alert_id=str(alert.get('id')),
            predicted_disposition=prediction.disposition,
            confidence=prediction.confidence,
            model_version=prediction.model_version
        )

        return MLPredictionResponse(
            alert_id=request.alert_id,
            disposition=prediction.disposition,
            confidence=prediction.confidence,
            probabilities=prediction.probabilities,
            features_used=prediction.features_used,
            model_version=prediction.model_version
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict/batch")
async def predict_batch(request: PredictBatchRequest):
    """
    Get ML predictions for multiple alerts.

    Returns predictions for all specified alerts.
    All predictions are logged for drift detection.
    """
    from services.ml_classifier import get_ml_classifier
    from services.ml_training_trigger import log_prediction
    from services.postgres_db import postgres_db
    import json

    try:
        classifier = get_ml_classifier()

        if not classifier.is_ready():
            raise HTTPException(
                status_code=400,
                detail="ML classifier not trained. Call POST /api/v1/ml/train with force=true first."
            )

        # Fetch alerts
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM alerts
                WHERE id::text = ANY($1) OR alert_id = ANY($1)
            """, request.alert_ids)

        predictions = []
        errors = []

        for row in rows:
            alert = dict(row)
            alert_id = str(alert.get('id'))

            if isinstance(alert.get('raw_event'), str):
                try:
                    alert['raw_event'] = json.loads(alert['raw_event'])
                except:
                    pass

            prediction = classifier.predict(alert)

            if prediction:
                predictions.append({
                    "alert_id": alert_id,
                    "disposition": prediction.disposition,
                    "confidence": prediction.confidence,
                    "probabilities": prediction.probabilities,
                    "features_used": prediction.features_used
                })

                # Log for drift detection
                await log_prediction(
                    alert_id=alert_id,
                    predicted_disposition=prediction.disposition,
                    confidence=prediction.confidence,
                    model_version=prediction.model_version
                )
            else:
                errors.append({
                    "alert_id": alert_id,
                    "error": "Prediction failed"
                })

        return {
            "predictions": predictions,
            "errors": errors,
            "model_version": classifier.metadata.get('version', 'unknown')
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# MODEL MANAGEMENT
# ============================================================================

@router.get("/model/features")
async def get_model_features():
    """
    Get information about features used by the ML model.

    Useful for understanding what the model considers.
    """
    from services.ml_classifier import AlertFeatureExtractor

    extractor = AlertFeatureExtractor()

    return {
        "known_sources": extractor.KNOWN_SOURCES,
        "severities": extractor.SEVERITIES,
        "ioc_types": extractor.IOC_TYPES,
        "keyword_categories": ["phishing", "malware", "suspicious", "legitimate", "test"],
        "text_features": "TF-IDF vectorization (max 100 features)",
        "temporal_features": ["hour_of_day", "day_of_week", "is_weekend", "is_business_hours"],
        "ml_influence_cap": "±15% maximum confidence adjustment"
    }


@router.delete("/model")
async def delete_model():
    """
    Delete the trained ML model.

    Forces a fresh training on next triggered train.
    """
    from services.ml_classifier import MODEL_PATH, VECTORIZER_PATH, METADATA_PATH
    import os

    try:
        deleted = []
        for path in [MODEL_PATH, VECTORIZER_PATH, METADATA_PATH]:
            if os.path.exists(path):
                os.remove(path)
                deleted.append(os.path.basename(path))

        # Reset the singleton
        from services.ml_classifier import get_ml_classifier
        classifier = get_ml_classifier()
        classifier.model = None
        classifier.vectorizer = None
        classifier._loaded = False

        return {
            "status": "deleted",
            "files_removed": deleted
        }

    except Exception as e:
        logger.error(f"Failed to delete model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_ml_stats():
    """
    Get ML classifier performance statistics.

    Shows accuracy, prediction counts, drift metrics, and disposition distribution.
    """
    from services.ml_classifier import get_ml_classifier
    from services.ml_training_trigger import get_bucket_tracker
    from services.postgres_db import postgres_db

    try:
        classifier = get_ml_classifier()
        model_info = classifier.get_model_info()

        # Get prediction stats
        prediction_stats = {"total": 0, "today": 0}
        if postgres_db.pool:
            try:
                async with postgres_db.tenant_acquire() as conn:
                    total = await conn.fetchval("SELECT COUNT(*) FROM ml_predictions")
                    today = await conn.fetchval("""
                        SELECT COUNT(*) FROM ml_predictions
                        WHERE created_at > NOW() - INTERVAL '24 hours'
                    """)
                    prediction_stats = {"total": total or 0, "today": today or 0}
            except:
                pass

        # Get drift status
        tracker = get_bucket_tracker()
        drift = await tracker.check_drift()

        return {
            "model": model_info,
            "predictions": prediction_stats,
            "drift": drift,
            "influence_cap": "±15%",
            "training_mode": "batch_triggered"
        }

    except Exception as e:
        logger.error(f"Failed to get ML stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CONFIGURATION
# ============================================================================

@router.get("/dashboard")
async def get_ml_dashboard():
    """
    Get comprehensive ML dashboard data.

    Includes:
    - Model status and accuracy
    - Prediction counts and distribution
    - Auto-resolve statistics
    - Drift metrics
    - Training history summary
    - Performance over time
    """
    from services.ml_classifier import get_ml_classifier
    from services.ml_training_trigger import get_bucket_tracker, DEFAULT_CONFIG
    from services.postgres_db import postgres_db

    try:
        classifier = get_ml_classifier()
        model_info = classifier.get_model_info()

        dashboard = {
            "model": model_info,
            "predictions": {"total": 0, "today": 0, "week": 0},
            "disposition_distribution": {},
            "auto_resolved": {"total": 0, "today": 0},
            "drift": {"status": "unknown", "score": 0},
            "training": {"last_run": None, "total_runs": 0, "avg_accuracy": 0},
            "config": {
                "auto_resolve_threshold": 0.90,
                "anomaly_threshold": 0.3,
                "influence_cap": "±15%"
            }
        }

        if postgres_db.pool:
            async with postgres_db.tenant_acquire() as conn:
                # Prediction counts
                try:
                    dashboard["predictions"]["total"] = await conn.fetchval(
                        "SELECT COUNT(*) FROM ml_predictions"
                    ) or 0
                    dashboard["predictions"]["today"] = await conn.fetchval(
                        "SELECT COUNT(*) FROM ml_predictions WHERE created_at > NOW() - INTERVAL '24 hours'"
                    ) or 0
                    dashboard["predictions"]["week"] = await conn.fetchval(
                        "SELECT COUNT(*) FROM ml_predictions WHERE created_at > NOW() - INTERVAL '7 days'"
                    ) or 0
                except:
                    pass

                # Disposition distribution (last 30 days)
                try:
                    rows = await conn.fetch("""
                        SELECT predicted_disposition, COUNT(*) as count
                        FROM ml_predictions
                        WHERE created_at > NOW() - INTERVAL '30 days'
                        GROUP BY predicted_disposition
                        ORDER BY count DESC
                    """)
                    dashboard["disposition_distribution"] = {
                        r['predicted_disposition']: r['count'] for r in rows
                    }
                except:
                    pass

                # Auto-resolve counts (from agent executions with ml_auto_resolved flag)
                try:
                    auto_count = await conn.fetchval("""
                        SELECT COUNT(*) FROM agent_executions
                        WHERE result::jsonb->>'ml_auto_resolved' = 'true'
                    """)
                    auto_today = await conn.fetchval("""
                        SELECT COUNT(*) FROM agent_executions
                        WHERE result::jsonb->>'ml_auto_resolved' = 'true'
                        AND started_at > NOW() - INTERVAL '24 hours'
                    """)
                    dashboard["auto_resolved"] = {
                        "total": auto_count or 0,
                        "today": auto_today or 0
                    }
                except:
                    pass

                # Training history
                try:
                    training_stats = await conn.fetchrow("""
                        SELECT
                            COUNT(*) as total_runs,
                            MAX(trained_at) as last_run,
                            AVG(accuracy) as avg_accuracy
                        FROM ml_training_runs
                        WHERE status = 'completed'
                    """)
                    if training_stats:
                        dashboard["training"] = {
                            "total_runs": training_stats['total_runs'] or 0,
                            "last_run": training_stats['last_run'].isoformat() if training_stats['last_run'] else None,
                            "avg_accuracy": round(float(training_stats['avg_accuracy'] or 0), 4)
                        }
                except:
                    pass

        # Get drift status
        try:
            tracker = get_bucket_tracker()
            drift = await tracker.check_drift()
            dashboard["drift"] = drift
        except:
            pass

        return dashboard

    except Exception as e:
        logger.error(f"Failed to get ML dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config")
async def get_ml_config():
    """
    Get ML training trigger configuration.

    Shows bucket size threshold, time window, drift threshold, etc.
    """
    from services.ml_training_trigger import DEFAULT_CONFIG

    return {
        "training_triggers": {
            "min_bucket_size": DEFAULT_CONFIG.min_bucket_size,
            "max_hours_since_training": DEFAULT_CONFIG.max_hours_since_training,
            "min_bucket_for_time_trigger": DEFAULT_CONFIG.min_bucket_for_time_trigger,
            "drift_threshold": DEFAULT_CONFIG.drift_threshold,
            "min_predictions_for_drift": DEFAULT_CONFIG.min_predictions_for_drift,
            "training_days_back": DEFAULT_CONFIG.training_days_back
        },
        "influence": {
            "max_confidence_adjustment": "±15%",
            "ml_confidence_threshold": 0.6,
            "description": "ML nudges confidence, never decides. Riggs reasons."
        }
    }


# ============================================================================
# ML FEEDBACK & ACCURACY
# ============================================================================

@router.get("/accuracy")
async def get_ml_accuracy_report(days: int = Query(default=30, ge=1, le=365)):
    """
    Get ML accuracy report comparing predictions to analyst verdicts.

    Shows:
    - Overall accuracy percentage
    - Accuracy by confidence level (high/medium/low)
    - Accuracy by disposition type
    - Recommendations for improving model performance

    Args:
        days: Number of days to analyze (default 30)
    """
    from services.ml_training_trigger import get_ml_accuracy_report as get_report

    try:
        report = await get_report(days_back=days)

        if report.get("error"):
            raise HTTPException(status_code=500, detail=report["error"])

        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get accuracy report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/feedback/summary")
async def get_feedback_summary():
    """
    Get summary of ML feedback collected from analyst resolutions.

    Shows how many predictions have been verified by analysts,
    enabling drift detection and model accuracy tracking.
    """
    from services.postgres_db import postgres_db

    try:
        if not postgres_db.pool:
            raise HTTPException(status_code=500, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            # Get feedback stats
            total_predictions = await conn.fetchval(
                "SELECT COUNT(*) FROM ml_predictions"
            ) or 0

            with_feedback = await conn.fetchval(
                "SELECT COUNT(*) FROM ml_predictions WHERE actual_disposition IS NOT NULL"
            ) or 0

            recent_feedback = await conn.fetchval("""
                SELECT COUNT(*) FROM ml_predictions
                WHERE actual_disposition IS NOT NULL
                AND resolved_at > NOW() - INTERVAL '7 days'
            """) or 0

            # Get match rate
            matches = await conn.fetchval("""
                SELECT COUNT(*) FROM ml_predictions
                WHERE actual_disposition IS NOT NULL
                AND (
                    (predicted_disposition = actual_disposition)
                    OR (predicted_disposition IN ('benign', 'false_positive') AND actual_disposition IN ('benign', 'false_positive', 'benign_activity'))
                    OR (predicted_disposition IN ('malicious', 'true_positive') AND actual_disposition IN ('malicious', 'true_positive', 'verified_malicious'))
                )
            """) or 0

            match_rate = matches / with_feedback if with_feedback > 0 else None

            return {
                "total_predictions": total_predictions,
                "predictions_with_feedback": with_feedback,
                "feedback_rate": round(with_feedback / total_predictions, 3) if total_predictions > 0 else 0,
                "recent_feedback_7d": recent_feedback,
                "match_rate": round(match_rate, 3) if match_rate else None,
                "status": "collecting" if with_feedback < 20 else "sufficient_data"
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get feedback summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/{alert_id}")
async def get_prediction_history(alert_id: str):
    """
    Get ML prediction history for a specific alert.

    Shows the prediction made, confidence level, and if resolved,
    the actual analyst verdict for comparison.
    """
    from services.postgres_db import postgres_db

    try:
        if not postgres_db.pool:
            raise HTTPException(status_code=500, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    mp.id,
                    mp.alert_id,
                    mp.predicted_disposition,
                    mp.confidence,
                    mp.model_version,
                    mp.created_at,
                    mp.actual_disposition,
                    mp.resolved_by,
                    mp.resolved_at,
                    mp.investigation_id,
                    a.title as alert_title,
                    a.severity as alert_severity
                FROM ml_predictions mp
                LEFT JOIN alerts a ON mp.alert_id = a.id
                WHERE mp.alert_id::text = $1
            """, alert_id)

            if not row:
                raise HTTPException(status_code=404, detail="No ML prediction found for this alert")

            # Calculate if prediction was correct
            prediction_correct = None
            if row['actual_disposition']:
                pred_cat = _categorize_for_comparison(row['predicted_disposition'])
                actual_cat = _categorize_for_comparison(row['actual_disposition'])
                prediction_correct = pred_cat == actual_cat

            return {
                "alert_id": str(row['alert_id']),
                "alert_title": row['alert_title'],
                "alert_severity": row['alert_severity'],
                "prediction": {
                    "disposition": row['predicted_disposition'],
                    "confidence": row['confidence'],
                    "model_version": row['model_version'],
                    "timestamp": row['created_at'].isoformat() if row['created_at'] else None
                },
                "feedback": {
                    "actual_disposition": row['actual_disposition'],
                    "resolved_by": row['resolved_by'],
                    "resolved_at": row['resolved_at'].isoformat() if row['resolved_at'] else None,
                    "investigation_id": row['investigation_id'],
                    "prediction_correct": prediction_correct
                } if row['actual_disposition'] else None
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get prediction history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_recent_predictions(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    with_feedback_only: bool = Query(default=False)
):
    """
    Get recent ML predictions with optional filtering.

    Args:
        limit: Maximum number of predictions to return
        offset: Pagination offset
        with_feedback_only: Only return predictions that have analyst feedback
    """
    from services.postgres_db import postgres_db

    try:
        if not postgres_db.pool:
            raise HTTPException(status_code=500, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            feedback_filter = "AND actual_disposition IS NOT NULL" if with_feedback_only else ""

            rows = await conn.fetch(f"""
                SELECT
                    mp.alert_id,
                    mp.predicted_disposition,
                    mp.confidence,
                    mp.model_version,
                    mp.created_at,
                    mp.actual_disposition,
                    mp.resolved_by,
                    mp.resolved_at,
                    a.title as alert_title,
                    a.severity as alert_severity
                FROM ml_predictions mp
                LEFT JOIN alerts a ON mp.alert_id = a.id
                WHERE 1=1 {feedback_filter}
                ORDER BY mp.created_at DESC
                LIMIT $1 OFFSET $2
            """, limit, offset)

            total = await conn.fetchval(f"""
                SELECT COUNT(*) FROM ml_predictions
                WHERE 1=1 {feedback_filter}
            """)

            predictions = []
            for row in rows:
                prediction_correct = None
                if row['actual_disposition']:
                    pred_cat = _categorize_for_comparison(row['predicted_disposition'])
                    actual_cat = _categorize_for_comparison(row['actual_disposition'])
                    prediction_correct = pred_cat == actual_cat

                predictions.append({
                    "alert_id": str(row['alert_id']),
                    "alert_title": row['alert_title'],
                    "severity": row['alert_severity'],
                    "predicted": row['predicted_disposition'],
                    "confidence": row['confidence'],
                    "actual": row['actual_disposition'],
                    "correct": prediction_correct,
                    "predicted_at": row['created_at'].isoformat() if row['created_at'] else None,
                    "resolved_at": row['resolved_at'].isoformat() if row['resolved_at'] else None
                })

            return {
                "predictions": predictions,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(predictions) < total
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get predictions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _categorize_for_comparison(disposition: str) -> str:
    """Categorize disposition for accuracy comparison."""
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
