# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
ML Server Client
Connects to remote ML inference server (3090 Ti) for:
- Text embeddings
- Anomaly detection
- Threat classification
- Semantic similarity
"""

import os
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)


class MLServerClient:
    """
    Client for the remote ML inference server.
    Handles connection, retries, and fallbacks.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        enabled: Optional[bool] = None,
        timeout: float = 30.0
    ):
        self.host = host or os.getenv("ML_SERVER_HOST", "localhost")
        self.port = port or int(os.getenv("ML_SERVER_PORT", "8100"))
        self.enabled = enabled if enabled is not None else os.getenv("ML_SERVER_ENABLED", "true").lower() == "true"
        self.timeout = timeout
        self.base_url = f"http://{self.host}:{self.port}"

        # Stats
        self._request_count = 0
        self._error_count = 0
        self._last_health_check: Optional[datetime] = None
        self._is_healthy: bool = False

        logger.info(f"ML Client initialized: {self.base_url} (enabled={self.enabled})")

    async def _request(
        self,
        method: str,
        endpoint: str,
        json: Optional[Dict] = None,
        timeout: Optional[float] = None
    ) -> Optional[Dict]:
        """Make HTTP request to ML server."""
        if not self.enabled:
            logger.debug("ML Server disabled, skipping request")
            return None

        url = f"{self.base_url}{endpoint}"
        timeout = timeout or self.timeout

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                self._request_count += 1

                if method == "GET":
                    response = await client.get(url)
                elif method == "POST":
                    response = await client.post(url, json=json)
                else:
                    raise ValueError(f"Unsupported method: {method}")

                response.raise_for_status()
                return response.json()

        except httpx.TimeoutException:
            self._error_count += 1
            logger.warning(f"ML Server timeout: {url}")
            return None
        except httpx.ConnectError:
            self._error_count += 1
            logger.warning(f"ML Server connection failed: {url}")
            return None
        except httpx.HTTPStatusError as e:
            self._error_count += 1
            logger.warning(f"ML Server error {e.response.status_code}: {url}")
            return None
        except Exception as e:
            self._error_count += 1
            logger.error(f"ML Server unexpected error: {e}")
            return None

    async def health_check(self) -> Dict[str, Any]:
        """Check ML server health and get GPU stats."""
        result = await self._request("GET", "/health", timeout=5.0)
        self._last_health_check = datetime.utcnow()
        self._is_healthy = result is not None and result.get("status") == "healthy"

        if result:
            return result

        return {
            "status": "unreachable",
            "gpu_available": False,
            "models_loaded": [],
            "error": "ML Server not responding"
        }

    async def embed(
        self,
        text: str,
        model: str = "default"
    ) -> Optional[List[float]]:
        """
        Generate embedding for a single text.

        Args:
            text: Text to embed
            model: "default" (fast) or "large" (higher quality)

        Returns:
            List of floats (embedding vector) or None if failed
        """
        result = await self._request("POST", "/embed", json={
            "text": text,
            "model": model
        })

        if result:
            logger.debug(f"Embedding generated in {result.get('inference_ms', 0):.1f}ms")
            return result.get("embedding")
        return None

    async def embed_batch(
        self,
        texts: List[str],
        model: str = "default"
    ) -> Optional[List[List[float]]]:
        """
        Generate embeddings for multiple texts (optimized).

        Args:
            texts: List of texts to embed
            model: "default" (fast) or "large" (higher quality)

        Returns:
            List of embedding vectors or None if failed
        """
        if not texts:
            return []

        result = await self._request("POST", "/embed/batch", json={
            "texts": texts,
            "model": model
        })

        if result:
            logger.debug(f"Batch embeddings ({len(texts)}) in {result.get('inference_ms', 0):.1f}ms")
            return result.get("embeddings")
        return None

    async def similarity(
        self,
        text1: str,
        text2: str,
        model: str = "default"
    ) -> Optional[float]:
        """
        Compute semantic similarity between two texts.

        Args:
            text1: First text
            text2: Second text
            model: Embedding model to use

        Returns:
            Similarity score (0-1) or None if failed
        """
        result = await self._request("POST", "/similarity", json={
            "text1": text1,
            "text2": text2,
            "model": model
        })

        if result:
            return result.get("similarity")
        return None

    async def detect_anomaly(
        self,
        features: List[float],
        threshold: float = -0.5
    ) -> Optional[Dict[str, Any]]:
        """
        Detect if a feature vector is anomalous.

        Args:
            features: Numeric feature vector
            threshold: Anomaly threshold (lower = more sensitive)

        Returns:
            Dict with is_anomaly, score, or None if failed
        """
        result = await self._request("POST", "/anomaly/detect", json={
            "features": features,
            "threshold": threshold
        })

        if result:
            return {
                "is_anomaly": result.get("is_anomaly", False),
                "score": result.get("score", 0.0)
            }
        return None

    async def classify_threat(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Classify threat level from text.

        Args:
            text: Alert/event text to classify
            context: Optional context (source, severity hints, etc.)

        Returns:
            Dict with threat_level, confidence, indicators or None
        """
        result = await self._request("POST", "/classify/threat", json={
            "text": text,
            "context": context or {}
        })

        if result:
            return {
                "threat_level": result.get("threat_level", "unknown"),
                "confidence": result.get("confidence", 0.0),
                "indicators": result.get("indicators", [])
            }
        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return {
            "enabled": self.enabled,
            "host": self.host,
            "port": self.port,
            "requests": self._request_count,
            "errors": self._error_count,
            "error_rate": self._error_count / max(1, self._request_count),
            "is_healthy": self._is_healthy,
            "last_health_check": self._last_health_check.isoformat() if self._last_health_check else None
        }


# Global singleton instance
_ml_client: Optional[MLServerClient] = None


def get_ml_client() -> MLServerClient:
    """Get or create the ML client singleton."""
    global _ml_client
    if _ml_client is None:
        _ml_client = MLServerClient()
    return _ml_client


async def embed_text(text: str, model: str = "default") -> Optional[List[float]]:
    """Convenience function to embed text."""
    client = get_ml_client()
    return await client.embed(text, model)


async def embed_texts(texts: List[str], model: str = "default") -> Optional[List[List[float]]]:
    """Convenience function to embed multiple texts."""
    client = get_ml_client()
    return await client.embed_batch(texts, model)


async def get_similarity(text1: str, text2: str) -> Optional[float]:
    """Convenience function to get similarity."""
    client = get_ml_client()
    return await client.similarity(text1, text2)


async def classify_threat_level(text: str) -> Optional[Dict[str, Any]]:
    """Convenience function to classify threat."""
    client = get_ml_client()
    return await client.classify_threat(text)
