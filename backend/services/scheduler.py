# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Polling Scheduler Service
Background scheduler for automated integration polling
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import asyncio


class PollingScheduler:
    def __init__(self, db, ingestion_service):
        self.scheduler = AsyncIOScheduler()
        self.db = db
        self.ingestion_service = ingestion_service
        self.running = False
    
    async def start(self):
        """Start the scheduler and load all polling jobs"""
        if self.running:
            return
        
        print("[POLL] Starting polling scheduler...")
        
        # Load all enabled integrations with polling enabled
        integrations = await self.db.get_polling_integrations()
        
        for integration in integrations:
            await self.add_polling_job(integration)
        
        self.scheduler.start()
        self.running = True
        
        print(f"[OK] Scheduler started with {len(integrations)} polling jobs")
        
        # Log scheduler start
        await self.db.create_log({
            "level": "info",
            "message": f"Polling scheduler started with {len(integrations)} jobs",
            "source": "scheduler",
            "details": {"job_count": len(integrations)}
        })
    
    async def stop(self):
        """Stop the scheduler"""
        if not self.running:
            return
        
        print("[STOP] Stopping polling scheduler...")
        self.scheduler.shutdown(wait=True)
        self.running = False
        
        # Log scheduler stop
        await self.db.create_log({
            "level": "info",
            "message": "Polling scheduler stopped",
            "source": "scheduler"
        })
        
        print("[OK] Scheduler stopped")
    
    async def add_polling_job(self, integration: dict):
        """
        Add a polling job for an integration
        
        Args:
            integration: Integration configuration dict
        """
        integration_id = integration["integration_id"]
        job_id = f"poll_{integration_id}"
        interval_minutes = integration.get("poll_interval_minutes", 60)
        
        # Remove existing job if it exists
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)
        
        # Add new job
        self.scheduler.add_job(
            self.poll_job,
            trigger=IntervalTrigger(minutes=interval_minutes),
            args=[integration_id],
            id=job_id,
            name=f"Poll {integration['name']}",
            replace_existing=True,
            max_instances=1  # Prevent concurrent runs
        )
        
        print(f"[JOB] Added polling job: {integration['name']} (every {interval_minutes} min)")
    
    async def remove_polling_job(self, integration_id: str):
        """
        Remove a polling job
        
        Args:
            integration_id: Integration identifier
        """
        job_id = f"poll_{integration_id}"
        
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)
            print(f"[JOB] Removed polling job: {integration_id}")
    
    async def update_polling_job(self, integration: dict):
        """
        Update a polling job (remove and re-add)
        
        Args:
            integration: Integration configuration dict
        """
        await self.remove_polling_job(integration["integration_id"])
        
        if integration.get("enabled") and integration.get("poll_enabled"):
            await self.add_polling_job(integration)
    
    async def poll_job(self, integration_id: str):
        """
        Execute polling job for an integration
        
        Args:
            integration_id: Integration identifier
        """
        print(f"[POLL] Polling integration: {integration_id}")
        
        try:
            result = await self.ingestion_service.poll_integration(integration_id)
            
            if result["status"] == "success":
                print(f"[OK] Poll successful: {result.get('alerts_created', 0)} new alerts")
            else:
                print(f"[WARN] Poll warning: {result.get('message', 'Unknown')}")
                
        except Exception as e:
            print(f"[ERROR] Poll failed: {str(e)}")
            
            # Log error
            await self.db.create_log({
                "level": "error",
                "message": f"Polling job failed: {str(e)}",
                "source": "scheduler",
                "details": {
                    "integration_id": integration_id,
                    "error": str(e)
                }
            })
    
    async def trigger_manual_poll(self, integration_id: str) -> dict:
        """
        Manually trigger a poll for an integration (bypasses schedule)
        
        Args:
            integration_id: Integration identifier
            
        Returns:
            Poll result dict
        """
        print(f"[POLL] Manual poll triggered: {integration_id}")
        
        result = await self.ingestion_service.poll_integration(integration_id)
        
        return result
    
    def get_job_status(self, integration_id: str) -> dict:
        """
        Get status of a polling job
        
        Args:
            integration_id: Integration identifier
            
        Returns:
            Job status dict
        """
        job_id = f"poll_{integration_id}"
        job = self.scheduler.get_job(job_id)
        
        if not job:
            return {
                "exists": False,
                "message": "Job not found"
            }
        
        return {
            "exists": True,
            "name": job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            "trigger": str(job.trigger)
        }
    
    def list_jobs(self) -> list:
        """
        List all polling jobs
        
        Returns:
            List of job info dicts
        """
        jobs = []
        
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger)
            })
        
        return jobs
