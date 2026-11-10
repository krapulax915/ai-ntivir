#!/usr/bin/env python3
"""
AI Model Retraining Pipeline
Automated pipeline for retraining and updating AI models
"""

import os
import sys
import json
import logging
import numpy as np
import sqlite3
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

@dataclass
class RetrainingJob:
    """Retraining job configuration"""
    job_id: str
    model_name: str
    data_source: str
    trigger_condition: str
    schedule: str
    auto_deploy: bool
    min_accuracy_threshold: float
    max_training_time: int
    created_at: str
    last_run: Optional[str] = None
    status: str = "pending"

class ModelRetrainingPipeline:
    """Automated model retraining pipeline"""
    
    def __init__(self, models_dir: str = None, data_dir: str = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.ai.model_retraining_pipeline')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.models_dir = models_dir or os.path.join(os.getcwd(), "models")
        self.data_dir = data_dir or os.path.join(os.getcwd(), "training_data")
        
        # Database for retraining jobs
        self.db_path = os.path.join(os.getcwd(), "logs", "retraining_pipeline.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Active jobs
        self.active_jobs: Dict[str, RetrainingJob] = {}
        self.pipeline_running = False
        self.pipeline_thread = None
        
        # Statistics
        self.stats = {
            'total_retrainings': 0,
            'successful_retrainings': 0,
            'failed_retrainings': 0,
            'average_training_time': 0.0,
            'last_retraining': None
        }
        
        self.init_database()
        self.load_jobs()
        self.logger.info("Model retraining pipeline initialized")
    
    def init_database(self):
        """Initialize retraining database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Retraining jobs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS retraining_jobs (
                        job_id TEXT PRIMARY KEY,
                        model_name TEXT NOT NULL,
                        data_source TEXT NOT NULL,
                        trigger_condition TEXT NOT NULL,
                        schedule TEXT NOT NULL,
                        auto_deploy BOOLEAN NOT NULL,
                        min_accuracy_threshold REAL NOT NULL,
                        max_training_time INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        last_run TEXT,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Retraining history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS retraining_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id TEXT NOT NULL,
                        model_name TEXT NOT NULL,
                        start_time TEXT NOT NULL,
                        end_time TEXT,
                        status TEXT NOT NULL,
                        accuracy_before REAL,
                        accuracy_after REAL,
                        training_samples INTEGER,
                        error_message TEXT,
                        model_path TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_retraining_jobs_status ON retraining_jobs(status)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_retraining_history_job_id ON retraining_history(job_id)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize retraining database: {e}")
    
    def create_retraining_job(self, model_name: str, data_source: str, 
                            trigger_condition: str = "weekly", 
                            auto_deploy: bool = False,
                            min_accuracy_threshold: float = 0.85) -> str:
        """Create new retraining job"""
        try:
            job_id = f"retrain_{model_name}_{int(time.time())}"
            
            job = RetrainingJob(
                job_id=job_id,
                model_name=model_name,
                data_source=data_source,
                trigger_condition=trigger_condition,
                schedule="0 2 * * 0",  # Weekly at 2 AM on Sunday
                auto_deploy=auto_deploy,
                min_accuracy_threshold=min_accuracy_threshold,
                max_training_time=3600,  # 1 hour max
                created_at=datetime.now().isoformat()
            )
            
            # Save to database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO retraining_jobs 
                    (job_id, model_name, data_source, trigger_condition, schedule,
                     auto_deploy, min_accuracy_threshold, max_training_time, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    job.job_id, job.model_name, job.data_source, job.trigger_condition,
                    job.schedule, job.auto_deploy, job.min_accuracy_threshold,
                    job.max_training_time, job.status, job.created_at
                ))
                conn.commit()
            
            self.active_jobs[job_id] = job
            self.logger.info(f"Created retraining job: {job_id}")
            return job_id
            
        except Exception as e:
            self.logger.error(f"Failed to create retraining job: {e}")
            raise
    
    def start_pipeline(self):
        """Start the retraining pipeline"""
        if self.pipeline_running:
            return
        
        # Skip retraining thread for memory optimization
        self.retraining_thread = None
        self.logger.info("Retraining thread disabled for memory optimization")
        self.logger.info("Retraining pipeline started")
    
    def stop_pipeline(self):
        """Stop the retraining pipeline"""
        self.pipeline_running = False
        if self.pipeline_thread:
            self.pipeline_thread.join(timeout=5)
        self.logger.info("Retraining pipeline stopped")
    
    def _pipeline_worker(self):
        """Main pipeline worker thread"""
        while self.pipeline_running:
            try:
                # Check for jobs that need to run
                for job_id, job in self.active_jobs.items():
                    if self._should_run_job(job):
                        self._execute_retraining_job(job)
                
                # Sleep for 1 minute before next check
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Pipeline worker error: {e}")
                time.sleep(60)
    
    def _should_run_job(self, job: RetrainingJob) -> bool:
        """Check if job should run based on trigger conditions"""
        try:
            if job.status != "active":
                return False
            
            now = datetime.now()
            
            # Check last run time
            if job.last_run:
                last_run = datetime.fromisoformat(job.last_run)
                
                if job.trigger_condition == "daily":
                    return (now - last_run).days >= 1
                elif job.trigger_condition == "weekly":
                    return (now - last_run).days >= 7
                elif job.trigger_condition == "monthly":
                    return (now - last_run).days >= 30
            else:
                # Never run before
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking job trigger: {e}")
            return False
    
    def _execute_retraining_job(self, job: RetrainingJob):
        """Execute a retraining job"""
        start_time = datetime.now()
        
        try:
            self.logger.info(f"Starting retraining job: {job.job_id}")
            
            # Load training data
            X_train, X_test, y_train, y_test = self._load_training_data(job.data_source)
            
            if X_train is None:
                raise ValueError(f"Failed to load training data from {job.data_source}")
            
            # Load existing model for comparison
            model_path = os.path.join(self.models_dir, f"{job.model_name}.pkl")
            original_accuracy = 0.0
            
            if os.path.exists(model_path):
                original_model = joblib.load(model_path)
                original_accuracy = original_model.score(X_test, y_test)
            
            # Train new model
            new_model, new_accuracy = self._train_model(X_train, y_train, X_test, y_test)
            
            # Check if new model meets threshold
            if new_accuracy < job.min_accuracy_threshold:
                raise ValueError(f"New model accuracy {new_accuracy:.3f} below threshold {job.min_accuracy_threshold}")
            
            # Save new model
            new_model_path = os.path.join(self.models_dir, f"{job.model_name}_retrained.pkl")
            joblib.dump(new_model, new_model_path)
            
            # Auto-deploy if enabled and model is better
            if job.auto_deploy and new_accuracy > original_accuracy:
                # Backup original model
                backup_path = os.path.join(self.models_dir, f"{job.model_name}_backup_{int(time.time())}.pkl")
                if os.path.exists(model_path):
                    os.rename(model_path, backup_path)
                
                # Deploy new model
                os.rename(new_model_path, model_path)
                self.logger.info(f"Auto-deployed retrained model: {job.model_name}")
            
            # Update job
            job.last_run = start_time.isoformat()
            job.status = "completed"
            
            # Log success
            self._log_retraining_result(job, start_time, datetime.now(), "success", 
                                      original_accuracy, new_accuracy, len(X_train), 
                                      None, new_model_path)
            
            # Update statistics
            self.stats['total_retrainings'] += 1
            self.stats['successful_retrainings'] += 1
            self.stats['last_retraining'] = start_time.isoformat()
            
            training_time = (datetime.now() - start_time).total_seconds()
            if self.stats['average_training_time'] == 0:
                self.stats['average_training_time'] = training_time
            else:
                self.stats['average_training_time'] = (self.stats['average_training_time'] + training_time) / 2
            
            self.logger.info(f"Retraining job completed successfully: {job.job_id}")
            
        except Exception as e:
            # Log failure
            job.status = "failed"
            self._log_retraining_result(job, start_time, datetime.now(), "failed", 
                                      0.0, 0.0, 0, str(e), None)
            
            self.stats['total_retrainings'] += 1
            self.stats['failed_retrainings'] += 1
            
            self.logger.error(f"Retraining job failed: {job.job_id} - {e}")
    
    def _load_training_data(self, data_source: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Load training data from source"""
        try:
            # For demo purposes, generate synthetic data
            # In real implementation, this would load from actual data sources
            
            if data_source == "threat_database":
                # Generate synthetic threat detection data
                np.random.seed(42)
                n_samples = 1000
                n_features = 20
                
                X = np.random.randn(n_samples, n_features)
                # Add some patterns for threats
                threat_indices = np.random.choice(n_samples, n_samples // 3, replace=False)
                X[threat_indices] += np.random.randn(len(threat_indices), n_features) * 2
                
                y = np.zeros(n_samples)
                y[threat_indices] = 1
                
                return train_test_split(X, y, test_size=0.2, random_state=42)
            
            elif data_source == "file_analysis":
                # Generate synthetic file analysis data
                np.random.seed(123)
                n_samples = 800
                n_features = 15
                
                X = np.random.randn(n_samples, n_features)
                y = (X[:, 0] + X[:, 1] > 0).astype(int)
                
                return train_test_split(X, y, test_size=0.2, random_state=42)
            
            else:
                # Try to load from file
                data_path = os.path.join(self.data_dir, f"{data_source}.npz")
                if os.path.exists(data_path):
                    data = np.load(data_path)
                    X, y = data['X'], data['y']
                    return train_test_split(X, y, test_size=0.2, random_state=42)
                else:
                    return None, None, None, None
            
        except Exception as e:
            self.logger.error(f"Failed to load training data: {e}")
            return None, None, None, None
    
    def _train_model(self, X_train: np.ndarray, y_train: np.ndarray, 
                    X_test: np.ndarray, y_test: np.ndarray) -> Tuple[Any, float]:
        """Train a new model"""
        try:
            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Train Random Forest model
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            
            model.fit(X_train_scaled, y_train)
            
            # Evaluate
            accuracy = model.score(X_test_scaled, y_test)
            
            return model, accuracy
            
        except Exception as e:
            self.logger.error(f"Failed to train model: {e}")
            raise
    
    def _log_retraining_result(self, job: RetrainingJob, start_time: datetime, 
                              end_time: datetime, status: str, accuracy_before: float,
                              accuracy_after: float, training_samples: int, 
                              error_message: str, model_path: str):
        """Log retraining result to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO retraining_history 
                    (job_id, model_name, start_time, end_time, status, accuracy_before,
                     accuracy_after, training_samples, error_message, model_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    job.job_id, job.model_name, start_time.isoformat(), end_time.isoformat(),
                    status, accuracy_before, accuracy_after, training_samples,
                    error_message, model_path
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log retraining result: {e}")
    
    def load_jobs(self):
        """Load jobs from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM retraining_jobs')
                
                columns = [desc[0] for desc in cursor.description]
                for row in cursor.fetchall():
                    job_data = dict(zip(columns, row))
                    
                    job = RetrainingJob(
                        job_id=job_data['job_id'],
                        model_name=job_data['model_name'],
                        data_source=job_data['data_source'],
                        trigger_condition=job_data['trigger_condition'],
                        schedule=job_data['schedule'],
                        auto_deploy=bool(job_data['auto_deploy']),
                        min_accuracy_threshold=job_data['min_accuracy_threshold'],
                        max_training_time=job_data['max_training_time'],
                        created_at=job_data['created_at'],
                        last_run=job_data['last_run'],
                        status=job_data['status']
                    )
                    
                    self.active_jobs[job.job_id] = job
                
                self.logger.info(f"Loaded {len(self.active_jobs)} retraining jobs")
                
        except Exception as e:
            self.logger.error(f"Failed to load jobs: {e}")
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get job status"""
        if job_id in self.active_jobs:
            job = self.active_jobs[job_id]
            return {
                'job_id': job.job_id,
                'model_name': job.model_name,
                'status': job.status,
                'last_run': job.last_run,
                'created_at': job.created_at
            }
        return None
    
    def get_retraining_history(self, days: int = 30) -> List[Dict]:
        """Get retraining history"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM retraining_history 
                    WHERE start_time >= ?
                    ORDER BY start_time DESC
                ''', (cutoff_date,))
                
                columns = [desc[0] for desc in cursor.description]
                history = []
                
                for row in cursor.fetchall():
                    history.append(dict(zip(columns, row)))
                
                return history
                
        except Exception as e:
            self.logger.error(f"Failed to get retraining history: {e}")
            return []
    
    def get_pipeline_statistics(self) -> Dict[str, Any]:
        """Get pipeline statistics"""
        return {
            **self.stats,
            'active_jobs': len(self.active_jobs),
            'pipeline_running': self.pipeline_running
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.stop_pipeline()
        self.logger.info("Model retraining pipeline cleaned up")
