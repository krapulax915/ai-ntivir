#!/usr/bin/env python3
"""
AutoML Integration System
Automated Machine Learning pipeline with multiple AutoML backends
"""

import os
import json
import time
import logging
import numpy as np
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import pickle
import hashlib

# AutoML libraries (optional imports)
try:
    import auto_sklearn
    from auto_sklearn.classification import AutoSklearnClassifier
    AUTO_SKLEARN_AVAILABLE = True
except ImportError:
    AUTO_SKLEARN_AVAILABLE = False

try:
    import autokeras as ak
    AUTOKERAS_AVAILABLE = True
except ImportError:
    AUTOKERAS_AVAILABLE = False

try:
    from flaml import AutoML
    FLAML_AVAILABLE = True
except ImportError:
    FLAML_AVAILABLE = False

# Fallback to basic sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report

@dataclass
class AutoMLConfiguration:
    """AutoML configuration settings"""
    backend: str  # 'auto-sklearn', 'autokeras', 'flaml', 'basic'
    time_budget: int  # seconds
    memory_limit: int  # MB
    ensemble_size: int
    include_estimators: Optional[List[str]] = None
    exclude_estimators: Optional[List[str]] = None
    metric: str = 'accuracy'
    cv_folds: int = 5
    n_jobs: int = -1
    random_state: int = 42

@dataclass
class AutoMLResult:
    """Results from AutoML training"""
    model_id: str
    backend: str
    configuration: AutoMLConfiguration
    best_model: Any
    performance_metrics: Dict[str, float]
    training_time: float
    model_info: Dict[str, Any]
    feature_importance: Optional[Dict[str, float]] = None
    created_at: datetime = field(default_factory=datetime.now)

class AutoMLIntegration:
    """Automated Machine Learning integration system"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.ai.automl_integration')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = os.path.join(models_dir, "automl_results.db")
        
        os.makedirs(models_dir, exist_ok=True)
        self.init_database()
        
        # Available backends
        self.available_backends = []
        if AUTO_SKLEARN_AVAILABLE:
            self.available_backends.append('auto-sklearn')
        if AUTOKERAS_AVAILABLE:
            self.available_backends.append('autokeras')
        if FLAML_AVAILABLE:
            self.available_backends.append('flaml')
        self.available_backends.append('basic')  # Always available
        
        self.logger.info(f"Available AutoML backends: {self.available_backends}")
    
    def init_database(self):
        """Initialize database for AutoML results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # AutoML results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS automl_results (
                        model_id TEXT PRIMARY KEY,
                        backend TEXT NOT NULL,
                        configuration TEXT NOT NULL,
                        performance_metrics TEXT NOT NULL,
                        training_time REAL NOT NULL,
                        model_info TEXT NOT NULL,
                        feature_importance TEXT,
                        model_path TEXT,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                # AutoML experiments table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS automl_experiments (
                        experiment_id TEXT PRIMARY KEY,
                        dataset_info TEXT NOT NULL,
                        backends_tested TEXT NOT NULL,
                        best_model_id TEXT NOT NULL,
                        experiment_time REAL NOT NULL,
                        results_summary TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (best_model_id) REFERENCES automl_results (model_id)
                    )
                ''')
                
                conn.commit()
                self.logger.info("AutoML database initialized")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize AutoML database: {e}")
    
    def create_configuration(self, backend: str, time_budget: int = 300, 
                           memory_limit: int = 3072, **kwargs) -> AutoMLConfiguration:
        """Create AutoML configuration"""
        return AutoMLConfiguration(
            backend=backend,
            time_budget=time_budget,
            memory_limit=memory_limit,
            ensemble_size=kwargs.get('ensemble_size', 50),
            include_estimators=kwargs.get('include_estimators'),
            exclude_estimators=kwargs.get('exclude_estimators'),
            metric=kwargs.get('metric', 'accuracy'),
            cv_folds=kwargs.get('cv_folds', 5),
            n_jobs=kwargs.get('n_jobs', -1),
            random_state=kwargs.get('random_state', 42)
        )
    
    def train_automl_model(self, X, y, config: AutoMLConfiguration) -> AutoMLResult:
        """Train model using specified AutoML backend"""
        try:
            start_time = time.time()
            
            if config.backend == 'auto-sklearn' and AUTO_SKLEARN_AVAILABLE:
                result = self._train_auto_sklearn(X, y, config)
            elif config.backend == 'autokeras' and AUTOKERAS_AVAILABLE:
                result = self._train_autokeras(X, y, config)
            elif config.backend == 'flaml' and FLAML_AVAILABLE:
                result = self._train_flaml(X, y, config)
            else:
                result = self._train_basic_automl(X, y, config)
            
            result.training_time = time.time() - start_time
            
            # Store result
            self.store_automl_result(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"AutoML training failed with {config.backend}: {e}")
            # Fallback to basic AutoML
            return self._train_basic_automl(X, y, config)
    
    def _train_auto_sklearn(self, X, y, config: AutoMLConfiguration) -> AutoMLResult:
        """Train model using auto-sklearn"""
        try:
            automl = AutoSklearnClassifier(
                time_left_for_this_task=config.time_budget,
                per_run_time_limit=config.time_budget // 10,
                memory_limit=config.memory_limit,
                ensemble_size=config.ensemble_size,
                include_estimators=config.include_estimators,
                exclude_estimators=config.exclude_estimators,
                n_jobs=config.n_jobs,
                seed=config.random_state
            )
            
            # Split data for validation
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=config.random_state, stratify=y
            )
            
            # Train model
            automl.fit(X_train, y_train)
            
            # Evaluate
            y_pred = automl.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Get model info
            model_info = {
                'ensemble_size': len(automl.get_models_with_weights()),
                'best_model': str(automl.show_models()),
                'statistics': str(automl.sprint_statistics())
            }
            
            # Feature importance (if available)
            feature_importance = None
            try:
                if hasattr(automl, 'feature_importances_'):
                    feature_importance = {
                        f'feature_{i}': importance 
                        for i, importance in enumerate(automl.feature_importances_)
                    }
            except:
                pass
            
            model_id = hashlib.md5(f"auto_sklearn_{int(time.time())}".encode()).hexdigest()
            
            return AutoMLResult(
                model_id=model_id,
                backend='auto-sklearn',
                configuration=config,
                best_model=automl,
                performance_metrics={'accuracy': accuracy},
                training_time=0.0,  # Will be set by caller
                model_info=model_info,
                feature_importance=feature_importance
            )
            
        except Exception as e:
            self.logger.error(f"Auto-sklearn training failed: {e}")
            raise
    
    def _train_autokeras(self, X, y, config: AutoMLConfiguration) -> AutoMLResult:
        """Train model using AutoKeras"""
        try:
            # Convert to appropriate format
            if isinstance(X, np.ndarray):
                X = X.astype(np.float32)
            
            # Create classifier
            clf = ak.StructuredDataClassifier(
                max_trials=min(50, config.time_budget // 60),  # Rough estimate
                seed=config.random_state
            )
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=config.random_state, stratify=y
            )
            
            # Train model
            clf.fit(X_train, y_train, epochs=50, verbose=0)
            
            # Evaluate
            y_pred = clf.predict(X_test)
            y_pred_classes = np.argmax(y_pred, axis=1) if y_pred.ndim > 1 else (y_pred > 0.5).astype(int)
            accuracy = accuracy_score(y_test, y_pred_classes)
            
            model_info = {
                'model_type': 'AutoKeras StructuredDataClassifier',
                'trials_completed': clf.tuner.oracle.get_state()['tried_so_far'] if hasattr(clf, 'tuner') else 'unknown'
            }
            
            model_id = hashlib.md5(f"autokeras_{int(time.time())}".encode()).hexdigest()
            
            return AutoMLResult(
                model_id=model_id,
                backend='autokeras',
                configuration=config,
                best_model=clf,
                performance_metrics={'accuracy': accuracy},
                training_time=0.0,
                model_info=model_info
            )
            
        except Exception as e:
            self.logger.error(f"AutoKeras training failed: {e}")
            raise
    
    def _train_flaml(self, X, y, config: AutoMLConfiguration) -> AutoMLResult:
        """Train model using FLAML"""
        try:
            automl = AutoML()
            
            # Configure settings
            settings = {
                'time_budget': config.time_budget,
                'metric': config.metric,
                'task': 'classification',
                'n_jobs': config.n_jobs,
                'seed': config.random_state,
                'verbose': 0
            }
            
            if config.include_estimators:
                settings['estimator_list'] = config.include_estimators
            
            # Train model
            automl.fit(X, y, **settings)
            
            # Get performance metrics
            accuracy = automl.best_loss if config.metric == 'accuracy' else 1 - automl.best_loss
            
            model_info = {
                'best_estimator': automl.best_estimator,
                'best_config': automl.best_config,
                'feature_importance': automl.feature_importances_.tolist() if hasattr(automl, 'feature_importances_') else None
            }
            
            # Feature importance
            feature_importance = None
            if hasattr(automl, 'feature_importances_') and automl.feature_importances_ is not None:
                feature_importance = {
                    f'feature_{i}': importance 
                    for i, importance in enumerate(automl.feature_importances_)
                }
            
            model_id = hashlib.md5(f"flaml_{int(time.time())}".encode()).hexdigest()
            
            return AutoMLResult(
                model_id=model_id,
                backend='flaml',
                configuration=config,
                best_model=automl,
                performance_metrics={'accuracy': accuracy},
                training_time=0.0,
                model_info=model_info,
                feature_importance=feature_importance
            )
            
        except Exception as e:
            self.logger.error(f"FLAML training failed: {e}")
            raise
    
    def _train_basic_automl(self, X, y, config: AutoMLConfiguration) -> AutoMLResult:
        """Basic AutoML using sklearn with simple model selection"""
        try:
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
            from sklearn.svm import SVC
            from sklearn.linear_model import LogisticRegression
            from sklearn.naive_bayes import GaussianNB
            
            # Define candidate models
            models = {
                'random_forest': RandomForestClassifier(n_estimators=100, random_state=config.random_state),
                'gradient_boosting': GradientBoostingClassifier(random_state=config.random_state),
                'svm': SVC(probability=True, random_state=config.random_state),
                'logistic_regression': LogisticRegression(random_state=config.random_state, max_iter=1000),
                'naive_bayes': GaussianNB()
            }
            
            # Filter models based on configuration
            if config.include_estimators:
                models = {k: v for k, v in models.items() if k in config.include_estimators}
            if config.exclude_estimators:
                models = {k: v for k, v in models.items() if k not in config.exclude_estimators}
            
            best_model = None
            best_score = 0.0
            best_model_name = ""
            
            # Evaluate each model
            for name, model in models.items():
                try:
                    scores = cross_val_score(model, X, y, cv=config.cv_folds, scoring='accuracy')
                    mean_score = np.mean(scores)
                    
                    if mean_score > best_score:
                        best_score = mean_score
                        best_model = model
                        best_model_name = name
                        
                except Exception as e:
                    self.logger.warning(f"Model {name} failed: {e}")
                    continue
            
            if best_model is None:
                # Fallback to random forest
                best_model = RandomForestClassifier(random_state=config.random_state)
                best_model_name = "random_forest_fallback"
                best_score = 0.5
            
            # Train best model on full dataset
            best_model.fit(X, y)
            
            # Feature importance
            feature_importance = None
            if hasattr(best_model, 'feature_importances_'):
                feature_importance = {
                    f'feature_{i}': importance 
                    for i, importance in enumerate(best_model.feature_importances_)
                }
            
            model_info = {
                'best_model_name': best_model_name,
                'models_evaluated': list(models.keys()),
                'cross_val_score': best_score
            }
            
            model_id = hashlib.md5(f"basic_automl_{int(time.time())}".encode()).hexdigest()
            
            return AutoMLResult(
                model_id=model_id,
                backend='basic',
                configuration=config,
                best_model=best_model,
                performance_metrics={'accuracy': best_score},
                training_time=0.0,
                model_info=model_info,
                feature_importance=feature_importance
            )
            
        except Exception as e:
            self.logger.error(f"Basic AutoML training failed: {e}")
            raise
    
    def run_automl_experiment(self, X, y, backends: Optional[List[str]] = None, 
                            time_budget_per_backend: int = 300) -> Dict[str, AutoMLResult]:
        """Run AutoML experiment with multiple backends"""
        try:
            if backends is None:
                backends = self.available_backends
            
            # Filter available backends
            backends = [b for b in backends if b in self.available_backends]
            
            if not backends:
                backends = ['basic']
            
            results = {}
            experiment_start = time.time()
            
            self.logger.info(f"Starting AutoML experiment with backends: {backends}")
            
            for backend in backends:
                try:
                    self.logger.info(f"Training with {backend} backend...")
                    
                    config = self.create_configuration(
                        backend=backend,
                        time_budget=time_budget_per_backend
                    )
                    
                    result = self.train_automl_model(X, y, config)
                    results[backend] = result
                    
                    self.logger.info(f"{backend} completed with accuracy: {result.performance_metrics.get('accuracy', 0):.4f}")
                    
                except Exception as e:
                    self.logger.error(f"Backend {backend} failed: {e}")
                    continue
            
            # Store experiment
            experiment_time = time.time() - experiment_start
            self.store_experiment(X, y, results, experiment_time)
            
            return results
            
        except Exception as e:
            self.logger.error(f"AutoML experiment failed: {e}")
            return {}
    
    def get_best_model(self, results: Dict[str, AutoMLResult]) -> Optional[AutoMLResult]:
        """Get best model from experiment results"""
        if not results:
            return None
        
        best_result = None
        best_score = 0.0
        
        for backend, result in results.items():
            accuracy = result.performance_metrics.get('accuracy', 0)
            if accuracy > best_score:
                best_score = accuracy
                best_result = result
        
        return best_result
    
    def store_automl_result(self, result: AutoMLResult):
        """Store AutoML result in database"""
        try:
            # Save model to file
            model_filename = f"{result.model_id}.pkl"
            model_path = os.path.join(self.models_dir, model_filename)
            
            with open(model_path, 'wb') as f:
                pickle.dump(result.best_model, f)
            
            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO automl_results 
                    (model_id, backend, configuration, performance_metrics, training_time,
                     model_info, feature_importance, model_path, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.model_id,
                    result.backend,
                    json.dumps(result.configuration.__dict__),
                    json.dumps(result.performance_metrics),
                    result.training_time,
                    json.dumps(result.model_info),
                    json.dumps(result.feature_importance) if result.feature_importance else None,
                    model_path,
                    result.created_at.isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store AutoML result: {e}")
    
    def store_experiment(self, X, y, results: Dict[str, AutoMLResult], experiment_time: float):
        """Store experiment results"""
        try:
            experiment_id = hashlib.md5(f"experiment_{int(time.time())}".encode()).hexdigest()
            
            dataset_info = {
                'n_samples': X.shape[0],
                'n_features': X.shape[1],
                'n_classes': len(np.unique(y))
            }
            
            # Get best model
            best_result = self.get_best_model(results)
            best_model_id = best_result.model_id if best_result else ""
            
            results_summary = {
                backend: {
                    'accuracy': result.performance_metrics.get('accuracy', 0),
                    'training_time': result.training_time
                }
                for backend, result in results.items()
            }
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO automl_experiments 
                    (experiment_id, dataset_info, backends_tested, best_model_id,
                     experiment_time, results_summary, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    experiment_id,
                    json.dumps(dataset_info),
                    json.dumps(list(results.keys())),
                    best_model_id,
                    experiment_time,
                    json.dumps(results_summary),
                    datetime.now().isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store experiment: {e}")
    
    def load_model(self, model_id: str):
        """Load trained AutoML model"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT model_path FROM automl_results WHERE model_id = ?', (model_id,))
                row = cursor.fetchone()
                
                if not row:
                    raise ValueError(f"Model {model_id} not found")
                
                model_path = row[0]
                
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                
                return model
                
        except Exception as e:
            self.logger.error(f"Failed to load model {model_id}: {e}")
            return None
    
    def get_automl_statistics(self) -> Dict[str, Any]:
        """Get AutoML statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total models
                cursor.execute('SELECT COUNT(*) FROM automl_results')
                total_models = cursor.fetchone()[0]
                
                # Total experiments
                cursor.execute('SELECT COUNT(*) FROM automl_experiments')
                total_experiments = cursor.fetchone()[0]
                
                # Backend statistics
                cursor.execute('''
                    SELECT backend, COUNT(*), AVG(performance_metrics) 
                    FROM automl_results 
                    GROUP BY backend
                ''')
                backend_stats = cursor.fetchall()
                
                # Best performance
                cursor.execute('''
                    SELECT MAX(json_extract(performance_metrics, '$.accuracy')) 
                    FROM automl_results
                ''')
                best_accuracy = cursor.fetchone()[0] or 0.0
                
                return {
                    'total_models': total_models,
                    'total_experiments': total_experiments,
                    'available_backends': self.available_backends,
                    'backend_statistics': {
                        row[0]: {'count': row[1], 'avg_performance': row[2]}
                        for row in backend_stats
                    },
                    'best_accuracy': best_accuracy
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get AutoML statistics: {e}")
            return {}
