#!/usr/bin/env python3
"""
Machine Learning Model Auto-Tuning System
Automatic hyperparameter optimization, model architecture search, and dynamic model selection
"""

import os
import sys
import json
import time
import logging
import numpy as np
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import pickle
import hashlib

# ML libraries for optimization
try:
    import optuna
    from sklearn.model_selection import cross_val_score, StratifiedKFold
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.svm import SVC
    from sklearn.neural_network import MLPClassifier
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    import xgboost as xgb
    import lightgbm as lgb
    ADVANCED_ML_AVAILABLE = True
except ImportError:
    ADVANCED_ML_AVAILABLE = False
    print("Warning: Advanced ML libraries not available. Install optuna, xgboost, lightgbm for full functionality.")

@dataclass
class ModelConfiguration:
    """Model configuration with hyperparameters"""
    model_type: str
    hyperparameters: Dict[str, Any]
    architecture: Optional[Dict[str, Any]] = None
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    training_time: float = 0.0
    validation_score: float = 0.0
    cross_val_scores: List[float] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    model_id: str = field(default="")
    
    def __post_init__(self):
        if not self.model_id:
            config_str = f"{self.model_type}_{json.dumps(self.hyperparameters, sort_keys=True)}"
            self.model_id = hashlib.md5(config_str.encode()).hexdigest()

@dataclass
class OptimizationResult:
    """Results from hyperparameter optimization"""
    best_config: ModelConfiguration
    optimization_history: List[ModelConfiguration]
    total_trials: int
    optimization_time: float
    convergence_info: Dict[str, Any]

class AutoTuningSystem:
    """Automatic hyperparameter optimization using Optuna"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.ai.auto_tuning_system')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = os.path.join(models_dir, "auto_tuning.db")
        self.optimization_history = []
        self.best_models = {}

        # Ensure models directory exists
        os.makedirs(models_dir, exist_ok=True)
        
        # Initialize database
        self.init_database()
        
        # Model search spaces
        self.search_spaces = {
            'random_forest': {
                'n_estimators': (50, 500),
                'max_depth': (3, 20),
                'min_samples_split': (2, 20),
                'min_samples_leaf': (1, 10),
                'max_features': ['sqrt', 'log2', None]
            },
            'gradient_boosting': {
                'n_estimators': (50, 300),
                'learning_rate': (0.01, 0.3),
                'max_depth': (3, 10),
                'min_samples_split': (2, 20),
                'subsample': (0.6, 1.0)
            },
            'xgboost': {
                'n_estimators': (50, 500),
                'learning_rate': (0.01, 0.3),
                'max_depth': (3, 10),
                'min_child_weight': (1, 10),
                'subsample': (0.6, 1.0),
                'colsample_bytree': (0.6, 1.0)
            },
            'lightgbm': {
                'n_estimators': (50, 500),
                'learning_rate': (0.01, 0.3),
                'max_depth': (3, 10),
                'min_child_samples': (10, 100),
                'subsample': (0.6, 1.0),
                'colsample_bytree': (0.6, 1.0)
            },
            'mlp': {
                'hidden_layer_sizes': [(50,), (100,), (50, 50), (100, 50), (100, 100)],
                'activation': ['relu', 'tanh'],
                'alpha': (0.0001, 0.01),
                'learning_rate_init': (0.001, 0.01),
                'max_iter': (200, 1000)
            },
            'svm': {
                'C': (0.1, 100),
                'gamma': ['scale', 'auto'],
                'kernel': ['rbf', 'poly', 'sigmoid']
            }
        }
    
    def init_database(self):
        """Initialize SQLite database for storing optimization results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Model configurations table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS model_configurations (
                        model_id TEXT PRIMARY KEY,
                        model_type TEXT NOT NULL,
                        hyperparameters TEXT NOT NULL,
                        architecture TEXT,
                        performance_metrics TEXT NOT NULL,
                        training_time REAL NOT NULL,
                        validation_score REAL NOT NULL,
                        cross_val_scores TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                # Optimization sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS optimization_sessions (
                        session_id TEXT PRIMARY KEY,
                        model_type TEXT NOT NULL,
                        dataset_info TEXT NOT NULL,
                        best_model_id TEXT NOT NULL,
                        total_trials INTEGER NOT NULL,
                        optimization_time REAL NOT NULL,
                        convergence_info TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (best_model_id) REFERENCES model_configurations (model_id)
                    )
                ''')
                
                # Model performance tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS model_performance (
                        performance_id TEXT PRIMARY KEY,
                        model_id TEXT NOT NULL,
                        dataset_name TEXT NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        evaluation_date TEXT NOT NULL,
                        FOREIGN KEY (model_id) REFERENCES model_configurations (model_id)
                    )
                ''')
                
                conn.commit()
                self.logger.info("Auto-tuning database initialized")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def create_model(self, model_type: str, hyperparameters: Dict[str, Any]):
        """Create model instance with given hyperparameters"""
        try:
            if model_type == 'random_forest':
                return RandomForestClassifier(**hyperparameters, random_state=42)
            elif model_type == 'gradient_boosting':
                return GradientBoostingClassifier(**hyperparameters, random_state=42)
            elif model_type == 'xgboost' and ADVANCED_ML_AVAILABLE:
                return xgb.XGBClassifier(**hyperparameters, random_state=42, eval_metric='logloss')
            elif model_type == 'lightgbm' and ADVANCED_ML_AVAILABLE:
                return lgb.LGBMClassifier(**hyperparameters, random_state=42, verbose=-1)
            elif model_type == 'mlp':
                return MLPClassifier(**hyperparameters, random_state=42)
            elif model_type == 'svm':
                return SVC(**hyperparameters, random_state=42, probability=True)
            else:
                raise ValueError(f"Unsupported model type: {model_type}")
                
        except Exception as e:
            self.logger.error(f"Failed to create model {model_type}: {e}")
            return None
    
    def suggest_hyperparameters(self, trial, model_type: str) -> Dict[str, Any]:
        """Suggest hyperparameters for given model type using Optuna"""
        if model_type not in self.search_spaces:
            raise ValueError(f"No search space defined for model type: {model_type}")
        
        search_space = self.search_spaces[model_type]
        hyperparameters = {}
        
        for param_name, param_config in search_space.items():
            if isinstance(param_config, tuple) and len(param_config) == 2:
                if isinstance(param_config[0], int) and isinstance(param_config[1], int):
                    # Integer range
                    hyperparameters[param_name] = trial.suggest_int(param_name, param_config[0], param_config[1])
                elif isinstance(param_config[0], float) or isinstance(param_config[1], float):
                    # Float range
                    hyperparameters[param_name] = trial.suggest_float(param_name, param_config[0], param_config[1])
            elif isinstance(param_config, list):
                # Categorical choice
                hyperparameters[param_name] = trial.suggest_categorical(param_name, param_config)
        
        return hyperparameters
    
    def evaluate_model(self, model, X, y, cv_folds: int = 5) -> Tuple[float, List[float], Dict[str, float]]:
        """Evaluate model using cross-validation"""
        try:
            start_time = time.time()
            
            # Cross-validation
            cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
            cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy', n_jobs=-1)
            
            # Fit model for detailed metrics
            model.fit(X, y)
            y_pred = model.predict(X)
            
            # Calculate detailed metrics
            metrics = {
                'accuracy': accuracy_score(y, y_pred),
                'precision': precision_score(y, y_pred, average='weighted', zero_division=0),
                'recall': recall_score(y, y_pred, average='weighted', zero_division=0),
                'f1_score': f1_score(y, y_pred, average='weighted', zero_division=0)
            }
            
            training_time = time.time() - start_time
            mean_cv_score = np.mean(cv_scores)
            
            return mean_cv_score, cv_scores.tolist(), metrics
            
        except Exception as e:
            self.logger.error(f"Model evaluation failed: {e}")
            return 0.0, [], {}
    
    def optimize_hyperparameters(self, model_type: str, X, y, n_trials: int = 100, 
                                timeout: Optional[int] = None) -> OptimizationResult:
        """Optimize hyperparameters for given model type"""
        if not ADVANCED_ML_AVAILABLE:
            self.logger.warning("Advanced ML libraries not available. Using basic optimization.")
            return self._basic_optimization(model_type, X, y)
        
        try:
            start_time = time.time()
            optimization_history = []
            
            def objective(trial):
                try:
                    # Suggest hyperparameters
                    hyperparameters = self.suggest_hyperparameters(trial, model_type)
                    
                    # Create and evaluate model
                    model = self.create_model(model_type, hyperparameters)
                    if model is None:
                        return 0.0
                    
                    validation_score, cv_scores, metrics = self.evaluate_model(model, X, y)
                    
                    # Store configuration
                    config = ModelConfiguration(
                        model_type=model_type,
                        hyperparameters=hyperparameters,
                        performance_metrics=metrics,
                        validation_score=validation_score,
                        cross_val_scores=cv_scores,
                        training_time=time.time() - start_time
                    )
                    
                    optimization_history.append(config)
                    
                    # Store in database
                    self.store_model_configuration(config)
                    
                    return validation_score
                    
                except Exception as e:
                    self.logger.error(f"Trial failed: {e}")
                    return 0.0
            
            # Create study
            study = optuna.create_study(
                direction='maximize',
                study_name=f"{model_type}_optimization_{int(time.time())}",
                storage=None  # In-memory storage
            )
            
            # Optimize
            study.optimize(objective, n_trials=n_trials, timeout=timeout)
            
            # Get best configuration
            best_trial = study.best_trial
            best_config = None
            
            for config in optimization_history:
                if config.validation_score == best_trial.value:
                    best_config = config
                    break
            
            if best_config is None:
                # Fallback: create best config from best trial
                best_hyperparameters = best_trial.params
                best_model = self.create_model(model_type, best_hyperparameters)
                validation_score, cv_scores, metrics = self.evaluate_model(best_model, X, y)
                
                best_config = ModelConfiguration(
                    model_type=model_type,
                    hyperparameters=best_hyperparameters,
                    performance_metrics=metrics,
                    validation_score=validation_score,
                    cross_val_scores=cv_scores
                )
            
            # Create optimization result
            optimization_time = time.time() - start_time
            result = OptimizationResult(
                best_config=best_config,
                optimization_history=optimization_history,
                total_trials=len(study.trials),
                optimization_time=optimization_time,
                convergence_info={
                    'best_value': study.best_value,
                    'best_params': study.best_params,
                    'n_trials': len(study.trials)
                }
            )
            
            # Store optimization session
            self.store_optimization_session(result, X, y)
            
            self.logger.info(f"Hyperparameter optimization completed for {model_type}")
            self.logger.info(f"Best score: {best_config.validation_score:.4f}")
            self.logger.info(f"Best params: {best_config.hyperparameters}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Hyperparameter optimization failed: {e}")
            return self._basic_optimization(model_type, X, y)
    
    def _basic_optimization(self, model_type: str, X, y) -> OptimizationResult:
        """Basic optimization without advanced libraries"""
        try:
            # Use predefined good configurations
            basic_configs = {
                'random_forest': [
                    {'n_estimators': 100, 'max_depth': 10, 'min_samples_split': 5},
                    {'n_estimators': 200, 'max_depth': 15, 'min_samples_split': 2},
                    {'n_estimators': 150, 'max_depth': 12, 'min_samples_split': 3}
                ],
                'gradient_boosting': [
                    {'n_estimators': 100, 'learning_rate': 0.1, 'max_depth': 6},
                    {'n_estimators': 150, 'learning_rate': 0.05, 'max_depth': 8},
                    {'n_estimators': 200, 'learning_rate': 0.01, 'max_depth': 10}
                ]
            }
            
            if model_type not in basic_configs:
                # Default configuration
                basic_configs[model_type] = [{}]
            
            best_config = None
            best_score = 0.0
            optimization_history = []
            
            for hyperparameters in basic_configs[model_type]:
                model = self.create_model(model_type, hyperparameters)
                if model is None:
                    continue
                
                validation_score, cv_scores, metrics = self.evaluate_model(model, X, y)
                
                config = ModelConfiguration(
                    model_type=model_type,
                    hyperparameters=hyperparameters,
                    performance_metrics=metrics,
                    validation_score=validation_score,
                    cross_val_scores=cv_scores
                )
                
                optimization_history.append(config)
                
                if validation_score > best_score:
                    best_score = validation_score
                    best_config = config
            
            if best_config is None:
                # Create default config
                best_config = ModelConfiguration(
                    model_type=model_type,
                    hyperparameters={},
                    validation_score=0.0
                )
            
            return OptimizationResult(
                best_config=best_config,
                optimization_history=optimization_history,
                total_trials=len(optimization_history),
                optimization_time=0.0,
                convergence_info={'method': 'basic_grid_search'}
            )
            
        except Exception as e:
            self.logger.error(f"Basic optimization failed: {e}")
            return OptimizationResult(
                best_config=ModelConfiguration(model_type=model_type, hyperparameters={}, validation_score=0.0),
                optimization_history=[],
                total_trials=0,
                optimization_time=0.0,
                convergence_info={}
            )
    
    def store_model_configuration(self, config: ModelConfiguration):
        """Store model configuration in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO model_configurations 
                    (model_id, model_type, hyperparameters, architecture, performance_metrics, 
                     training_time, validation_score, cross_val_scores, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    config.model_id,
                    config.model_type,
                    json.dumps(config.hyperparameters),
                    json.dumps(config.architecture) if config.architecture else None,
                    json.dumps(config.performance_metrics),
                    config.training_time,
                    config.validation_score,
                    json.dumps(config.cross_val_scores),
                    config.created_at.isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store model configuration: {e}")
    
    def store_optimization_session(self, result: OptimizationResult, X, y):
        """Store optimization session results"""
        try:
            session_id = hashlib.md5(f"{result.best_config.model_type}_{int(time.time())}".encode()).hexdigest()
            dataset_info = {
                'n_samples': X.shape[0],
                'n_features': X.shape[1],
                'n_classes': len(np.unique(y)) if hasattr(y, '__len__') else 2
            }
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO optimization_sessions 
                    (session_id, model_type, dataset_info, best_model_id, total_trials, 
                     optimization_time, convergence_info, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session_id,
                    result.best_config.model_type,
                    json.dumps(dataset_info),
                    result.best_config.model_id,
                    result.total_trials,
                    result.optimization_time,
                    json.dumps(result.convergence_info),
                    datetime.now().isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store optimization session: {e}")
    
    def get_best_models(self, model_type: Optional[str] = None, limit: int = 10) -> List[ModelConfiguration]:
        """Get best performing models from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if model_type:
                    cursor.execute('''
                        SELECT * FROM model_configurations 
                        WHERE model_type = ? 
                        ORDER BY validation_score DESC 
                        LIMIT ?
                    ''', (model_type, limit))
                else:
                    cursor.execute('''
                        SELECT * FROM model_configurations 
                        ORDER BY validation_score DESC 
                        LIMIT ?
                    ''', (limit,))
                
                rows = cursor.fetchall()
                models = []
                
                for row in rows:
                    config = ModelConfiguration(
                        model_id=row[0],
                        model_type=row[1],
                        hyperparameters=json.loads(row[2]),
                        architecture=json.loads(row[3]) if row[3] else None,
                        performance_metrics=json.loads(row[4]),
                        training_time=row[5],
                        validation_score=row[6],
                        cross_val_scores=json.loads(row[7]),
                        created_at=datetime.fromisoformat(row[8])
                    )
                    models.append(config)
                
                return models
                
        except Exception as e:
            self.logger.error(f"Failed to get best models: {e}")
            return []
    
    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total configurations
                cursor.execute('SELECT COUNT(*) FROM model_configurations')
                total_configs = cursor.fetchone()[0]
                
                # Total sessions
                cursor.execute('SELECT COUNT(*) FROM optimization_sessions')
                total_sessions = cursor.fetchone()[0]
                
                # Best scores by model type
                cursor.execute('''
                    SELECT model_type, MAX(validation_score) as best_score, COUNT(*) as count
                    FROM model_configurations 
                    GROUP BY model_type
                ''')
                model_stats = cursor.fetchall()
                
                # Recent activity
                cursor.execute('''
                    SELECT COUNT(*) FROM optimization_sessions 
                    WHERE created_at > datetime('now', '-7 days')
                ''')
                recent_sessions = cursor.fetchone()[0]
                
                return {
                    'total_configurations': total_configs,
                    'total_sessions': total_sessions,
                    'recent_sessions_7days': recent_sessions,
                    'model_type_stats': {
                        row[0]: {'best_score': row[1], 'total_configs': row[2]}
                        for row in model_stats
                    }
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get optimization statistics: {e}")
            return {}
    
    def cleanup_old_configurations(self, days_old: int = 30):
        """Clean up old model configurations"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete old configurations (keep best ones)
                cursor.execute('''
                    DELETE FROM model_configurations 
                    WHERE created_at < ? 
                    AND model_id NOT IN (
                        SELECT model_id FROM model_configurations 
                        WHERE model_type = model_configurations.model_type 
                        ORDER BY validation_score DESC 
                        LIMIT 5
                    )
                ''', (cutoff_date.isoformat(),))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                self.logger.info(f"Cleaned up {deleted_count} old model configurations")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old configurations: {e}")

# Alias for backward compatibility
HyperparameterOptimizer = AutoTuningSystem
