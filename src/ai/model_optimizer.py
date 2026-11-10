#!/usr/bin/env python3
"""
Advanced AI Model Performance Optimizer
Analyzes and optimizes machine learning models for threat detection
"""

import os
import sys
import json
import logging
import numpy as np
import sqlite3
import pickle
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import threading
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
import joblib

@dataclass
class ModelPerformanceMetrics:
    """Model performance metrics data structure"""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    training_time: float
    prediction_time: float
    model_size: int
    feature_count: int
    sample_count: int
    timestamp: str
    cross_val_scores: List[float]
    confusion_matrix: List[List[int]]
    feature_importance: Optional[Dict[str, float]] = None

@dataclass
class OptimizationResult:
    """Model optimization result"""
    original_metrics: ModelPerformanceMetrics
    optimized_metrics: ModelPerformanceMetrics
    improvement_percentage: float
    optimization_method: str
    parameters_changed: Dict[str, Any]
    recommendation: str

class AIModelOptimizer:
    """Advanced AI model performance optimizer"""
    
    def __init__(self, models_dir: str = None, callback: callable = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.ai.model_optimizer')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.models_dir = models_dir or os.path.join(os.getcwd(), "models")
        self.callback = callback
        
        # Performance database
        self.db_path = os.path.join(os.getcwd(), "logs", "model_performance.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Optimization history
        self.optimization_history: List[OptimizationResult] = []
        
        # Model cache
        self.model_cache = {}
        self.scaler_cache = {}
        
        # Performance tracking
        self.performance_stats = {
            'models_analyzed': 0,
            'optimizations_performed': 0,
            'average_improvement': 0.0,
            'best_model_accuracy': 0.0,
            'last_optimization': None
        }
        
        # Thread safety
        self.lock = threading.Lock()
        
        self.init_database()
        self.logger.info("AI Model Optimizer initialized")
    
    def init_database(self):
        """Initialize performance tracking database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Model performance table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS model_performance (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        model_name TEXT NOT NULL,
                        accuracy REAL NOT NULL,
                        precision_score REAL NOT NULL,
                        recall_score REAL NOT NULL,
                        f1_score REAL NOT NULL,
                        roc_auc REAL NOT NULL,
                        training_time REAL NOT NULL,
                        prediction_time REAL NOT NULL,
                        model_size INTEGER NOT NULL,
                        feature_count INTEGER NOT NULL,
                        sample_count INTEGER NOT NULL,
                        cross_val_scores TEXT,
                        confusion_matrix TEXT,
                        feature_importance TEXT,
                        timestamp TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Optimization history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS optimization_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        model_name TEXT NOT NULL,
                        optimization_method TEXT NOT NULL,
                        improvement_percentage REAL NOT NULL,
                        parameters_changed TEXT NOT NULL,
                        recommendation TEXT,
                        original_accuracy REAL NOT NULL,
                        optimized_accuracy REAL NOT NULL,
                        timestamp TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_model_performance_name ON model_performance(model_name)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_model_performance_timestamp ON model_performance(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_optimization_history_name ON optimization_history(model_name)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize performance database: {e}")
    
    def analyze_model_performance(self, model_path: str, X_test: np.ndarray, y_test: np.ndarray) -> ModelPerformanceMetrics:
        """Comprehensive model performance analysis"""
        try:
            model_name = os.path.basename(model_path).replace('.onnx', '').replace('.pkl', '')
            
            # Load model
            model = self.load_model(model_path)
            if model is None:
                raise ValueError(f"Failed to load model from {model_path}")
            
            # Load scaler if exists
            scaler_path = model_path.replace('.onnx', '_scaler.pkl').replace('.pkl', '_scaler.pkl')
            scaler = None
            if os.path.exists(scaler_path):
                scaler = joblib.load(scaler_path)
                X_test_scaled = scaler.transform(X_test)
            else:
                X_test_scaled = X_test
            
            # Measure prediction time
            start_time = time.time()
            if hasattr(model, 'predict_proba'):
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
                y_pred = (y_pred_proba > 0.5).astype(int)
            else:
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = None
            prediction_time = time.time() - start_time
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
            
            # ROC AUC (if probabilities available)
            roc_auc = 0.0
            if y_pred_proba is not None:
                try:
                    roc_auc = roc_auc_score(y_test, y_pred_proba)
                except:
                    roc_auc = 0.0
            
            # Cross-validation scores
            cv_scores = []
            try:
                if hasattr(model, 'fit'):  # Sklearn model
                    cv_scores = cross_val_score(model, X_test_scaled, y_test, cv=5, scoring='accuracy').tolist()
            except:
                cv_scores = [accuracy] * 5  # Fallback
            
            # Confusion matrix
            from sklearn.metrics import confusion_matrix
            cm = confusion_matrix(y_test, y_pred).tolist()
            
            # Feature importance
            feature_importance = None
            if hasattr(model, 'feature_importances_'):
                feature_importance = {f'feature_{i}': float(imp) for i, imp in enumerate(model.feature_importances_)}
            elif hasattr(model, 'coef_'):
                feature_importance = {f'feature_{i}': float(coef) for i, coef in enumerate(model.coef_[0])}
            
            # Model size
            model_size = os.path.getsize(model_path) if os.path.exists(model_path) else 0
            
            # Create metrics object
            metrics = ModelPerformanceMetrics(
                model_name=model_name,
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                roc_auc=roc_auc,
                training_time=0.0,  # Would need to be tracked during training
                prediction_time=prediction_time,
                model_size=model_size,
                feature_count=X_test.shape[1],
                sample_count=X_test.shape[0],
                timestamp=datetime.now().isoformat(),
                cross_val_scores=cv_scores,
                confusion_matrix=cm,
                feature_importance=feature_importance
            )
            
            # Save to database
            self.save_performance_metrics(metrics)
            
            # Update stats
            with self.lock:
                self.performance_stats['models_analyzed'] += 1
                if accuracy > self.performance_stats['best_model_accuracy']:
                    self.performance_stats['best_model_accuracy'] = accuracy
            
            self.logger.info(f"Model analysis completed: {model_name} - Accuracy: {accuracy:.3f}")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to analyze model performance: {e}")
            raise
    
    def optimize_model(self, model_path: str, X_train: np.ndarray, y_train: np.ndarray, 
                      X_test: np.ndarray, y_test: np.ndarray, 
                      optimization_method: str = 'grid_search') -> OptimizationResult:
        """Optimize model performance using various techniques"""
        try:
            # Get original performance
            original_metrics = self.analyze_model_performance(model_path, X_test, y_test)
            
            # Load original model
            original_model = self.load_model(model_path)
            if original_model is None:
                raise ValueError(f"Failed to load original model from {model_path}")
            
            # Prepare data
            scaler_path = model_path.replace('.onnx', '_scaler.pkl').replace('.pkl', '_scaler.pkl')
            if os.path.exists(scaler_path):
                scaler = joblib.load(scaler_path)
                X_train_scaled = scaler.transform(X_train)
                X_test_scaled = scaler.transform(X_test)
            else:
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)
            
            optimized_model = None
            parameters_changed = {}
            
            if optimization_method == 'grid_search':
                optimized_model, parameters_changed = self.grid_search_optimization(
                    original_model, X_train_scaled, y_train
                )
            elif optimization_method == 'feature_selection':
                optimized_model, parameters_changed = self.feature_selection_optimization(
                    original_model, X_train_scaled, y_train, X_test_scaled, y_test
                )
            elif optimization_method == 'ensemble':
                optimized_model, parameters_changed = self.ensemble_optimization(
                    original_model, X_train_scaled, y_train
                )
            elif optimization_method == 'neural_architecture':
                optimized_model, parameters_changed = self.neural_architecture_optimization(
                    X_train_scaled, y_train
                )
            else:
                raise ValueError(f"Unknown optimization method: {optimization_method}")
            
            if optimized_model is None:
                raise ValueError("Optimization failed to produce a valid model")
            
            # Save optimized model
            optimized_model_path = model_path.replace('.pkl', '_optimized.pkl').replace('.onnx', '_optimized.pkl')
            joblib.dump(optimized_model, optimized_model_path)
            
            # Save optimized scaler
            optimized_scaler_path = optimized_model_path.replace('.pkl', '_scaler.pkl')
            joblib.dump(scaler, optimized_scaler_path)
            
            # Analyze optimized model performance
            optimized_metrics = self.analyze_model_performance(optimized_model_path, X_test, y_test)
            
            # Calculate improvement
            improvement = ((optimized_metrics.accuracy - original_metrics.accuracy) / original_metrics.accuracy) * 100
            
            # Generate recommendation
            recommendation = self.generate_optimization_recommendation(
                original_metrics, optimized_metrics, optimization_method, parameters_changed
            )
            
            # Create optimization result
            result = OptimizationResult(
                original_metrics=original_metrics,
                optimized_metrics=optimized_metrics,
                improvement_percentage=improvement,
                optimization_method=optimization_method,
                parameters_changed=parameters_changed,
                recommendation=recommendation
            )
            
            # Save optimization history
            self.save_optimization_result(result)
            
            # Update stats
            with self.lock:
                self.performance_stats['optimizations_performed'] += 1
                self.performance_stats['last_optimization'] = datetime.now().isoformat()
                
                # Update average improvement
                total_improvements = sum(opt.improvement_percentage for opt in self.optimization_history)
                self.performance_stats['average_improvement'] = total_improvements / len(self.optimization_history)
            
            self.optimization_history.append(result)
            
            self.logger.info(f"Model optimization completed: {improvement:.2f}% improvement")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to optimize model: {e}")
            raise
    
    def grid_search_optimization(self, model, X_train: np.ndarray, y_train: np.ndarray) -> Tuple[Any, Dict]:
        """Optimize model using grid search"""
        try:
            # Define parameter grids for different model types
            param_grids = {
                'RandomForestClassifier': {
                    'n_estimators': [100, 200, 300],
                    'max_depth': [10, 20, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4]
                },
                'GradientBoostingClassifier': {
                    'n_estimators': [100, 200],
                    'learning_rate': [0.01, 0.1, 0.2],
                    'max_depth': [3, 5, 7]
                },
                'SVC': {
                    'C': [0.1, 1, 10],
                    'gamma': ['scale', 'auto', 0.001, 0.01],
                    'kernel': ['rbf', 'linear']
                },
                'MLPClassifier': {
                    'hidden_layer_sizes': [(100,), (100, 50), (200, 100)],
                    'alpha': [0.0001, 0.001, 0.01],
                    'learning_rate': ['constant', 'adaptive']
                }
            }
            
            model_type = type(model).__name__
            
            if model_type in param_grids:
                param_grid = param_grids[model_type]
                
                # Create new model instance
                new_model = type(model)()
                
                # Perform grid search
                grid_search = GridSearchCV(
                    new_model, param_grid, cv=3, scoring='accuracy', n_jobs=-1
                )
                
                grid_search.fit(X_train, y_train)
                
                return grid_search.best_estimator_, grid_search.best_params_
            else:
                # Fallback: return original model with empty parameters
                return model, {}
                
        except Exception as e:
            self.logger.error(f"Grid search optimization failed: {e}")
            return model, {}
    
    def feature_selection_optimization(self, model, X_train: np.ndarray, y_train: np.ndarray,
                                     X_test: np.ndarray, y_test: np.ndarray) -> Tuple[Any, Dict]:
        """Optimize model using feature selection"""
        try:
            from sklearn.feature_selection import SelectKBest, f_classif, RFE
            
            # Try different feature selection methods
            best_score = 0
            best_model = model
            best_params = {}
            
            # SelectKBest with different k values
            for k in [10, 20, 30, min(50, X_train.shape[1])]:
                if k >= X_train.shape[1]:
                    continue
                    
                selector = SelectKBest(f_classif, k=k)
                X_train_selected = selector.fit_transform(X_train, y_train)
                X_test_selected = selector.transform(X_test)
                
                # Train model on selected features
                temp_model = type(model)()
                temp_model.fit(X_train_selected, y_train)
                
                # Evaluate
                score = temp_model.score(X_test_selected, y_test)
                
                if score > best_score:
                    best_score = score
                    best_model = temp_model
                    best_params = {'feature_selection': 'SelectKBest', 'k': k}
            
            return best_model, best_params
            
        except Exception as e:
            self.logger.error(f"Feature selection optimization failed: {e}")
            return model, {}
    
    def ensemble_optimization(self, model, X_train: np.ndarray, y_train: np.ndarray) -> Tuple[Any, Dict]:
        """Optimize using ensemble methods"""
        try:
            from sklearn.ensemble import VotingClassifier, BaggingClassifier
            
            # Create ensemble with multiple models
            models = [
                ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
                ('gb', GradientBoostingClassifier(n_estimators=100, random_state=42)),
                ('original', model)
            ]
            
            # Voting classifier
            ensemble = VotingClassifier(models, voting='soft' if hasattr(model, 'predict_proba') else 'hard')
            ensemble.fit(X_train, y_train)
            
            return ensemble, {'optimization_type': 'ensemble', 'models_count': len(models)}
            
        except Exception as e:
            self.logger.error(f"Ensemble optimization failed: {e}")
            return model, {}
    
    def neural_architecture_optimization(self, X_train: np.ndarray, y_train: np.ndarray) -> Tuple[Any, Dict]:
        """Optimize neural network architecture"""
        try:
            # Try different neural network architectures
            architectures = [
                (100,),
                (200, 100),
                (300, 200, 100),
                (500, 300, 100),
                (100, 50, 25)
            ]
            
            best_score = 0
            best_model = None
            best_params = {}
            
            for arch in architectures:
                model = MLPClassifier(
                    hidden_layer_sizes=arch,
                    max_iter=1000,
                    random_state=42,
                    early_stopping=True,
                    validation_fraction=0.1
                )
                
                try:
                    model.fit(X_train, y_train)
                    score = model.score(X_train, y_train)
                    
                    if score > best_score:
                        best_score = score
                        best_model = model
                        best_params = {'architecture': arch, 'layers': len(arch)}
                        
                except Exception:
                    continue
            
            return best_model or MLPClassifier(), best_params
            
        except Exception as e:
            self.logger.error(f"Neural architecture optimization failed: {e}")
            return MLPClassifier(), {}
    
    def generate_optimization_recommendation(self, original: ModelPerformanceMetrics, 
                                           optimized: ModelPerformanceMetrics,
                                           method: str, parameters: Dict) -> str:
        """Generate optimization recommendation"""
        improvement = optimized.accuracy - original.accuracy
        
        if improvement > 0.05:
            recommendation = f"Excellent improvement! The {method} optimization increased accuracy by {improvement:.3f}. "
        elif improvement > 0.01:
            recommendation = f"Good improvement! The {method} optimization increased accuracy by {improvement:.3f}. "
        elif improvement > 0:
            recommendation = f"Minor improvement achieved with {method} optimization (+{improvement:.3f} accuracy). "
        else:
            recommendation = f"The {method} optimization did not improve performance. Consider trying different methods. "
        
        # Add specific recommendations based on metrics
        if optimized.precision < 0.8:
            recommendation += "Consider focusing on precision improvement to reduce false positives. "
        
        if optimized.recall < 0.8:
            recommendation += "Consider focusing on recall improvement to catch more threats. "
        
        if optimized.prediction_time > original.prediction_time * 2:
            recommendation += "The optimization increased prediction time significantly - consider performance trade-offs. "
        
        return recommendation
    
    def load_model(self, model_path: str):
        """Load model from file"""
        try:
            if model_path in self.model_cache:
                return self.model_cache[model_path]
            
            if model_path.endswith('.pkl'):
                model = joblib.load(model_path)
            elif model_path.endswith('.onnx'):
                # For ONNX models, we'd need onnxruntime
                # For now, return None to indicate unsupported
                return None
            else:
                return None
            
            self.model_cache[model_path] = model
            return model
            
        except Exception as e:
            self.logger.error(f"Failed to load model from {model_path}: {e}")
            return None
    
    def save_performance_metrics(self, metrics: ModelPerformanceMetrics):
        """Save performance metrics to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO model_performance 
                    (model_name, accuracy, precision_score, recall_score, f1_score, roc_auc,
                     training_time, prediction_time, model_size, feature_count, sample_count,
                     cross_val_scores, confusion_matrix, feature_importance, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.model_name,
                    metrics.accuracy,
                    metrics.precision,
                    metrics.recall,
                    metrics.f1_score,
                    metrics.roc_auc,
                    metrics.training_time,
                    metrics.prediction_time,
                    metrics.model_size,
                    metrics.feature_count,
                    metrics.sample_count,
                    json.dumps(metrics.cross_val_scores),
                    json.dumps(metrics.confusion_matrix),
                    json.dumps(metrics.feature_importance) if metrics.feature_importance else None,
                    metrics.timestamp
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save performance metrics: {e}")
    
    def save_optimization_result(self, result: OptimizationResult):
        """Save optimization result to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO optimization_history 
                    (model_name, optimization_method, improvement_percentage, parameters_changed,
                     recommendation, original_accuracy, optimized_accuracy, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.original_metrics.model_name,
                    result.optimization_method,
                    result.improvement_percentage,
                    json.dumps(result.parameters_changed),
                    result.recommendation,
                    result.original_metrics.accuracy,
                    result.optimized_metrics.accuracy,
                    datetime.now().isoformat()
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save optimization result: {e}")
    
    def get_performance_history(self, model_name: str = None, days: int = 30) -> List[Dict]:
        """Get model performance history"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if model_name:
                    cursor.execute('''
                        SELECT * FROM model_performance 
                        WHERE model_name = ? AND timestamp >= ?
                        ORDER BY timestamp DESC
                    ''', (model_name, cutoff_date))
                else:
                    cursor.execute('''
                        SELECT * FROM model_performance 
                        WHERE timestamp >= ?
                        ORDER BY timestamp DESC
                    ''', (cutoff_date,))
                
                columns = [desc[0] for desc in cursor.description]
                history = []
                
                for row in cursor.fetchall():
                    record = dict(zip(columns, row))
                    # Parse JSON fields
                    if record['cross_val_scores']:
                        record['cross_val_scores'] = json.loads(record['cross_val_scores'])
                    if record['confusion_matrix']:
                        record['confusion_matrix'] = json.loads(record['confusion_matrix'])
                    if record['feature_importance']:
                        record['feature_importance'] = json.loads(record['feature_importance'])
                    history.append(record)
                
                return history
                
        except Exception as e:
            self.logger.error(f"Failed to get performance history: {e}")
            return []
    
    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        return {
            **self.performance_stats,
            'optimization_history_count': len(self.optimization_history),
            'cached_models': len(self.model_cache)
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.model_cache.clear()
        self.scaler_cache.clear()
        self.logger.info("AI Model Optimizer cleaned up")
