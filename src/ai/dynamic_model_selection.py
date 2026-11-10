#!/usr/bin/env python3
"""
Dynamic Model Selection System
Intelligent model selection based on data characteristics and performance metrics
"""

import os
import json
import time
import logging
import numpy as np
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import hashlib

try:
    from sklearn.model_selection import cross_val_score
    from sklearn.metrics import accuracy_score
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

@dataclass
class DatasetCharacteristics:
    """Dataset characteristics for model selection"""
    n_samples: int
    n_features: int
    n_classes: int
    class_balance: Dict[str, float]
    missing_values_ratio: float
    outlier_ratio: float
    dimensionality_ratio: float
    noise_level: float
    separability_score: float
    complexity_score: float
    dataset_id: str = field(default="")
    
    def __post_init__(self):
        if not self.dataset_id:
            char_str = json.dumps({
                'n_samples': self.n_samples,
                'n_features': self.n_features,
                'n_classes': self.n_classes
            }, sort_keys=True)
            self.dataset_id = hashlib.md5(char_str.encode()).hexdigest()

@dataclass
class SelectionDecision:
    """Model selection decision with reasoning"""
    selected_model: str
    confidence_score: float
    reasoning: List[str]
    alternative_models: List[Tuple[str, float]]
    dataset_characteristics: DatasetCharacteristics
    selection_time: float
    decision_id: str = field(default="")
    
    def __post_init__(self):
        if not self.decision_id:
            decision_str = f"{self.selected_model}_{int(time.time())}"
            self.decision_id = hashlib.md5(decision_str.encode()).hexdigest()

class DynamicModelSelector:
    """Dynamic model selection based on data characteristics"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.ai.dynamic_model_selection')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = os.path.join(models_dir, "model_selection.db")
        
        os.makedirs(models_dir, exist_ok=True)
        self.init_database()
        
        # Available model types
        self.available_models = [
            'random_forest', 'gradient_boosting', 'xgboost', 'lightgbm',
            'svm', 'logistic_regression', 'naive_bayes', 'mlp'
        ]
        
        # Model selection rules
        self.selection_rules = {
            'small_dataset': {
                'condition': lambda chars: chars.n_samples < 1000,
                'preferred_models': ['naive_bayes', 'logistic_regression'],
                'avoid_models': ['xgboost', 'lightgbm'],
                'reasoning': 'Small datasets work better with simpler models'
            },
            'large_dataset': {
                'condition': lambda chars: chars.n_samples > 10000,
                'preferred_models': ['xgboost', 'lightgbm', 'random_forest'],
                'avoid_models': ['svm'],
                'reasoning': 'Large datasets benefit from ensemble methods'
            },
            'high_dimensional': {
                'condition': lambda chars: chars.dimensionality_ratio > 0.1,
                'preferred_models': ['logistic_regression', 'svm', 'random_forest'],
                'avoid_models': ['naive_bayes'],
                'reasoning': 'High-dimensional data needs regularization'
            },
            'imbalanced_classes': {
                'condition': lambda chars: min(chars.class_balance.values()) < 0.1,
                'preferred_models': ['random_forest', 'gradient_boosting', 'xgboost'],
                'avoid_models': ['naive_bayes'],
                'reasoning': 'Imbalanced data works better with ensemble methods'
            }
        }
    
    def init_database(self):
        """Initialize database for model selection data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS selection_decisions (
                        decision_id TEXT PRIMARY KEY,
                        selected_model TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        reasoning TEXT NOT NULL,
                        alternative_models TEXT NOT NULL,
                        dataset_characteristics TEXT NOT NULL,
                        selection_time REAL NOT NULL,
                        actual_performance REAL,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                conn.commit()
                self.logger.info("Model selection database initialized")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def analyze_dataset_characteristics(self, X, y) -> DatasetCharacteristics:
        """Analyze dataset characteristics for model selection"""
        try:
            n_samples, n_features = X.shape
            n_classes = len(np.unique(y))
            
            # Class balance
            unique, counts = np.unique(y, return_counts=True)
            class_balance = {str(cls): count / n_samples for cls, count in zip(unique, counts)}
            
            # Missing values ratio
            if hasattr(X, 'isnull'):
                missing_values_ratio = X.isnull().sum().sum() / (n_samples * n_features)
            else:
                missing_values_ratio = np.isnan(X).sum() / (n_samples * n_features) if X.dtype.kind in 'fc' else 0.0
            
            # Outlier detection using IQR method
            outlier_ratio = self._calculate_outlier_ratio(X)
            
            # Dimensionality ratio
            dimensionality_ratio = n_features / n_samples
            
            # Noise level estimation
            noise_level = self._estimate_noise_level(X, y)
            
            # Class separability
            separability_score = self._calculate_separability(X, y)
            
            # Dataset complexity
            complexity_score = self._calculate_complexity(X, y)
            
            return DatasetCharacteristics(
                n_samples=n_samples,
                n_features=n_features,
                n_classes=n_classes,
                class_balance=class_balance,
                missing_values_ratio=missing_values_ratio,
                outlier_ratio=outlier_ratio,
                dimensionality_ratio=dimensionality_ratio,
                noise_level=noise_level,
                separability_score=separability_score,
                complexity_score=complexity_score
            )
            
        except Exception as e:
            self.logger.error(f"Failed to analyze dataset characteristics: {e}")
            return DatasetCharacteristics(
                n_samples=len(X), n_features=X.shape[1] if hasattr(X, 'shape') else 0,
                n_classes=len(np.unique(y)), class_balance={},
                missing_values_ratio=0.0, outlier_ratio=0.0, dimensionality_ratio=0.0,
                noise_level=0.0, separability_score=0.5, complexity_score=0.5
            )
    
    def _calculate_outlier_ratio(self, X) -> float:
        """Calculate ratio of outliers using IQR method"""
        try:
            outlier_count = 0
            total_values = 0
            
            for i in range(X.shape[1]):
                col = X[:, i] if hasattr(X, '__getitem__') else X.iloc[:, i]
                if np.issubdtype(col.dtype, np.number):
                    Q1 = np.percentile(col, 25)
                    Q3 = np.percentile(col, 75)
                    IQR = Q3 - Q1
                    lower_bound = Q1 - 1.5 * IQR
                    upper_bound = Q3 + 1.5 * IQR
                    outliers = (col < lower_bound) | (col > upper_bound)
                    outlier_count += np.sum(outliers)
                    total_values += len(col)
            
            return outlier_count / total_values if total_values > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"Outlier ratio calculation failed: {e}")
            return 0.1
    
    def _estimate_noise_level(self, X, y) -> float:
        """Estimate noise level in the dataset"""
        try:
            if not SKLEARN_AVAILABLE:
                return 0.2
            
            knn = KNeighborsClassifier(n_neighbors=5)
            scores = cross_val_score(knn, X, y, cv=3, scoring='accuracy')
            avg_accuracy = np.mean(scores)
            noise_level = max(0.0, 1.0 - avg_accuracy)
            
            return min(1.0, noise_level)
            
        except Exception as e:
            self.logger.error(f"Noise level estimation failed: {e}")
            return 0.2
    
    def _calculate_separability(self, X, y) -> float:
        """Calculate class separability score"""
        try:
            if not SKLEARN_AVAILABLE:
                return 0.5
            
            lda = LinearDiscriminantAnalysis()
            scores = cross_val_score(lda, X, y, cv=3, scoring='accuracy')
            
            return np.mean(scores)
            
        except Exception as e:
            self.logger.error(f"Separability calculation failed: {e}")
            return 0.5
    
    def _calculate_complexity(self, X, y) -> float:
        """Calculate dataset complexity score"""
        try:
            complexity_factors = []
            
            # Feature correlation complexity
            if X.shape[1] > 1:
                corr_matrix = np.corrcoef(X.T)
                avg_correlation = np.mean(np.abs(corr_matrix[np.triu_indices_from(corr_matrix, k=1)]))
                complexity_factors.append(avg_correlation)
            
            # Dimensionality complexity
            dim_complexity = min(1.0, X.shape[1] / 100)
            complexity_factors.append(dim_complexity)
            
            return np.mean(complexity_factors) if complexity_factors else 0.5
            
        except Exception as e:
            self.logger.error(f"Complexity calculation failed: {e}")
            return 0.5
    
    def select_best_model(self, X, y, available_models: Optional[List[str]] = None) -> SelectionDecision:
        """Select best model based on dataset characteristics"""
        try:
            start_time = time.time()
            
            # Analyze dataset characteristics
            characteristics = self.analyze_dataset_characteristics(X, y)
            
            # Get available models
            if available_models is None:
                available_models = self.available_models
            
            # Apply selection rules
            model_scores = self._apply_selection_rules(characteristics, available_models)
            
            # Sort models by score
            sorted_models = sorted(model_scores.items(), key=lambda x: x[1], reverse=True)
            
            if not sorted_models:
                selected_model = 'random_forest'
                confidence_score = 0.5
                reasoning = ['Fallback to default model']
                alternatives = []
            else:
                selected_model = sorted_models[0][0]
                confidence_score = sorted_models[0][1]
                alternatives = sorted_models[1:5]
                reasoning = self._generate_reasoning(characteristics, selected_model)
            
            selection_time = time.time() - start_time
            
            decision = SelectionDecision(
                selected_model=selected_model,
                confidence_score=confidence_score,
                reasoning=reasoning,
                alternative_models=alternatives,
                dataset_characteristics=characteristics,
                selection_time=selection_time
            )
            
            # Store decision
            self.store_selection_decision(decision)
            
            return decision
            
        except Exception as e:
            self.logger.error(f"Model selection failed: {e}")
            return SelectionDecision(
                selected_model='random_forest',
                confidence_score=0.5,
                reasoning=['Error in selection process'],
                alternative_models=[],
                dataset_characteristics=self.analyze_dataset_characteristics(X, y),
                selection_time=0.0
            )
    
    def _apply_selection_rules(self, characteristics: DatasetCharacteristics, 
                             available_models: List[str]) -> Dict[str, float]:
        """Apply rule-based model selection"""
        model_scores = {model: 0.5 for model in available_models}
        
        for rule_name, rule in self.selection_rules.items():
            try:
                if rule['condition'](characteristics):
                    for model in rule['preferred_models']:
                        if model in model_scores:
                            model_scores[model] += 0.2
                    
                    for model in rule['avoid_models']:
                        if model in model_scores:
                            model_scores[model] -= 0.2
                            
            except Exception as e:
                self.logger.warning(f"Rule {rule_name} failed: {e}")
                continue
        
        # Normalize scores
        for model in model_scores:
            model_scores[model] = max(0.0, min(1.0, model_scores[model]))
        
        return model_scores
    
    def _generate_reasoning(self, characteristics: DatasetCharacteristics, 
                          selected_model: str) -> List[str]:
        """Generate reasoning for model selection"""
        reasoning = []
        
        try:
            if characteristics.n_samples < 1000:
                reasoning.append(f"Small dataset ({characteristics.n_samples} samples)")
            elif characteristics.n_samples > 10000:
                reasoning.append(f"Large dataset ({characteristics.n_samples} samples)")
            
            if characteristics.dimensionality_ratio > 0.1:
                reasoning.append(f"High-dimensional data ({characteristics.n_features} features)")
            
            min_class_ratio = min(characteristics.class_balance.values())
            if min_class_ratio < 0.1:
                reasoning.append(f"Imbalanced classes (min ratio: {min_class_ratio:.2f})")
            
            model_reasons = {
                'random_forest': 'Robust ensemble method',
                'xgboost': 'High-performance gradient boosting',
                'logistic_regression': 'Simple and interpretable',
                'svm': 'Effective for complex boundaries',
                'naive_bayes': 'Fast for small datasets'
            }
            
            if selected_model in model_reasons:
                reasoning.append(model_reasons[selected_model])
            
            return reasoning[:5]
            
        except Exception as e:
            self.logger.error(f"Reasoning generation failed: {e}")
            return [f"Selected {selected_model}"]
    
    def store_selection_decision(self, decision: SelectionDecision):
        """Store selection decision in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO selection_decisions 
                    (decision_id, selected_model, confidence_score, reasoning, alternative_models,
                     dataset_characteristics, selection_time, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    decision.decision_id,
                    decision.selected_model,
                    decision.confidence_score,
                    json.dumps(decision.reasoning),
                    json.dumps(decision.alternative_models),
                    json.dumps(decision.dataset_characteristics.__dict__),
                    decision.selection_time,
                    datetime.now().isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store selection decision: {e}")
    
    def get_selection_statistics(self) -> Dict[str, Any]:
        """Get model selection statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM selection_decisions')
                total_decisions = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT selected_model, COUNT(*) 
                    FROM selection_decisions 
                    GROUP BY selected_model
                ''')
                model_counts = dict(cursor.fetchall())
                
                cursor.execute('SELECT AVG(confidence_score) FROM selection_decisions')
                avg_confidence = cursor.fetchone()[0] or 0.0
                
                return {
                    'total_decisions': total_decisions,
                    'model_selection_counts': model_counts,
                    'average_confidence': avg_confidence
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get selection statistics: {e}")
            return {}
