#!/usr/bin/env python3
"""
Model Architecture Search System
Neural Architecture Search (NAS) and automated model design
"""

import os
import json
import time
import logging
import numpy as np
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import hashlib
import pickle

try:
    from sklearn.neural_network import MLPClassifier
    from sklearn.ensemble import VotingClassifier, StackingClassifier
    from sklearn.base import BaseEstimator, ClassifierMixin
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models, optimizers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    print("Warning: TensorFlow not available. Limited architecture search capabilities.")

@dataclass
class NetworkArchitecture:
    """Neural network architecture definition"""
    architecture_id: str
    layers: List[Dict[str, Any]]
    optimizer_config: Dict[str, Any]
    loss_function: str
    metrics: List[str]
    input_shape: Tuple[int, ...]
    output_shape: int
    performance_score: float = 0.0
    training_time: float = 0.0
    model_size: int = 0  # Number of parameters
    created_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        if not self.architecture_id:
            arch_str = json.dumps({
                'layers': self.layers,
                'optimizer': self.optimizer_config,
                'loss': self.loss_function
            }, sort_keys=True)
            self.architecture_id = hashlib.md5(arch_str.encode()).hexdigest()

@dataclass
class EnsembleArchitecture:
    """Ensemble model architecture"""
    ensemble_id: str
    base_models: List[str]  # Model types or IDs
    ensemble_method: str  # 'voting', 'stacking', 'bagging'
    ensemble_params: Dict[str, Any]
    performance_score: float = 0.0
    diversity_score: float = 0.0  # Measure of model diversity
    created_at: datetime = field(default_factory=datetime.now)

class ModelArchitectureSearch:
    """Neural Architecture Search and model design automation"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.ai.model_architecture_search')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = os.path.join(models_dir, "architecture_search.db")
        
        os.makedirs(models_dir, exist_ok=True)
        self.init_database()
        
        # Architecture search spaces
        self.layer_types = ['dense', 'dropout', 'batch_norm']
        self.activation_functions = ['relu', 'tanh', 'sigmoid', 'leaky_relu']
        self.optimizer_types = ['adam', 'sgd', 'rmsprop', 'adagrad']
        
        # Architecture templates
        self.architecture_templates = {
            'shallow': {'min_layers': 1, 'max_layers': 3, 'max_units': 128},
            'medium': {'min_layers': 2, 'max_layers': 5, 'max_units': 256},
            'deep': {'min_layers': 4, 'max_layers': 8, 'max_units': 512},
            'wide': {'min_layers': 2, 'max_layers': 4, 'max_units': 1024}
        }
    
    def init_database(self):
        """Initialize database for architecture search results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Network architectures table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS network_architectures (
                        architecture_id TEXT PRIMARY KEY,
                        layers TEXT NOT NULL,
                        optimizer_config TEXT NOT NULL,
                        loss_function TEXT NOT NULL,
                        metrics TEXT NOT NULL,
                        input_shape TEXT NOT NULL,
                        output_shape INTEGER NOT NULL,
                        performance_score REAL NOT NULL,
                        training_time REAL NOT NULL,
                        model_size INTEGER NOT NULL,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                # Ensemble architectures table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ensemble_architectures (
                        ensemble_id TEXT PRIMARY KEY,
                        base_models TEXT NOT NULL,
                        ensemble_method TEXT NOT NULL,
                        ensemble_params TEXT NOT NULL,
                        performance_score REAL NOT NULL,
                        diversity_score REAL NOT NULL,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                # Architecture search sessions
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS search_sessions (
                        session_id TEXT PRIMARY KEY,
                        search_type TEXT NOT NULL,
                        search_params TEXT NOT NULL,
                        best_architecture_id TEXT NOT NULL,
                        total_architectures INTEGER NOT NULL,
                        search_time REAL NOT NULL,
                        dataset_info TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                conn.commit()
                self.logger.info("Architecture search database initialized")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def generate_random_architecture(self, template: str, input_shape: Tuple[int, ...], 
                                   output_shape: int) -> NetworkArchitecture:
        """Generate random neural network architecture"""
        try:
            if template not in self.architecture_templates:
                template = 'medium'
            
            config = self.architecture_templates[template]
            n_layers = np.random.randint(config['min_layers'], config['max_layers'] + 1)
            
            layers = []
            
            # Input layer is implicit in Keras
            current_units = np.random.randint(32, config['max_units'] + 1)
            
            # Hidden layers
            for i in range(n_layers):
                # Dense layer
                layers.append({
                    'type': 'dense',
                    'units': current_units,
                    'activation': np.random.choice(self.activation_functions)
                })
                
                # Optional dropout
                if np.random.random() < 0.3:  # 30% chance of dropout
                    layers.append({
                        'type': 'dropout',
                        'rate': np.random.uniform(0.1, 0.5)
                    })
                
                # Optional batch normalization
                if np.random.random() < 0.2:  # 20% chance of batch norm
                    layers.append({
                        'type': 'batch_norm'
                    })
                
                # Reduce units for next layer
                current_units = max(16, int(current_units * np.random.uniform(0.5, 0.9)))
            
            # Output layer
            layers.append({
                'type': 'dense',
                'units': output_shape,
                'activation': 'sigmoid' if output_shape == 1 else 'softmax'
            })
            
            # Optimizer configuration
            optimizer_type = np.random.choice(self.optimizer_types)
            optimizer_config = {
                'type': optimizer_type,
                'learning_rate': np.random.uniform(0.0001, 0.01)
            }
            
            if optimizer_type == 'adam':
                optimizer_config.update({
                    'beta_1': np.random.uniform(0.8, 0.95),
                    'beta_2': np.random.uniform(0.9, 0.999)
                })
            elif optimizer_type == 'sgd':
                optimizer_config.update({
                    'momentum': np.random.uniform(0.0, 0.9)
                })
            
            # Loss function
            loss_function = 'binary_crossentropy' if output_shape == 1 else 'sparse_categorical_crossentropy'
            
            return NetworkArchitecture(
                architecture_id="",  # Will be generated in __post_init__
                layers=layers,
                optimizer_config=optimizer_config,
                loss_function=loss_function,
                metrics=['accuracy'],
                input_shape=input_shape,
                output_shape=output_shape
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate random architecture: {e}")
            return None
    
    def build_keras_model(self, architecture: NetworkArchitecture):
        """Build Keras model from architecture definition"""
        if not TF_AVAILABLE:
            self.logger.warning("TensorFlow not available. Cannot build Keras model.")
            return None
        
        try:
            model = models.Sequential()
            
            # Add layers
            for i, layer_config in enumerate(architecture.layers):
                if layer_config['type'] == 'dense':
                    if i == 0:
                        # First layer needs input shape
                        model.add(layers.Dense(
                            layer_config['units'],
                            activation=layer_config['activation'],
                            input_shape=architecture.input_shape
                        ))
                    else:
                        model.add(layers.Dense(
                            layer_config['units'],
                            activation=layer_config['activation']
                        ))
                elif layer_config['type'] == 'dropout':
                    model.add(layers.Dropout(layer_config['rate']))
                elif layer_config['type'] == 'batch_norm':
                    model.add(layers.BatchNormalization())
            
            # Configure optimizer
            opt_config = architecture.optimizer_config
            if opt_config['type'] == 'adam':
                optimizer = optimizers.Adam(
                    learning_rate=opt_config['learning_rate'],
                    beta_1=opt_config.get('beta_1', 0.9),
                    beta_2=opt_config.get('beta_2', 0.999)
                )
            elif opt_config['type'] == 'sgd':
                optimizer = optimizers.SGD(
                    learning_rate=opt_config['learning_rate'],
                    momentum=opt_config.get('momentum', 0.0)
                )
            elif opt_config['type'] == 'rmsprop':
                optimizer = optimizers.RMSprop(learning_rate=opt_config['learning_rate'])
            else:
                optimizer = optimizers.Adam(learning_rate=opt_config['learning_rate'])
            
            # Compile model
            model.compile(
                optimizer=optimizer,
                loss=architecture.loss_function,
                metrics=architecture.metrics
            )
            
            return model
            
        except Exception as e:
            self.logger.error(f"Failed to build Keras model: {e}")
            return None
    
    def evaluate_architecture(self, architecture: NetworkArchitecture, X, y, 
                            validation_split: float = 0.2, epochs: int = 50) -> float:
        """Evaluate neural network architecture"""
        try:
            if TF_AVAILABLE:
                return self._evaluate_keras_architecture(architecture, X, y, validation_split, epochs)
            else:
                return self._evaluate_sklearn_architecture(architecture, X, y)
                
        except Exception as e:
            self.logger.error(f"Architecture evaluation failed: {e}")
            return 0.0
    
    def _evaluate_keras_architecture(self, architecture: NetworkArchitecture, X, y, 
                                   validation_split: float, epochs: int) -> float:
        """Evaluate architecture using Keras"""
        try:
            model = self.build_keras_model(architecture)
            if model is None:
                return 0.0
            
            start_time = time.time()
            
            # Train model
            history = model.fit(
                X, y,
                validation_split=validation_split,
                epochs=epochs,
                verbose=0,
                batch_size=min(32, len(X) // 10)
            )
            
            # Get best validation accuracy
            val_accuracy = max(history.history.get('val_accuracy', [0]))
            
            # Update architecture with results
            architecture.performance_score = val_accuracy
            architecture.training_time = time.time() - start_time
            architecture.model_size = model.count_params()
            
            return val_accuracy
            
        except Exception as e:
            self.logger.error(f"Keras architecture evaluation failed: {e}")
            return 0.0
    
    def _evaluate_sklearn_architecture(self, architecture: NetworkArchitecture, X, y) -> float:
        """Evaluate architecture using sklearn MLPClassifier"""
        try:
            # Convert architecture to sklearn MLP parameters
            hidden_layer_sizes = []
            for layer in architecture.layers:
                if layer['type'] == 'dense' and layer != architecture.layers[-1]:  # Exclude output layer
                    hidden_layer_sizes.append(layer['units'])
            
            if not hidden_layer_sizes:
                hidden_layer_sizes = [100]  # Default
            
            # Get activation from first dense layer
            activation = 'relu'
            for layer in architecture.layers:
                if layer['type'] == 'dense':
                    activation = layer['activation']
                    break
            
            # Map activations
            activation_map = {'leaky_relu': 'relu'}
            activation = activation_map.get(activation, activation)
            
            # Create and train model
            model = MLPClassifier(
                hidden_layer_sizes=tuple(hidden_layer_sizes),
                activation=activation,
                learning_rate_init=architecture.optimizer_config['learning_rate'],
                max_iter=200,
                random_state=42
            )
            
            start_time = time.time()
            model.fit(X, y)
            
            # Evaluate
            score = model.score(X, y)
            
            # Update architecture
            architecture.performance_score = score
            architecture.training_time = time.time() - start_time
            architecture.model_size = sum(layer.size for layer in model.coefs_)
            
            return score
            
        except Exception as e:
            self.logger.error(f"Sklearn architecture evaluation failed: {e}")
            return 0.0
    
    def search_architectures(self, X, y, n_architectures: int = 50, 
                           template: str = 'medium') -> List[NetworkArchitecture]:
        """Search for best neural network architectures"""
        try:
            input_shape = (X.shape[1],)
            output_shape = len(np.unique(y)) if len(np.unique(y)) > 2 else 1
            
            architectures = []
            
            self.logger.info(f"Starting architecture search with {n_architectures} candidates")
            
            for i in range(n_architectures):
                # Generate random architecture
                arch = self.generate_random_architecture(template, input_shape, output_shape)
                if arch is None:
                    continue
                
                # Evaluate architecture
                score = self.evaluate_architecture(arch, X, y)
                arch.performance_score = score
                
                architectures.append(arch)
                
                # Store in database
                self.store_architecture(arch)
                
                if (i + 1) % 10 == 0:
                    self.logger.info(f"Evaluated {i + 1}/{n_architectures} architectures")
            
            # Sort by performance
            architectures.sort(key=lambda x: x.performance_score, reverse=True)
            
            self.logger.info(f"Architecture search completed. Best score: {architectures[0].performance_score:.4f}")
            
            return architectures
            
        except Exception as e:
            self.logger.error(f"Architecture search failed: {e}")
            return []
    
    def create_ensemble_architecture(self, base_models: List[str], 
                                   ensemble_method: str = 'voting') -> EnsembleArchitecture:
        """Create ensemble architecture from base models"""
        try:
            ensemble_params = {}
            
            if ensemble_method == 'voting':
                ensemble_params = {
                    'voting': 'soft',  # Use predicted probabilities
                    'weights': None    # Equal weights
                }
            elif ensemble_method == 'stacking':
                ensemble_params = {
                    'final_estimator': 'logistic_regression',
                    'cv': 5
                }
            elif ensemble_method == 'bagging':
                ensemble_params = {
                    'n_estimators': len(base_models),
                    'bootstrap': True
                }
            
            ensemble = EnsembleArchitecture(
                ensemble_id="",  # Will be generated
                base_models=base_models,
                ensemble_method=ensemble_method,
                ensemble_params=ensemble_params
            )
            
            # Generate ID
            ensemble_str = json.dumps({
                'base_models': base_models,
                'method': ensemble_method,
                'params': ensemble_params
            }, sort_keys=True)
            ensemble.ensemble_id = hashlib.md5(ensemble_str.encode()).hexdigest()
            
            return ensemble
            
        except Exception as e:
            self.logger.error(f"Failed to create ensemble architecture: {e}")
            return None
    
    def store_architecture(self, architecture: NetworkArchitecture):
        """Store network architecture in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO network_architectures 
                    (architecture_id, layers, optimizer_config, loss_function, metrics,
                     input_shape, output_shape, performance_score, training_time, 
                     model_size, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    architecture.architecture_id,
                    json.dumps(architecture.layers),
                    json.dumps(architecture.optimizer_config),
                    architecture.loss_function,
                    json.dumps(architecture.metrics),
                    json.dumps(architecture.input_shape),
                    architecture.output_shape,
                    architecture.performance_score,
                    architecture.training_time,
                    architecture.model_size,
                    architecture.created_at.isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store architecture: {e}")
    
    def store_ensemble_architecture(self, ensemble: EnsembleArchitecture):
        """Store ensemble architecture in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO ensemble_architectures 
                    (ensemble_id, base_models, ensemble_method, ensemble_params,
                     performance_score, diversity_score, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ensemble.ensemble_id,
                    json.dumps(ensemble.base_models),
                    ensemble.ensemble_method,
                    json.dumps(ensemble.ensemble_params),
                    ensemble.performance_score,
                    ensemble.diversity_score,
                    ensemble.created_at.isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store ensemble architecture: {e}")
    
    def get_best_architectures(self, limit: int = 10) -> List[NetworkArchitecture]:
        """Get best performing architectures"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM network_architectures 
                    ORDER BY performance_score DESC 
                    LIMIT ?
                ''', (limit,))
                
                rows = cursor.fetchall()
                architectures = []
                
                for row in rows:
                    arch = NetworkArchitecture(
                        architecture_id=row[0],
                        layers=json.loads(row[1]),
                        optimizer_config=json.loads(row[2]),
                        loss_function=row[3],
                        metrics=json.loads(row[4]),
                        input_shape=tuple(json.loads(row[5])),
                        output_shape=row[6],
                        performance_score=row[7],
                        training_time=row[8],
                        model_size=row[9],
                        created_at=datetime.fromisoformat(row[10])
                    )
                    architectures.append(arch)
                
                return architectures
                
        except Exception as e:
            self.logger.error(f"Failed to get best architectures: {e}")
            return []
    
    def get_search_statistics(self) -> Dict[str, Any]:
        """Get architecture search statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total architectures
                cursor.execute('SELECT COUNT(*) FROM network_architectures')
                total_architectures = cursor.fetchone()[0]
                
                # Best performance
                cursor.execute('SELECT MAX(performance_score) FROM network_architectures')
                best_score = cursor.fetchone()[0] or 0.0
                
                # Average performance
                cursor.execute('SELECT AVG(performance_score) FROM network_architectures')
                avg_score = cursor.fetchone()[0] or 0.0
                
                # Architecture complexity distribution
                cursor.execute('SELECT AVG(model_size) FROM network_architectures')
                avg_model_size = cursor.fetchone()[0] or 0
                
                return {
                    'total_architectures': total_architectures,
                    'best_performance': best_score,
                    'average_performance': avg_score,
                    'average_model_size': avg_model_size
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get search statistics: {e}")
            return {}
    
    def export_architecture(self, architecture_id: str, filepath: str):
        """Export architecture definition to file"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM network_architectures WHERE architecture_id = ?
                ''', (architecture_id,))
                
                row = cursor.fetchone()
                if not row:
                    raise ValueError(f"Architecture {architecture_id} not found")
                
                arch_data = {
                    'architecture_id': row[0],
                    'layers': json.loads(row[1]),
                    'optimizer_config': json.loads(row[2]),
                    'loss_function': row[3],
                    'metrics': json.loads(row[4]),
                    'input_shape': json.loads(row[5]),
                    'output_shape': row[6],
                    'performance_score': row[7],
                    'training_time': row[8],
                    'model_size': row[9],
                    'created_at': row[10]
                }
                
                with open(filepath, 'w') as f:
                    json.dump(arch_data, f, indent=2)
                
                self.logger.info(f"Architecture exported to {filepath}")
                
        except Exception as e:
            self.logger.error(f"Failed to export architecture: {e}")
    
    def import_architecture(self, filepath: str) -> NetworkArchitecture:
        """Import architecture definition from file"""
        try:
            with open(filepath, 'r') as f:
                arch_data = json.load(f)
            
            architecture = NetworkArchitecture(
                architecture_id=arch_data['architecture_id'],
                layers=arch_data['layers'],
                optimizer_config=arch_data['optimizer_config'],
                loss_function=arch_data['loss_function'],
                metrics=arch_data['metrics'],
                input_shape=tuple(arch_data['input_shape']),
                output_shape=arch_data['output_shape'],
                performance_score=arch_data['performance_score'],
                training_time=arch_data['training_time'],
                model_size=arch_data['model_size'],
                created_at=datetime.fromisoformat(arch_data['created_at'])
            )
            
            # Store in database
            self.store_architecture(architecture)
            
            self.logger.info(f"Architecture imported from {filepath}")
            return architecture
            
        except Exception as e:
            self.logger.error(f"Failed to import architecture: {e}")
            return None
