#!/usr/bin/env python3
"""
Predictive Threat Analysis Engine
Advanced AI-powered threat prediction and behavioral analysis
"""

import os
import sys
import time
import json
import sqlite3
import hashlib
import logging
import threading
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

class ThreatTrend(Enum):
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    EMERGING = "emerging"
    CRITICAL = "critical"

class PredictionConfidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

@dataclass
class ThreatPrediction:
    threat_type: str
    probability: float
    confidence: PredictionConfidence
    trend: ThreatTrend
    time_window: int  # hours
    risk_factors: List[str]
    recommended_actions: List[str]
    prediction_timestamp: datetime
    metadata: Dict[str, Any]

@dataclass
class BehavioralPattern:
    pattern_id: str
    pattern_type: str
    frequency: int
    last_seen: datetime
    risk_score: float
    indicators: List[str]
    related_threats: List[str]

class PredictiveThreatEngine:
    """Advanced predictive threat analysis engine"""
    
    def __init__(self, intelligence_engine=None, threat_classifier=None):
        self.intelligence_engine = intelligence_engine
        self.threat_classifier = threat_classifier
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.intelligence.predictive_threat_engine')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Database for behavioral patterns and predictions
        self.db_path = os.path.join(os.path.dirname(__file__), "predictive_threats.db")
        self.init_database()
        
        # Behavioral analysis components
        self.behavioral_patterns = {}
        self.threat_predictions = {}
        self.learning_models = {}
        
        # Analysis parameters
        self.prediction_window = 24  # hours
        self.pattern_threshold = 0.7
        self.confidence_threshold = 0.6
        
        # Background analysis thread
        self.analysis_thread = None
        self.running = False
        
        # Initialize machine learning models
        self.init_ml_models()
        
        self.logger.info("Predictive Threat Engine initialized")
    
    def init_database(self):
        """Initialize SQLite database for patterns and predictions"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Behavioral patterns table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS behavioral_patterns (
                        pattern_id TEXT PRIMARY KEY,
                        pattern_type TEXT NOT NULL,
                        frequency INTEGER DEFAULT 0,
                        last_seen TIMESTAMP,
                        risk_score REAL,
                        indicators TEXT,
                        related_threats TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Threat predictions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_predictions (
                        prediction_id TEXT PRIMARY KEY,
                        threat_type TEXT NOT NULL,
                        probability REAL,
                        confidence TEXT,
                        trend TEXT,
                        time_window INTEGER,
                        risk_factors TEXT,
                        recommended_actions TEXT,
                        prediction_timestamp TIMESTAMP,
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Threat events table for learning
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_events (
                        event_id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        severity REAL,
                        timestamp TIMESTAMP,
                        file_path TEXT,
                        process_name TEXT,
                        behavioral_indicators TEXT,
                        detection_method TEXT,
                        false_positive BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_patterns_type ON behavioral_patterns(pattern_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_type ON threat_predictions(threat_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON threat_events(timestamp)')
                
                conn.commit()
                self.logger.info("Predictive threat database initialized")
                
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
    
    def init_ml_models(self):
        """Initialize machine learning models for threat prediction"""
        try:
            # Simple behavioral pattern recognition models
            self.learning_models = {
                'file_behavior': {
                    'weights': np.random.random(10),
                    'bias': 0.0,
                    'learning_rate': 0.01,
                    'samples': 0
                },
                'process_behavior': {
                    'weights': np.random.random(8),
                    'bias': 0.0,
                    'learning_rate': 0.01,
                    'samples': 0
                }
            }
            
            self.logger.info("ML models initialized for predictive analysis")
            
        except Exception as e:
            self.logger.error(f"ML model initialization failed: {e}")
    
    def start(self):
        """Start predictive analysis engine"""
        try:
            if self.running:
                return
            
            self.running = True
            self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
            self.analysis_thread.start()
            
            self.logger.info("Predictive threat analysis started")
            
        except Exception as e:
            self.logger.error(f"Failed to start predictive analysis: {e}")
    
    def stop(self):
        """Stop predictive analysis engine"""
        try:
            self.running = False
            if self.analysis_thread:
                self.analysis_thread.join(timeout=5)
            
            self.logger.info("Predictive threat analysis stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping predictive analysis: {e}")
    
    def _analysis_loop(self):
        """Main analysis loop for continuous threat prediction"""
        try:
            while self.running:
                try:
                    # Analyze behavioral patterns
                    self.analyze_behavioral_patterns()
                    
                    # Generate threat predictions
                    self.generate_threat_predictions()
                    
                    # Clean old data
                    self.cleanup_old_data()
                    
                    # Sleep for analysis interval (5 minutes)
                    time.sleep(300)
                    
                except Exception as e:
                    self.logger.error(f"Analysis loop error: {e}")
                    time.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"Analysis loop failed: {e}")
    
    def analyze_behavioral_patterns(self):
        """Analyze behavioral patterns from threat events"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get recent threat events for pattern analysis
                cursor.execute('''
                    SELECT * FROM threat_events 
                    WHERE timestamp > datetime('now', '-24 hours')
                    ORDER BY timestamp DESC
                ''')
                
                events = cursor.fetchall()
                
                # Analyze patterns by event type
                pattern_analysis = {}
                
                for event in events:
                    event_type = event[1]
                    behavioral_indicators = json.loads(event[6] or '[]')
                    
                    if event_type not in pattern_analysis:
                        pattern_analysis[event_type] = {
                            'count': 0,
                            'indicators': {},
                            'risk_scores': []
                        }
                    
                    pattern_analysis[event_type]['count'] += 1
                    pattern_analysis[event_type]['risk_scores'].append(event[2])
                    
                    # Count behavioral indicators
                    for indicator in behavioral_indicators:
                        if indicator not in pattern_analysis[event_type]['indicators']:
                            pattern_analysis[event_type]['indicators'][indicator] = 0
                        pattern_analysis[event_type]['indicators'][indicator] += 1
                
                # Create or update behavioral patterns
                for event_type, analysis in pattern_analysis.items():
                    if analysis['count'] >= 3:  # Minimum events for pattern
                        pattern = self.create_behavioral_pattern(event_type, analysis)
                        if pattern:
                            self.save_behavioral_pattern(pattern)
                
                self.logger.debug(f"Analyzed {len(pattern_analysis)} behavioral patterns")
                
        except Exception as e:
            self.logger.error(f"Behavioral pattern analysis failed: {e}")
    
    def create_behavioral_pattern(self, event_type: str, analysis: Dict) -> Optional[BehavioralPattern]:
        """Create behavioral pattern from analysis data"""
        try:
            pattern_id = hashlib.md5(f"{event_type}_{datetime.now().isoformat()}".encode()).hexdigest()
            
            # Calculate risk score
            avg_risk = np.mean(analysis['risk_scores']) if analysis['risk_scores'] else 0.0
            frequency_factor = min(analysis['count'] / 10.0, 1.0)
            risk_score = (avg_risk + frequency_factor) / 2.0
            
            # Get top indicators
            top_indicators = sorted(
                analysis['indicators'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]
            
            indicators = [indicator for indicator, count in top_indicators]
            related_threats = self.get_related_threats(event_type, indicators)
            
            pattern = BehavioralPattern(
                pattern_id=pattern_id,
                pattern_type=event_type,
                frequency=analysis['count'],
                last_seen=datetime.now(),
                risk_score=risk_score,
                indicators=indicators,
                related_threats=related_threats
            )
            
            return pattern
            
        except Exception as e:
            self.logger.error(f"Pattern creation failed: {e}")
            return None
    
    def get_related_threats(self, event_type: str, indicators: List[str]) -> List[str]:
        """Get related threats based on intelligence data"""
        try:
            related_threats = []
            
            if self.intelligence_engine:
                # Query intelligence engine for related threats
                for indicator in indicators:
                    threats = self.intelligence_engine.query_threat_by_indicator(indicator)
                    if threats:
                        related_threats.extend([t.get('threat_name', '') for t in threats])
            
            return list(set(related_threats))[:5]
            
        except Exception as e:
            self.logger.debug(f"Related threat lookup failed: {e}")
            return []
    
    def save_behavioral_pattern(self, pattern: BehavioralPattern):
        """Save behavioral pattern to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO behavioral_patterns 
                    (pattern_id, pattern_type, frequency, last_seen, risk_score, 
                     indicators, related_threats, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.pattern_id,
                    pattern.pattern_type,
                    pattern.frequency,
                    pattern.last_seen,
                    pattern.risk_score,
                    json.dumps(pattern.indicators),
                    json.dumps(pattern.related_threats),
                    datetime.now()
                ))
                
                conn.commit()
                self.behavioral_patterns[pattern.pattern_id] = pattern
                
        except Exception as e:
            self.logger.error(f"Failed to save behavioral pattern: {e}")
    
    def generate_threat_predictions(self):
        """Generate threat predictions based on patterns and intelligence"""
        try:
            patterns = self.get_active_patterns()
            threat_types = ['malware', 'ransomware', 'trojan', 'spyware', 'adware', 'rootkit']
            
            for threat_type in threat_types:
                prediction = self.predict_threat_probability(threat_type, patterns)
                if prediction and prediction.probability > 0.3:
                    self.save_threat_prediction(prediction)
            
            self.logger.debug("Generated threat predictions")
            
        except Exception as e:
            self.logger.error(f"Threat prediction generation failed: {e}")
    
    def predict_threat_probability(self, threat_type: str, patterns: List[BehavioralPattern]) -> Optional[ThreatPrediction]:
        """Predict probability of specific threat type"""
        try:
            relevant_patterns = [p for p in patterns if threat_type in p.related_threats or threat_type in p.pattern_type.lower()]
            
            if not relevant_patterns:
                return None
            
            # Calculate probability
            pattern_scores = [p.risk_score * (p.frequency / 10.0) for p in relevant_patterns]
            base_probability = min(np.mean(pattern_scores), 1.0) if pattern_scores else 0.0
            
            # Enhance with intelligence data
            intelligence_factor = self.get_intelligence_factor(threat_type)
            final_probability = (base_probability * 0.7) + (intelligence_factor * 0.3)
            
            # Determine confidence and trend
            confidence = self.calculate_confidence(relevant_patterns, intelligence_factor)
            trend = self.analyze_threat_trend(threat_type)
            
            # Generate risk factors and recommendations
            risk_factors = self.generate_risk_factors(threat_type, relevant_patterns)
            recommendations = self.generate_recommendations(threat_type, final_probability, trend)
            
            prediction = ThreatPrediction(
                threat_type=threat_type,
                probability=final_probability,
                confidence=confidence,
                trend=trend,
                time_window=self.prediction_window,
                risk_factors=risk_factors,
                recommended_actions=recommendations,
                prediction_timestamp=datetime.now(),
                metadata={
                    'pattern_count': len(relevant_patterns),
                    'intelligence_factor': intelligence_factor,
                    'base_probability': base_probability
                }
            )
            
            return prediction
            
        except Exception as e:
            self.logger.error(f"Threat probability prediction failed: {e}")
            return None
    
    def get_intelligence_factor(self, threat_type: str) -> float:
        """Get intelligence factor for threat type"""
        try:
            if not self.intelligence_engine:
                return 0.0
            
            # Simple intelligence factor calculation
            return 0.3  # Placeholder
            
        except Exception as e:
            return 0.0
    
    def calculate_confidence(self, patterns: List[BehavioralPattern], intelligence_factor: float) -> PredictionConfidence:
        """Calculate prediction confidence level"""
        try:
            pattern_quality = len(patterns) / 10.0
            data_quality = (sum(p.frequency for p in patterns) / len(patterns)) / 20.0 if patterns else 0.0
            
            overall_quality = (pattern_quality + data_quality + intelligence_factor) / 3.0
            
            if overall_quality >= 0.8:
                return PredictionConfidence.VERY_HIGH
            elif overall_quality >= 0.6:
                return PredictionConfidence.HIGH
            elif overall_quality >= 0.4:
                return PredictionConfidence.MEDIUM
            else:
                return PredictionConfidence.LOW
                
        except Exception as e:
            return PredictionConfidence.LOW
    
    def analyze_threat_trend(self, threat_type: str) -> ThreatTrend:
        """Analyze threat trend based on historical data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT DATE(timestamp) as date, COUNT(*) as count
                    FROM threat_events 
                    WHERE event_type LIKE ? AND timestamp > datetime('now', '-7 days')
                    GROUP BY DATE(timestamp)
                    ORDER BY date
                ''', (f'%{threat_type}%',))
                
                daily_counts = cursor.fetchall()
                
                if len(daily_counts) < 3:
                    return ThreatTrend.STABLE
                
                counts = [row[1] for row in daily_counts]
                trend_slope = np.polyfit(range(len(counts)), counts, 1)[0]
                recent_avg = np.mean(counts[-3:])
                
                if trend_slope > 2 and recent_avg > 10:
                    return ThreatTrend.CRITICAL
                elif trend_slope > 1:
                    return ThreatTrend.INCREASING
                elif trend_slope < -1:
                    return ThreatTrend.DECREASING
                elif recent_avg > 5 and len(daily_counts) <= 2:
                    return ThreatTrend.EMERGING
                else:
                    return ThreatTrend.STABLE
                    
        except Exception as e:
            return ThreatTrend.STABLE
    
    def generate_risk_factors(self, threat_type: str, patterns: List[BehavioralPattern]) -> List[str]:
        """Generate risk factors for threat prediction"""
        try:
            risk_factors = []
            
            if patterns:
                high_risk_patterns = [p for p in patterns if p.risk_score > 0.7]
                if high_risk_patterns:
                    risk_factors.append(f"High-risk behavioral patterns detected ({len(high_risk_patterns)})")
                
                frequent_patterns = [p for p in patterns if p.frequency > 10]
                if frequent_patterns:
                    risk_factors.append(f"Frequent suspicious activities ({len(frequent_patterns)} patterns)")
            
            # Threat-specific risk factors
            threat_risks = {
                'ransomware': ['File encryption activities', 'Network communication to C&C servers'],
                'trojan': ['Suspicious network connections', 'Unauthorized system modifications'],
                'spyware': ['Data collection behaviors', 'Keylogging activities'],
                'malware': ['Code injection attempts', 'Anti-analysis techniques'],
                'rootkit': ['System-level modifications', 'Stealth behaviors'],
                'adware': ['Unwanted advertisements', 'Browser modifications']
            }
            
            if threat_type in threat_risks:
                risk_factors.extend(threat_risks[threat_type])
            
            return risk_factors[:5]
            
        except Exception as e:
            return []
    
    def generate_recommendations(self, threat_type: str, probability: float, trend: ThreatTrend) -> List[str]:
        """Generate actionable recommendations"""
        try:
            recommendations = []
            
            if probability > 0.8:
                recommendations.extend([
                    "Increase real-time monitoring frequency",
                    "Enable advanced threat detection modes",
                    "Consider system isolation if threats detected"
                ])
            elif probability > 0.6:
                recommendations.extend([
                    "Enhance monitoring for suspicious activities",
                    "Update threat signatures and definitions"
                ])
            elif probability > 0.4:
                recommendations.extend([
                    "Monitor system for unusual behaviors",
                    "Ensure antivirus definitions are current"
                ])
            
            if trend == ThreatTrend.CRITICAL:
                recommendations.extend([
                    "Immediate security assessment required",
                    "Consider emergency response procedures"
                ])
            elif trend == ThreatTrend.INCREASING:
                recommendations.extend([
                    "Increase scan frequency",
                    "Review recent system changes"
                ])
            
            return list(set(recommendations))[:7]
            
        except Exception as e:
            return []
    
    def save_threat_prediction(self, prediction: ThreatPrediction):
        """Save threat prediction to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                prediction_id = hashlib.md5(
                    f"{prediction.threat_type}_{prediction.prediction_timestamp.isoformat()}".encode()
                ).hexdigest()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_predictions 
                    (prediction_id, threat_type, probability, confidence, trend, 
                     time_window, risk_factors, recommended_actions, prediction_timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    prediction_id,
                    prediction.threat_type,
                    prediction.probability,
                    prediction.confidence.value,
                    prediction.trend.value,
                    prediction.time_window,
                    json.dumps(prediction.risk_factors),
                    json.dumps(prediction.recommended_actions),
                    prediction.prediction_timestamp,
                    json.dumps(prediction.metadata)
                ))
                
                conn.commit()
                self.threat_predictions[prediction_id] = prediction
                
        except Exception as e:
            self.logger.error(f"Failed to save threat prediction: {e}")
    
    def get_active_patterns(self) -> List[BehavioralPattern]:
        """Get active behavioral patterns"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM behavioral_patterns 
                    WHERE last_seen > datetime('now', '-48 hours')
                    ORDER BY risk_score DESC
                ''')
                
                patterns = []
                for row in cursor.fetchall():
                    pattern = BehavioralPattern(
                        pattern_id=row[0],
                        pattern_type=row[1],
                        frequency=row[2],
                        last_seen=datetime.fromisoformat(row[3]),
                        risk_score=row[4],
                        indicators=json.loads(row[5] or '[]'),
                        related_threats=json.loads(row[6] or '[]')
                    )
                    patterns.append(pattern)
                
                return patterns
                
        except Exception as e:
            self.logger.error(f"Failed to get active patterns: {e}")
            return []
    
    def get_current_predictions(self) -> List[ThreatPrediction]:
        """Get current threat predictions"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM threat_predictions 
                    WHERE prediction_timestamp > datetime('now', '-24 hours')
                    ORDER BY probability DESC
                ''')
                
                predictions = []
                for row in cursor.fetchall():
                    prediction = ThreatPrediction(
                        threat_type=row[1],
                        probability=row[2],
                        confidence=PredictionConfidence(row[3]),
                        trend=ThreatTrend(row[4]),
                        time_window=row[5],
                        risk_factors=json.loads(row[6] or '[]'),
                        recommended_actions=json.loads(row[7] or '[]'),
                        prediction_timestamp=datetime.fromisoformat(row[8]),
                        metadata=json.loads(row[9] or '{}')
                    )
                    predictions.append(prediction)
                
                return predictions
                
        except Exception as e:
            self.logger.error(f"Failed to get current predictions: {e}")
            return []
    
    def record_threat_event(self, event_data: Dict[str, Any]):
        """Record threat event for learning"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                event_id = hashlib.md5(
                    f"{event_data.get('file_path', '')}_{datetime.now().isoformat()}".encode()
                ).hexdigest()
                
                cursor.execute('''
                    INSERT INTO threat_events 
                    (event_id, event_type, severity, timestamp, file_path, process_name,
                     behavioral_indicators, detection_method)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_id,
                    event_data.get('event_type', 'unknown'),
                    event_data.get('severity', 0.5),
                    datetime.now(),
                    event_data.get('file_path', ''),
                    event_data.get('process_name', ''),
                    json.dumps(event_data.get('behavioral_indicators', [])),
                    event_data.get('detection_method', 'unknown')
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to record threat event: {e}")
    
    def cleanup_old_data(self):
        """Clean up old data from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Remove old patterns (older than 7 days)
                cursor.execute('''
                    DELETE FROM behavioral_patterns 
                    WHERE last_seen < datetime('now', '-7 days')
                ''')
                
                # Remove old predictions (older than 48 hours)
                cursor.execute('''
                    DELETE FROM threat_predictions 
                    WHERE prediction_timestamp < datetime('now', '-48 hours')
                ''')
                
                # Remove old events (older than 30 days)
                cursor.execute('''
                    DELETE FROM threat_events 
                    WHERE timestamp < datetime('now', '-30 days')
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Data cleanup failed: {e}")
    
    def get_prediction_statistics(self) -> Dict[str, Any]:
        """Get prediction engine statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get pattern count
                cursor.execute('SELECT COUNT(*) FROM behavioral_patterns')
                pattern_count = cursor.fetchone()[0]
                
                # Get prediction count
                cursor.execute('SELECT COUNT(*) FROM threat_predictions WHERE prediction_timestamp > datetime("now", "-24 hours")')
                prediction_count = cursor.fetchone()[0]
                
                # Get event count
                cursor.execute('SELECT COUNT(*) FROM threat_events WHERE timestamp > datetime("now", "-24 hours")')
                event_count = cursor.fetchone()[0]
                
                # Get high-risk predictions
                cursor.execute('SELECT COUNT(*) FROM threat_predictions WHERE probability > 0.7 AND prediction_timestamp > datetime("now", "-24 hours")')
                high_risk_count = cursor.fetchone()[0]
                
                return {
                    'active_patterns': pattern_count,
                    'recent_predictions': prediction_count,
                    'recent_events': event_count,
                    'high_risk_predictions': high_risk_count,
                    'engine_status': 'running' if self.running else 'stopped',
                    'last_analysis': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
