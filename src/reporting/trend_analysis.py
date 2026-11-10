"""
Trend Analysis and Forecasting System
Provides advanced trend analysis, forecasting, and predictive analytics for AI Antivirus.
"""

import sqlite3
import json
import logging
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import os

try:
    from sklearn.linear_model import LinearRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import mean_absolute_error, mean_squared_error
    from sklearn.ensemble import RandomForestRegressor
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    LinearRegression = None
    StandardScaler = None
    RandomForestRegressor = None

@dataclass
class TrendPoint:
    """Individual trend data point"""
    timestamp: str
    value: float
    metric_name: str
    category: str

@dataclass
class TrendAnalysis:
    """Trend analysis result"""
    metric_name: str
    period_days: int
    trend_direction: str  # 'increasing', 'decreasing', 'stable'
    trend_strength: float  # 0-1, how strong the trend is
    slope: float
    r_squared: float
    data_points: int
    start_value: float
    end_value: float
    percentage_change: float

@dataclass
class ForecastResult:
    """Forecasting result"""
    metric_name: str
    forecast_horizon_days: int
    predicted_values: List[float]
    confidence_intervals: List[Tuple[float, float]]
    model_accuracy: float
    forecast_dates: List[str]
    model_type: str

@dataclass
class AnomalyDetection:
    """Anomaly detection result"""
    metric_name: str
    timestamp: str
    value: float
    expected_value: float
    deviation_score: float
    is_anomaly: bool
    anomaly_type: str  # 'spike', 'drop', 'drift'

class TrendAnalysisEngine:
    """Advanced Trend Analysis and Forecasting Engine"""
    
    def __init__(self, db_path: str = None):
        """Initialize Trend Analysis Engine"""
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.reporting.trend_analysis')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Database setup
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'trend_analysis.db')
        
        self.db_path = db_path
        self.init_database()
        
        # Analysis parameters
        self.min_data_points = 7  # Minimum points for trend analysis
        self.anomaly_threshold = 2.0  # Standard deviations for anomaly detection
        
    def init_database(self):
        """Initialize trend analysis database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Trend analyses table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS trend_analyses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT NOT NULL,
                        period_days INTEGER NOT NULL,
                        trend_direction TEXT NOT NULL,
                        trend_strength REAL NOT NULL,
                        slope REAL NOT NULL,
                        r_squared REAL NOT NULL,
                        data_points INTEGER NOT NULL,
                        start_value REAL NOT NULL,
                        end_value REAL NOT NULL,
                        percentage_change REAL NOT NULL,
                        analysis_date DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Forecasts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS forecasts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT NOT NULL,
                        forecast_horizon_days INTEGER NOT NULL,
                        predicted_values TEXT NOT NULL,
                        confidence_intervals TEXT NOT NULL,
                        model_accuracy REAL NOT NULL,
                        forecast_dates TEXT NOT NULL,
                        model_type TEXT NOT NULL,
                        created_date DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Anomalies table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS anomalies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT NOT NULL,
                        timestamp DATETIME NOT NULL,
                        value REAL NOT NULL,
                        expected_value REAL NOT NULL,
                        deviation_score REAL NOT NULL,
                        anomaly_type TEXT NOT NULL,
                        detected_date DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Trend patterns table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS trend_patterns (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pattern_name TEXT NOT NULL,
                        pattern_type TEXT NOT NULL,
                        metrics_involved TEXT NOT NULL,
                        pattern_strength REAL NOT NULL,
                        pattern_data TEXT NOT NULL,
                        identified_date DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.commit()
                self.logger.info("Trend analysis database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize trend analysis database: {e}")
            raise
    
    def analyze_metric_trend(self, metric_name: str, period_days: int = 30) -> Optional[TrendAnalysis]:
        """Analyze trend for a specific metric"""
        try:
            # Get data from analytics database
            analytics_db = os.path.join(os.path.dirname(self.db_path), 'analytics.db')
            
            if not os.path.exists(analytics_db):
                self.logger.warning("Analytics database not found")
                return None
            
            with sqlite3.connect(analytics_db) as conn:
                cursor = conn.cursor()
                
                start_date = datetime.now() - timedelta(days=period_days)
                
                cursor.execute('''
                    SELECT timestamp, value FROM metrics 
                    WHERE name = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                ''', (metric_name, start_date))
                
                data = cursor.fetchall()
                
                if len(data) < self.min_data_points:
                    self.logger.warning(f"Insufficient data points for {metric_name}: {len(data)}")
                    return None
                
                # Convert to numpy arrays
                timestamps = [datetime.fromisoformat(row[0].replace('Z', '+00:00')) if 'Z' in row[0] else datetime.fromisoformat(row[0]) for row in data]
                values = np.array([row[1] for row in data])
                
                # Create time series (days from start)
                time_series = np.array([(ts - timestamps[0]).total_seconds() / 86400 for ts in timestamps])
                
                # Perform linear regression
                if SKLEARN_AVAILABLE:
                    model = LinearRegression()
                    X = time_series.reshape(-1, 1)
                    model.fit(X, values)
                    
                    slope = model.coef_[0]
                    r_squared = model.score(X, values)
                    
                    # Predict trend
                    y_pred = model.predict(X)
                    trend_strength = abs(r_squared)
                    
                else:
                    # Simple linear regression without sklearn
                    slope, intercept, r_squared = self._simple_linear_regression(time_series, values)
                    trend_strength = abs(r_squared)
                
                # Determine trend direction
                if abs(slope) < 0.01:  # Very small slope
                    trend_direction = 'stable'
                elif slope > 0:
                    trend_direction = 'increasing'
                else:
                    trend_direction = 'decreasing'
                
                # Calculate percentage change
                start_value = values[0]
                end_value = values[-1]
                percentage_change = ((end_value - start_value) / start_value * 100) if start_value != 0 else 0
                
                analysis = TrendAnalysis(
                    metric_name=metric_name,
                    period_days=period_days,
                    trend_direction=trend_direction,
                    trend_strength=trend_strength,
                    slope=slope,
                    r_squared=r_squared,
                    data_points=len(data),
                    start_value=start_value,
                    end_value=end_value,
                    percentage_change=percentage_change
                )
                
                # Save analysis
                self._save_trend_analysis(analysis)
                
                return analysis
                
        except Exception as e:
            self.logger.error(f"Failed to analyze trend for {metric_name}: {e}")
            return None
    
    def _simple_linear_regression(self, x: np.ndarray, y: np.ndarray) -> Tuple[float, float, float]:
        """Simple linear regression implementation"""
        n = len(x)
        x_mean = np.mean(x)
        y_mean = np.mean(y)
        
        # Calculate slope
        numerator = np.sum((x - x_mean) * (y - y_mean))
        denominator = np.sum((x - x_mean) ** 2)
        slope = numerator / denominator if denominator != 0 else 0
        
        # Calculate intercept
        intercept = y_mean - slope * x_mean
        
        # Calculate R-squared
        y_pred = slope * x + intercept
        ss_res = np.sum((y - y_pred) ** 2)
        ss_tot = np.sum((y - y_mean) ** 2)
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
        
        return slope, intercept, r_squared
    
    def _save_trend_analysis(self, analysis: TrendAnalysis):
        """Save trend analysis to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO trend_analyses 
                    (metric_name, period_days, trend_direction, trend_strength, slope,
                     r_squared, data_points, start_value, end_value, percentage_change)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (analysis.metric_name, analysis.period_days, analysis.trend_direction,
                      analysis.trend_strength, analysis.slope, analysis.r_squared,
                      analysis.data_points, analysis.start_value, analysis.end_value,
                      analysis.percentage_change))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save trend analysis: {e}")
    
    def forecast_metric(self, metric_name: str, forecast_days: int = 7, 
                       training_days: int = 30) -> Optional[ForecastResult]:
        """Forecast future values for a metric"""
        try:
            if not SKLEARN_AVAILABLE:
                self.logger.warning("Scikit-learn not available, using simple linear forecast")
                return self._simple_forecast(metric_name, forecast_days, training_days)
            
            # Get training data
            analytics_db = os.path.join(os.path.dirname(self.db_path), 'analytics.db')
            
            if not os.path.exists(analytics_db):
                return None
            
            with sqlite3.connect(analytics_db) as conn:
                cursor = conn.cursor()
                
                start_date = datetime.now() - timedelta(days=training_days)
                
                cursor.execute('''
                    SELECT timestamp, value FROM metrics 
                    WHERE name = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                ''', (metric_name, start_date))
                
                data = cursor.fetchall()
                
                if len(data) < self.min_data_points:
                    return None
                
                # Prepare data
                timestamps = [datetime.fromisoformat(row[0].replace('Z', '+00:00')) if 'Z' in row[0] else datetime.fromisoformat(row[0]) for row in data]
                values = np.array([row[1] for row in data])
                
                # Create features (time-based)
                time_features = np.array([(ts - timestamps[0]).total_seconds() / 86400 for ts in timestamps])
                
                # Add additional features
                X = self._create_features(time_features, values)
                y = values
                
                # Train model
                model = RandomForestRegressor(n_estimators=100, random_state=42)
                model.fit(X, y)
                
                # Calculate model accuracy on training data
                y_pred_train = model.predict(X)
                accuracy = 1 - mean_absolute_error(y, y_pred_train) / (np.max(y) - np.min(y))
                accuracy = max(0, min(1, accuracy))  # Clamp between 0 and 1
                
                # Generate forecasts
                last_time = time_features[-1]
                forecast_times = [last_time + i + 1 for i in range(forecast_days)]
                forecast_dates = [(timestamps[-1] + timedelta(days=i+1)).isoformat() for i in range(forecast_days)]
                
                # Create forecast features
                forecast_X = self._create_forecast_features(forecast_times, values)
                
                # Make predictions
                predictions = model.predict(forecast_X)
                
                # Calculate confidence intervals (simplified)
                std_error = np.std(y - y_pred_train)
                confidence_intervals = [(pred - 1.96 * std_error, pred + 1.96 * std_error) 
                                      for pred in predictions]
                
                forecast = ForecastResult(
                    metric_name=metric_name,
                    forecast_horizon_days=forecast_days,
                    predicted_values=predictions.tolist(),
                    confidence_intervals=confidence_intervals,
                    model_accuracy=accuracy,
                    forecast_dates=forecast_dates,
                    model_type='RandomForest'
                )
                
                # Save forecast
                self._save_forecast(forecast)
                
                return forecast
                
        except Exception as e:
            self.logger.error(f"Failed to forecast {metric_name}: {e}")
            return None
    
    def _create_features(self, time_features: np.ndarray, values: np.ndarray) -> np.ndarray:
        """Create feature matrix for ML models"""
        features = []
        
        # Time-based features
        features.append(time_features)
        
        # Lagged features
        if len(values) > 1:
            lag1 = np.concatenate([[values[0]], values[:-1]])
            features.append(lag1)
        
        if len(values) > 2:
            lag2 = np.concatenate([[values[0], values[0]], values[:-2]])
            features.append(lag2)
        
        # Moving averages
        if len(values) >= 3:
            ma3 = np.convolve(values, np.ones(3)/3, mode='same')
            features.append(ma3)
        
        # Trend features
        if len(values) >= 5:
            trend = np.gradient(values)
            features.append(trend)
        
        return np.column_stack(features)
    
    def _create_forecast_features(self, forecast_times: List[float], 
                                historical_values: np.ndarray) -> np.ndarray:
        """Create features for forecasting"""
        features = []
        
        # Time features
        features.append(forecast_times)
        
        # Use last known values for lagged features
        last_values = historical_values[-2:] if len(historical_values) >= 2 else [historical_values[-1], historical_values[-1]]
        
        # Extend lagged features
        lag1_values = [last_values[-1]] * len(forecast_times)
        features.append(lag1_values)
        
        if len(last_values) >= 2:
            lag2_values = [last_values[-2]] * len(forecast_times)
            features.append(lag2_values)
        
        # Moving average (use recent average)
        if len(historical_values) >= 3:
            recent_avg = np.mean(historical_values[-3:])
            ma_values = [recent_avg] * len(forecast_times)
            features.append(ma_values)
        
        # Trend (use recent trend)
        if len(historical_values) >= 5:
            recent_trend = np.mean(np.gradient(historical_values[-5:]))
            trend_values = [recent_trend] * len(forecast_times)
            features.append(trend_values)
        
        return np.column_stack(features)
    
    def _simple_forecast(self, metric_name: str, forecast_days: int, 
                        training_days: int) -> Optional[ForecastResult]:
        """Simple linear forecast without sklearn"""
        try:
            # Get trend analysis
            trend = self.analyze_metric_trend(metric_name, training_days)
            if not trend:
                return None
            
            # Generate forecasts using linear extrapolation
            predictions = []
            forecast_dates = []
            
            for i in range(forecast_days):
                future_time = trend.period_days + i + 1
                predicted_value = trend.end_value + (trend.slope * (i + 1))
                predictions.append(predicted_value)
                
                forecast_date = (datetime.now() + timedelta(days=i+1)).isoformat()
                forecast_dates.append(forecast_date)
            
            # Simple confidence intervals
            std_estimate = abs(trend.end_value - trend.start_value) * 0.1
            confidence_intervals = [(pred - std_estimate, pred + std_estimate) 
                                  for pred in predictions]
            
            forecast = ForecastResult(
                metric_name=metric_name,
                forecast_horizon_days=forecast_days,
                predicted_values=predictions,
                confidence_intervals=confidence_intervals,
                model_accuracy=trend.r_squared,
                forecast_dates=forecast_dates,
                model_type='Linear'
            )
            
            self._save_forecast(forecast)
            return forecast
            
        except Exception as e:
            self.logger.error(f"Failed to create simple forecast: {e}")
            return None
    
    def _save_forecast(self, forecast: ForecastResult):
        """Save forecast to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO forecasts 
                    (metric_name, forecast_horizon_days, predicted_values, confidence_intervals,
                     model_accuracy, forecast_dates, model_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (forecast.metric_name, forecast.forecast_horizon_days,
                      json.dumps(forecast.predicted_values), json.dumps(forecast.confidence_intervals),
                      forecast.model_accuracy, json.dumps(forecast.forecast_dates),
                      forecast.model_type))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save forecast: {e}")
    
    def detect_anomalies(self, metric_name: str, lookback_days: int = 30) -> List[AnomalyDetection]:
        """Detect anomalies in metric data"""
        try:
            anomalies = []
            
            # Get recent data
            analytics_db = os.path.join(os.path.dirname(self.db_path), 'analytics.db')
            
            if not os.path.exists(analytics_db):
                return anomalies
            
            with sqlite3.connect(analytics_db) as conn:
                cursor = conn.cursor()
                
                start_date = datetime.now() - timedelta(days=lookback_days)
                
                cursor.execute('''
                    SELECT timestamp, value FROM metrics 
                    WHERE name = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                ''', (metric_name, start_date))
                
                data = cursor.fetchall()
                
                if len(data) < self.min_data_points:
                    return anomalies
                
                values = np.array([row[1] for row in data])
                timestamps = [row[0] for row in data]
                
                # Calculate rolling statistics
                window_size = min(7, len(values) // 2)
                
                for i in range(window_size, len(values)):
                    window_data = values[i-window_size:i]
                    current_value = values[i]
                    
                    # Calculate expected value and deviation
                    expected_value = np.mean(window_data)
                    std_dev = np.std(window_data)
                    
                    if std_dev > 0:
                        deviation_score = abs(current_value - expected_value) / std_dev
                        
                        if deviation_score > self.anomaly_threshold:
                            # Determine anomaly type
                            if current_value > expected_value + (self.anomaly_threshold * std_dev):
                                anomaly_type = 'spike'
                            elif current_value < expected_value - (self.anomaly_threshold * std_dev):
                                anomaly_type = 'drop'
                            else:
                                anomaly_type = 'drift'
                            
                            anomaly = AnomalyDetection(
                                metric_name=metric_name,
                                timestamp=timestamps[i],
                                value=current_value,
                                expected_value=expected_value,
                                deviation_score=deviation_score,
                                is_anomaly=True,
                                anomaly_type=anomaly_type
                            )
                            
                            anomalies.append(anomaly)
                            
                            # Save anomaly
                            self._save_anomaly(anomaly)
                
                return anomalies
                
        except Exception as e:
            self.logger.error(f"Failed to detect anomalies for {metric_name}: {e}")
            return []
    
    def _save_anomaly(self, anomaly: AnomalyDetection):
        """Save anomaly to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO anomalies 
                    (metric_name, timestamp, value, expected_value, deviation_score, anomaly_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (anomaly.metric_name, anomaly.timestamp, anomaly.value,
                      anomaly.expected_value, anomaly.deviation_score, anomaly.anomaly_type))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save anomaly: {e}")
    
    def generate_trend_report(self, metrics: List[str] = None, period_days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive trend analysis report"""
        try:
            if metrics is None:
                metrics = ['threat_detection_rate', 'false_positive_rate', 'system_uptime', 'avg_scan_time']
            
            report = {
                'generated_at': datetime.now().isoformat(),
                'period_days': period_days,
                'trend_analyses': {},
                'forecasts': {},
                'anomalies': {},
                'summary': {
                    'metrics_analyzed': len(metrics),
                    'trends_detected': 0,
                    'anomalies_found': 0,
                    'forecasts_generated': 0
                }
            }
            
            for metric in metrics:
                # Trend analysis
                trend = self.analyze_metric_trend(metric, period_days)
                if trend:
                    report['trend_analyses'][metric] = asdict(trend)
                    if trend.trend_direction != 'stable':
                        report['summary']['trends_detected'] += 1
                
                # Forecasting
                forecast = self.forecast_metric(metric, 7, period_days)
                if forecast:
                    report['forecasts'][metric] = asdict(forecast)
                    report['summary']['forecasts_generated'] += 1
                
                # Anomaly detection
                anomalies = self.detect_anomalies(metric, period_days)
                if anomalies:
                    report['anomalies'][metric] = [asdict(a) for a in anomalies]
                    report['summary']['anomalies_found'] += len(anomalies)
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate trend report: {e}")
            return {}
    
    def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old trend analysis data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=days_to_keep)
                
                tables = ['trend_analyses', 'forecasts', 'anomalies', 'trend_patterns']
                
                for table in tables:
                    if table == 'trend_analyses':
                        cursor.execute(f'DELETE FROM {table} WHERE analysis_date < ?', (cutoff_date,))
                    elif table == 'forecasts':
                        cursor.execute(f'DELETE FROM {table} WHERE created_date < ?', (cutoff_date,))
                    elif table == 'anomalies':
                        cursor.execute(f'DELETE FROM {table} WHERE detected_date < ?', (cutoff_date,))
                    else:
                        cursor.execute(f'DELETE FROM {table} WHERE identified_date < ?', (cutoff_date,))
                
                conn.commit()
                self.logger.info(f"Cleaned up trend analysis data older than {days_to_keep} days")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")

if __name__ == "__main__":
    # Test trend analysis
    engine = TrendAnalysisEngine()
    
    # Generate trend report
    report = engine.generate_trend_report()
    print("Trend Analysis Report:")
    print(f"  Metrics analyzed: {report.get('summary', {}).get('metrics_analyzed', 0)}")
    print(f"  Trends detected: {report.get('summary', {}).get('trends_detected', 0)}")
    print(f"  Anomalies found: {report.get('summary', {}).get('anomalies_found', 0)}")
    print(f"  Forecasts generated: {report.get('summary', {}).get('forecasts_generated', 0)}")
