# Advanced Heuristic Analysis Module
from ..advanced_heuristic_analysis import AdvancedHeuristicAnalyzer

class HeuristicAnalysisEngine:
    def __init__(self):
        self.analyzer = AdvancedHeuristicAnalyzer()
    
    def analyze_file_heuristics(self, file_path: str) -> dict:
        return self.analyzer.analyze_file(file_path)
    
    def is_suspicious_file(self, file_path: str) -> bool:
        result = self.analyzer.analyze_file(file_path)
        return result.get('is_suspicious', False)
    
    def get_threat_level(self, file_path: str) -> int:
        result = self.analyzer.analyze_file(file_path)
        return result.get('threat_level', 1)
