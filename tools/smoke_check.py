import importlib, sys, os
sys.path.insert(0, r'F:\aintivirus-supermaven-vscode\new-base1-ok\AI_Antivirus')
print('Path prep done')
try:
    from log_management_system import LogManagementSystem
    lms = LogManagementSystem(log_dir=os.path.join(os.getcwd(),'test_logs'))
    p = lms.create_scan_log('smoke_test', {'files_scanned':1,'threats_found':0,'scan_results':[]})
    print('create_scan_log returned:', p)
    ok = lms.log_scan_progress(p, {'progress':10,'current_status':'starting'})
    print('log_scan_progress ok:', ok)
    fin = lms.finalize_scan_log(p, {'files_scanned':1,'threats_found':0,'scan_results':[]})
    print('finalize_scan_log ok:', fin)
except Exception as e:
    print('ERROR in log manager smoke:', e)

try:
    import importlib.util
    spec = importlib.util.spec_from_file_location('ead', r'F:\aintivirus-supermaven-vscode\new-base1-ok\AI_Antivirus\src\detection\enhanced_anomaly_detector.py')
    ead = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ead)
    inst = ead.EnhancedAnomalyDetector(db_path=':memory:')
    print('EnhancedAnomalyDetector instance created:', type(inst))
except Exception as e:
    print('ERROR in anomaly detector import/instantiation:', e)

try:
    spec = importlib.util.spec_from_file_location('scan', r'F:\aintivirus-supermaven-vscode\new-base1-ok\AI_Antivirus\enhanced_quick_scan_system.py')
    scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan)
    print('Enhanced quick scan module imported; class present:', hasattr(scan,'CriticalSystemScanner'))
except Exception as e:
    print('ERROR importing enhanced_quick_scan_system:', e)
