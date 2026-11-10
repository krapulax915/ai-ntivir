"""Test for LogManagementSystem create_scan_log"""
import os
import shutil
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from log_management_system import LogManagementSystem


def run_log_test():
    tmp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'tmp_logs'))
    # Cleanup
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    os.makedirs(tmp_dir, exist_ok=True)

    lms = LogManagementSystem(log_dir=tmp_dir)
    results = {
        'files_scanned': 5,
        'threats_found': 1,
        'scan_duration': 1.23,
        'scan_results': [{'file_path': 'C:/a.exe', 'threat_score': 0.9}]
    }

    path = lms.create_scan_log('enhanced_quick', results)
    print('Created log path:', path)
    assert path is not None
    assert os.path.exists(path)

    # Validate content
    with open(path, 'r', encoding='utf-8') as f:
        data = f.read()
        assert 'enhanced_quick' in data
        assert 'files_scanned' in data

    # get_scan_logs should list the JSON file
    scan_files = lms.get_scan_logs()
    print('Scan files listed:', scan_files)
    assert any(f.endswith('.json') for f in scan_files)

    latest = lms.get_latest_scan_log()
    print('Latest log parsed:', latest)
    assert isinstance(latest, dict)
    assert latest.get('files_scanned') == 5

    # Finalize the log first: this closes the file handlers so the temp
    # directory can be removed on Windows (open handles block rmtree).
    lms.finalize_scan_log(path, {'summary': {'files_scanned': 5, 'threats_found': 0}, 'threats': []})

    # Cleanup
    shutil.rmtree(tmp_dir)
    print('Log management smoke test passed')


if __name__ == '__main__':
    run_log_test()
