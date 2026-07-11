from app import create_app
from flask import url_for

app = create_app()
with app.app_context():
    client = app.test_client()
    
    # 1. Test Dashboard
    print("Testing /dashboard...")
    resp = client.get('/dashboard')
    print(f"Dashboard status code: {resp.status_code}")
    if resp.status_code != 200:
        print(resp.data.decode('utf-8'))
        
    # 2. Test Scan History
    print("Testing /history...")
    resp = client.get('/history')
    print(f"History status code: {resp.status_code}")
    if resp.status_code != 200:
        print(resp.data.decode('utf-8'))
        
    # 3. Test Scan History filters
    print("Testing /history filters...")
    resp = client.get('/history?query=google&grade=D')
    print(f"History filter status code: {resp.status_code}")
    if resp.status_code != 200:
        print(resp.data.decode('utf-8'))
