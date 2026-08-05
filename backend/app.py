import os
import sys
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.ml_model import detector

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), '..', 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='/')
CORS(app)

@app.route('/')
def index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/awareness')
def awareness():
    return send_from_directory(FRONTEND_DIR, 'awareness.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No JSON body received'}), 400
    
    content_type = data.get('type', '').lower()
    content = data.get('content', '').strip()

    if not content:
        return jsonify({'error': 'Content is required'}), 400
    
    if content_type not in ('url','email'):
        return jsonify({'error': 'Invalid content type'}), 400
    
    try:
        if content_type == 'url':
            result = detector.analyze_url(content)
        else:
            result = detector.analyze_email(content)
        return jsonify(result)
    except Exception as e:
        print(f'[ERROR] Analysis failed: {e}')
        return jsonify({'error': 'Analysis failed', 'detail': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify(detector.get_status())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f'[INFO] Starting Phishing Awareness app on port {port}...')
    print(f'[INFO] Open http://localhost:{port} in your browser')
    app.run(host='0.0.0.0', port=port, debug=True)
