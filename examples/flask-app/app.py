from flask import Flask
# or configure to use ZUQA in your application's settings
from flask_cors import CORS
import time

from zuqa.contrib.flask import ZUQA

app = Flask(__name__)

app.config['ZUQA'] = {
    # Set required service name. Allowed characters:
    # a-z, A-Z, 0-9, -, _, and space
    'SERVICE_NAME': 'HELLO',
    # Use if APM Server requires a token
    'SECRET_TOKEN': '',
    # Set custom APM Server URL (default: http://localhost:8200)
    'SERVER_URL': 'http://localhost:8200',
    'METRICS_INTERVAL': '200ms',
}

apm = ZUQA(app)
cors = CORS(app, resources={r"/*": {"origins": "*"}})


@app.route('/hello')
def hello_world():
    time.sleep(1)
    return 'Hello, World!'
