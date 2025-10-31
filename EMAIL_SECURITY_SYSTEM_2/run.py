import os
from app import app
from config import config

if __name__ == '__main__':
    # Get environment
    env = os.getenv('FLASK_ENV', 'development')
    app.config.from_object(config.get(env, config['default']))
    
    # Get port from environment or default to 5000
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    
    print(f"Starting Email Security System...")
    print(f"Environment: {env}")
    print(f"Debug mode: {app.config['DEBUG']}")
    print(f"Server: http://{host}:{port}")
    print(f"Database: {app.config.get('DB_HOST', 'localhost')}")
    
    app.run(
        host=host,
        port=port,
        debug=app.config['DEBUG']
    )