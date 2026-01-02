from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import pymysql
import bcrypt
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import logging

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

jwt = JWTManager(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    try:
        return pymysql.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME'),
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        logger.error(f"DB Connection failed: {str(e)}")
        raise

def log_audit(user_id, action, resource_type, resource_id, resource_name, details="", ip=""):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO audit_logs 
                (team_member_id, action, resource_type, resource_id, resource_name, details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, action, resource_type, resource_id, resource_name, details, ip or request.remote_addr))
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Audit logging failed: {str(e)}")

@app.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'DevOps Vault API', 'version': '1.0', 'status': 'running'}), 200

@app.route('/api/health', methods=['GET'])
def health():
    try:
        conn = get_db_connection()
        conn.close()
        return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, username, password_hash, role FROM team_members WHERE username = %s AND is_active = TRUE",
                (username,)
            )
            user = cursor.fetchone()
        conn.close()
            
        if not user:
            log_audit(None, 'login_failed', 'user', None, username, "User not found")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            log_audit(None, 'login_failed', 'user', None, username, "Wrong password")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        access_token = create_access_token(
            identity={'id': user['id'], 'username': user['username'], 'role': user['role']}
        )
        
        log_audit(user['id'], 'login_success', 'user', user['id'], username, "Successful login")
        return jsonify({'access_token': access_token, 'username': user['username'], 'role': user['role']}), 200
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/credentials', methods=['GET'])
@jwt_required()
def get_credentials():
    current_user = get_jwt_identity()
    user_id = current_user['id']
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT DISTINCT c.* FROM credentials c
                LEFT JOIN permissions p ON c.id = p.credential_id
                WHERE p.team_member_id = %s OR c.created_by = %s
                ORDER BY c.created_at DESC
            """, (user_id, user_id))
            credentials = cursor.fetchall()
        conn.close()
        
        for cred in credentials:
            cred['created_at'] = str(cred['created_at'])
            cred['updated_at'] = str(cred['updated_at'])
        
        log_audit(user_id, 'view_list', 'credentials', None, 'All', "Viewed credentials list")
        return jsonify(credentials), 200
    except Exception as e:
        logger.error(f"Error fetching credentials: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/credentials/<int:cred_id>', methods=['GET'])
@jwt_required()
def get_credential(cred_id):
    current_user = get_jwt_identity()
    user_id = current_user['id']
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT c.* FROM credentials c
                LEFT JOIN permissions p ON c.id = p.credential_id
                WHERE c.id = %s AND (p.team_member_id = %s OR c.created_by = %s)
            """, (cred_id, user_id, user_id))
            credential = cursor.fetchone()
        conn.close()
        
        if not credential:
            return jsonify({'error': 'Credential not found or access denied'}), 404
        
        log_audit(user_id, 'view_detail', 'credential', cred_id, credential['name'], "Viewed credential details")
        return jsonify(credential), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/credentials', methods=['POST'])
@jwt_required()
def create_credential():
    current_user = get_jwt_identity()
    user_id = current_user['id']
    data = request.json
    
    required_fields = ['name', 'type', 'username']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO credentials 
                (name, type, username, password, host, port, key_name, category, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data['name'],
                data['type'],
                data.get('username'),
                data.get('password'),
                data.get('host'),
                data.get('port'),
                data.get('key_name'),
                data.get('category', 'Servers'),
                user_id
            ))
            conn.commit()
            cred_id = cursor.lastrowid
            
            cursor.execute("""
                INSERT INTO permissions 
                (team_member_id, credential_id, can_view, can_edit, can_delete)
                VALUES (%s, %s, TRUE, TRUE, TRUE)
            """, (user_id, cred_id))
            conn.commit()
        conn.close()
        
        log_audit(user_id, 'create', 'credential', cred_id, data['name'], "Created new credential")
        return jsonify({'success': True, 'id': cred_id}), 201
    except Exception as e:
        logger.error(f"Error creating credential: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/credentials/<int:cred_id>', methods=['PUT'])
@jwt_required()
def update_credential(cred_id):
    current_user = get_jwt_identity()
    user_id = current_user['id']
    data = request.json
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT created_by, name FROM credentials WHERE id = %s", (cred_id,))
            cred = cursor.fetchone()
        
        if not cred or (cred['created_by'] != user_id and current_user['role'] != 'admin'):
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE credentials 
                SET name=%s, type=%s, username=%s, password=%s, host=%s, port=%s, category=%s
                WHERE id=%s
            """, (
                data.get('name', cred['name']),
                data.get('type'),
                data.get('username'),
                data.get('password'),
                data.get('host'),
                data.get('port'),
                data.get('category'),
                cred_id
            ))
            conn.commit()
        conn.close()
        
        log_audit(user_id, 'update', 'credential', cred_id, cred['name'], "Updated credential")
        return jsonify({'success': True}), 200
    except Exception as e:
        logger.error(f"Error updating credential: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/credentials/<int:cred_id>', methods=['DELETE'])
@jwt_required()
def delete_credential(cred_id):
    current_user = get_jwt_identity()
    user_id = current_user['id']
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT created_by, name FROM credentials WHERE id = %s", (cred_id,))
            cred = cursor.fetchone()
        
        if not cred or (cred['created_by'] != user_id and current_user['role'] != 'admin'):
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM credentials WHERE id = %s", (cred_id,))
            conn.commit()
        conn.close()
        
        log_audit(user_id, 'delete', 'credential', cred_id, cred['name'], "Deleted credential")
        return jsonify({'success': True}), 200
    except Exception as e:
        logger.error(f"Error deleting credential: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    current_user = get_jwt_identity()
    
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT al.*, tm.username FROM audit_logs al
                LEFT JOIN team_members tm ON al.team_member_id = tm.id
                ORDER BY al.timestamp DESC
                LIMIT 1000
            """)
            logs = cursor.fetchall()
        conn.close()
        
        for log in logs:
            log['timestamp'] = str(log['timestamp'])
        
        return jsonify(logs), 200
    except Exception as e:
        logger.error(f"Error fetching audit logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run()
