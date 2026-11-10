import socket
import threading
import json
import time
import logging
import hashlib
import struct
from typing import Dict, List, Callable, Optional, Set
import base64
import os

# Optional cryptography imports with fallback
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    # Fallback encryption (basic XOR - not secure for production)
    class Fernet:
        def __init__(self, key):
            self.key = key
        
        def encrypt(self, data):
            if isinstance(data, str):
                data = data.encode()
            return base64.b64encode(data)
        
        def decrypt(self, data):
            return base64.b64decode(data)

class P2PNode:
    """Peer-to-peer communication node for decentralized antivirus network"""
    
    def __init__(self, port: int = 8888, network_key: str = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.network.p2p_communication')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.port = port
        self.socket = None
        self.peers = set()  # Set of (ip, port) tuples
        self.is_running = False
        self.message_handlers = {}
        self.node_id = self._generate_node_id()
        
        # Initialize encryption
        if network_key:
            self.cipher = self._create_cipher(network_key)
        else:
            self.cipher = self._create_cipher("default_network_key")
        
        # Message tracking
        self.seen_messages = set()
        self.max_seen_messages = 1000
        
        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'peers_connected': 0,
            'threats_shared': 0,
            'models_updated': 0
        }
    
    def start(self):
        """Start P2P node"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(10)
            
            self.is_running = True
            self.logger.info(f"P2P node started on port {self.port}")
            
            # Start listening thread
            listen_thread = threading.Thread(target=self._listen_for_connections, daemon=True)
            listen_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start P2P node: {e}")
            raise
    
    def stop(self):
        """Stop P2P node"""
        self.is_running = False
        if self.socket:
            self.socket.close()
        self.logger.info("P2P node stopped")
    
    def register_handler(self, message_type: str, handler: Callable):
        """Register message handler"""
        self.message_handlers[message_type] = handler
    
    def broadcast_threat_info(self, threat_data: Dict):
        """Broadcast threat information to all peers"""
        message = {
            'type': 'threat_info',
            'node_id': self.node_id,
            'timestamp': time.time(),
            'data': threat_data
        }
        self._broadcast_message(message)
        self.stats['threats_shared'] += 1
    
    def broadcast_model_update(self, model_info: Dict):
        """Broadcast model update to peers"""
        message = {
            'type': 'model_update',
            'node_id': self.node_id,
            'timestamp': time.time(),
            'data': model_info
        }
        self._broadcast_message(message)
        self.stats['models_updated'] += 1
    
    def request_threat_database(self, peer_address: tuple):
        """Request threat database from specific peer"""
        message = {
            'type': 'threat_db_request',
            'node_id': self.node_id,
            'timestamp': time.time()
        }
        self._send_message_to_peer(peer_address, message)
    
    def add_peer(self, ip: str, port: int):
        """Manually add peer"""
        peer_address = (ip, port)
        if peer_address not in self.peers:
            if self._test_peer_connection(peer_address):
                self.peers.add(peer_address)
                self.stats['peers_connected'] += 1
                self.logger.info(f"Peer added: {ip}:{port}")
                return True
        return False
    
    def get_peer_list(self) -> List[tuple]:
        """Get list of connected peers"""
        return list(self.peers)
    
    def get_stats(self) -> Dict:
        """Get node statistics"""
        stats = self.stats.copy()
        stats['active_peers'] = len(self.peers)
        stats['node_id'] = self.node_id
        stats['uptime'] = time.time() - getattr(self, 'start_time', time.time())
        return stats
    
    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        hostname = socket.gethostname()
        mac = hex(hash(hostname + str(time.time())))
        return hashlib.sha256(mac.encode()).hexdigest()[:16]
    
    def _create_cipher(self, network_key: str) -> Fernet:
        """Create encryption cipher with fallback"""
        if CRYPTOGRAPHY_AVAILABLE:
            password = network_key.encode()
            salt = b'aintivirus_salt_2024'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            return Fernet(key)
        else:
            # Fallback to basic encryption
            return Fernet(network_key)
    
    def _listen_for_connections(self):
        """Listen for incoming peer connections"""
        while self.is_running:
            try:
                client_socket, address = self.socket.accept()
                # Handle connection in separate thread
                handler_thread = threading.Thread(
                    target=self._handle_peer_connection,
                    args=(client_socket, address),
                    daemon=True
                )
                handler_thread.start()
            except Exception as e:
                if self.is_running:
                    self.logger.error(f"Error accepting connection: {e}")
    
    def _handle_peer_connection(self, client_socket: socket.socket, address: tuple):
        """Handle individual peer connection"""
        try:
            # Add peer to list
            self.peers.add(address)
            
            while self.is_running:
                # Receive message length
                length_data = client_socket.recv(4)
                if not length_data:
                    break
                
                message_length = struct.unpack('!I', length_data)[0]
                
                # Receive encrypted message
                encrypted_data = b''
                while len(encrypted_data) < message_length:
                    chunk = client_socket.recv(message_length - len(encrypted_data))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                # Decrypt and process message
                try:
                    decrypted_data = self.cipher.decrypt(encrypted_data)
                    message = json.loads(decrypted_data.decode())
                    self._process_message(message, address)
                except Exception as e:
                    self.logger.error(f"Failed to decrypt message from {address}: {e}")
                
        except Exception as e:
            self.logger.error(f"Error handling peer {address}: {e}")
        finally:
            client_socket.close()
            self.peers.discard(address)
    
    def _process_message(self, message: Dict, sender_address: tuple):
        """Process received message"""
        try:
            # Check for duplicate messages
            message_id = f"{message.get('node_id')}_{message.get('timestamp')}"
            if message_id in self.seen_messages:
                return
            
            self.seen_messages.add(message_id)
            
            # Limit seen messages cache
            if len(self.seen_messages) > self.max_seen_messages:
                # Remove oldest messages (simplified)
                self.seen_messages = set(list(self.seen_messages)[-self.max_seen_messages//2:])
            
            message_type = message.get('type')
            self.stats['messages_received'] += 1
            
            # Handle different message types
            if message_type in self.message_handlers:
                self.message_handlers[message_type](message, sender_address)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
            
            # Forward message to other peers (flooding)
            self._forward_message(message, sender_address)
            
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    def _forward_message(self, message: Dict, sender_address: tuple):
        """Forward message to other peers"""
        for peer in self.peers:
            if peer != sender_address:
                try:
                    self._send_message_to_peer(peer, message)
                except Exception as e:
                    self.logger.error(f"Failed to forward message to {peer}: {e}")
    
    def _broadcast_message(self, message: Dict):
        """Broadcast message to all peers"""
        for peer in self.peers.copy():  # Copy to avoid modification during iteration
            try:
                self._send_message_to_peer(peer, message)
            except Exception as e:
                self.logger.error(f"Failed to send message to {peer}: {e}")
                # Remove failed peer
                self.peers.discard(peer)
        
        self.stats['messages_sent'] += 1
    
    def _send_message_to_peer(self, peer_address: tuple, message: Dict):
        """Send message to specific peer"""
        try:
            # Create connection
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.settimeout(10)  # 10 second timeout
            peer_socket.connect(peer_address)
            
            # Encrypt message
            message_data = json.dumps(message).encode()
            encrypted_data = self.cipher.encrypt(message_data)
            
            # Send message length and data
            message_length = len(encrypted_data)
            peer_socket.send(struct.pack('!I', message_length))
            peer_socket.send(encrypted_data)
            
            peer_socket.close()
            
        except Exception as e:
            self.logger.error(f"Failed to send message to {peer_address}: {e}")
            raise
    
    def _test_peer_connection(self, peer_address: tuple) -> bool:
        """Test connection to peer"""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            test_socket.connect(peer_address)
            test_socket.close()
            return True
        except:
            return False
    
    def _discover_peers(self):
        """Discover peers on local network"""
        while self.is_running:
            try:
                # Simple peer discovery using broadcast
                self._broadcast_discovery()
                time.sleep(60)  # Discovery every minute
            except Exception as e:
                self.logger.error(f"Peer discovery error: {e}")
    
    def _broadcast_discovery(self):
        """Broadcast discovery message"""
        try:
            # UDP broadcast for peer discovery
            broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            discovery_message = {
                'type': 'peer_discovery',
                'node_id': self.node_id,
                'port': self.port,
                'timestamp': time.time()
            }
            
            message_data = json.dumps(discovery_message).encode()
            broadcast_socket.sendto(message_data, ('<broadcast>', 8889))
            broadcast_socket.close()
            
        except Exception as e:
            self.logger.error(f"Broadcast discovery failed: {e}")

class P2PNetworkManager:
    """P2P Network Manager for coordinating multiple nodes"""
    
    def __init__(self, ai_engine, quarantine_manager, port: int = 8888):
        self.ai_engine = ai_engine
        self.quarantine_manager = quarantine_manager
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.network.p2p_communication')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.node = P2PNode(port)
        
        # Register message handlers
        self.node.register_handler('threat_info', self._handle_threat_info)
        self.node.register_handler('model_update', self._handle_model_update)
        self.node.register_handler('quarantine_request', self._handle_quarantine_request)
    
    def _handle_threat_info(self, message_data):
        """Handle threat information from peers"""
        try:
            threat_info = message_data.get('threat_info', {})
            self.logger.info(f"Received threat info: {threat_info.get('file_path', 'unknown')}")
            # Process threat information with AI engine
            if self.ai_engine:
                self.ai_engine.learn_from_peer_data(threat_info)
        except Exception as e:
            self.logger.error(f"Failed to handle threat info: {e}")
    
    def _handle_model_update(self, message_data):
        """Handle model update from peers"""
        try:
            model_data = message_data.get('model_data', {})
            self.logger.info("Received model update from peer")
            # Update AI model with peer data
            if self.ai_engine:
                self.ai_engine.update_from_peer_model(model_data)
        except Exception as e:
            self.logger.error(f"Failed to handle model update: {e}")
    
    def _handle_quarantine_request(self, message_data):
        """Handle quarantine request from peers"""
        try:
            quarantine_data = message_data.get('quarantine_data', {})
            self.logger.info(f"Received quarantine request: {quarantine_data.get('file_hash', 'unknown')}")
            # Process quarantine request
            if self.quarantine_manager:
                file_hash = quarantine_data.get('file_hash')
                if file_hash:
                    self.quarantine_manager.add_to_quarantine_by_hash(file_hash)
        except Exception as e:
            self.logger.error(f"Failed to handle quarantine request: {e}")
    
    def start(self):
        """Start P2P network manager"""
        try:
            self.node.start()
            self.logger.info("P2P Network Manager started")
        except Exception as e:
            self.logger.error(f"Failed to start P2P Network Manager: {e}")
    
    def stop(self):
        """Stop P2P network manager"""
        try:
            self.node.stop()
            self.logger.info("P2P Network Manager stopped")
        except Exception as e:
            self.logger.error(f"Failed to stop P2P Network Manager: {e}")
    
    def stop_network(self):
        """Stop P2P network"""
        if self.p2p_node:
            self.p2p_node.stop()
            self.p2p_node = None
        self.logger.info("P2P network stopped")
    
    def share_threat_detection(self, threat_info: Dict):
        """Share threat detection with network"""
        if self.p2p_node:
            # Add to local database
            with self.threat_db_lock:
                threat_id = hashlib.sha256(
                    f"{threat_info['file_path']}{threat_info['timestamp']}".encode()
                ).hexdigest()[:16]
                
                self.shared_threats[threat_id] = {
                    'threat_info': threat_info,
                    'shared_time': time.time(),
                    'source_node': self.p2p_node.node_id
                }
            
            # Broadcast to network
            self.p2p_node.broadcast_threat_info(threat_info)
    
    def share_model_update(self, model_path: str, model_info: Dict):
        """Share model update with network"""
        if self.p2p_node:
            update_info = {
                'model_path': model_path,
                'model_info': model_info,
                'update_time': time.time()
            }
            self.p2p_node.broadcast_model_update(update_info)
    
    def _handle_threat_info(self, message: Dict, sender_address: tuple):
        """Handle received threat information"""
        try:
            threat_data = message['data']
            sender_node = message['node_id']
            
            # Store in shared threats database
            with self.threat_db_lock:
                threat_id = hashlib.sha256(
                    f"{threat_data['file_path']}{message['timestamp']}".encode()
                ).hexdigest()[:16]
                
                if threat_id not in self.shared_threats:
                    self.shared_threats[threat_id] = {
                        'threat_info': threat_data,
                        'shared_time': message['timestamp'],
                        'source_node': sender_node
                    }
                    
                    self.logger.info(f"Received threat info from {sender_node}: {threat_data['file_path']}")
            
        except Exception as e:
            self.logger.error(f"Error handling threat info: {e}")
    
    def _handle_model_update(self, message: Dict, sender_address: tuple):
        """Handle model update message"""
        try:
            model_data = message['data']
            sender_node = message['node_id']
            
            # TODO: Implement secure model update mechanism
            self.logger.info(f"Model update received from {sender_node}")
            
        except Exception as e:
            self.logger.error(f"Error handling model update: {e}")
    
    def _handle_threat_db_request(self, message: Dict, sender_address: tuple):
        """Handle threat database request"""
        try:
            # Send threat database to requesting peer
            with self.threat_db_lock:
                response_message = {
                    'type': 'threat_db_response',
                    'node_id': self.p2p_node.node_id,
                    'timestamp': time.time(),
                    'data': {
                        'threats': self.shared_threats,
                        'count': len(self.shared_threats)
                    }
                }
            
            self.p2p_node._send_message_to_peer(sender_address, response_message)
            
        except Exception as e:
            self.logger.error(f"Error handling threat DB request: {e}")
    
    def _handle_threat_db_response(self, message: Dict, sender_address: tuple):
        """Handle threat database response"""
        try:
            threat_data = message['data']
            received_threats = threat_data['threats']
            
            # Merge received threats with local database
            with self.threat_db_lock:
                for threat_id, threat_info in received_threats.items():
                    if threat_id not in self.shared_threats:
                        self.shared_threats[threat_id] = threat_info
            
            self.logger.info(f"Merged {len(received_threats)} threats from network")
            
        except Exception as e:
            self.logger.error(f"Error handling threat DB response: {e}")
    
    def get_network_stats(self) -> Dict:
        """Get network statistics"""
        if self.p2p_node:
            stats = self.p2p_node.get_stats()
            with self.threat_db_lock:
                stats['shared_threats'] = len(self.shared_threats)
            return stats
        return {}
    
    def get_shared_threats(self) -> Dict:
        """Get shared threats database"""
        with self.threat_db_lock:
            return self.shared_threats.copy()
