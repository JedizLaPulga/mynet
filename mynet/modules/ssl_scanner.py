import ssl
import asyncio
import socket
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .base import BaseModule
from ..core.input_parser import Target

class SSLScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "SSL Scanner"
        self.description = "Scans SSL/TLS certificates"

    async def run(self, target: Target) -> Dict[str, Any]:
        host = target.host if target.host else target.original_input
        # Default to 443
        port = 443
        
        try:
            loop = asyncio.get_event_loop()
            # ssl.get_server_certificate is blocking, run in executor
            pem_data = await loop.run_in_executor(None, self._fetch_certificate, host, port)
            
            if not pem_data:
                # If we can't get a cert (e.g. port closed), return empty or null
                return {} # Return empty to indicate no SSL found/available
                
            return self._parse_certificate(pem_data)
        except Exception as e:
            return {"error": str(e)}

    def _fetch_certificate(self, host: str, port: int) -> Optional[str]:
        try:
            # We use a socket to check connectivity first or just try get_server_certificate
            # get_server_certificate attempts to connect.
            # It connects to (host, port) and returns the PEM-encoded certificate 
            # as a byte string (Python 2) or unicode string (Python 3).
            return ssl.get_server_certificate((host, port), timeout=self.config.timeout)
        except (socket.error, socket.timeout):
            return None
        except Exception:
            return None

    def _parse_certificate(self, pem_data: str) -> Dict[str, Any]:
        cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
        
        # Helper to extract name (simpler version)
        def get_common_name(name):
             # Try to get CN
             try:
                 attributes = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                 if attributes:
                     return attributes[0].value
                 return str(name)
             except:
                 return str(name)

        # SANs
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        valid_from = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        valid_to = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after

        return {
            "subject": get_common_name(cert.subject),
            "issuer": get_common_name(cert.issuer),
            "valid_from": valid_from.isoformat(),
            "valid_to": valid_to.isoformat(),
            "serial_number": str(cert.serial_number),
            "sans": sans
        }
