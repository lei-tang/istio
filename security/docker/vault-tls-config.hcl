{
  "backend": {
    "file": {
      "path": "/var/lib/vault"
    }
  },
  "listener": {
    "tcp":{
      "address":"0.0.0.0:8200",
      "tls_disable": "0",
      "tls_cert_file":"/etc/vault/server-tls-cert.pem",
      "tls_key_file":"/etc/vault/server-tls-key.pem"
    }
  }
}