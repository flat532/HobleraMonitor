import os

class Config:
    DB_FILE = 'monitor.db'
    HOST = '0.0.0.0'
    PORT = 5000
    DEBUG = True
    AUTH_LOG = '/var/log/auth.log'
    MAX_FAILED_LOGINS_PER_HOUR = 5
