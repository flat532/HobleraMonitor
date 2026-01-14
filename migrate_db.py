
import sqlite3
from config import Config

def migrate():
    print(f"Connecting to database: {Config.DB_FILE}")
    conn = sqlite3.connect(Config.DB_FILE)
    cursor = conn.cursor()
    
    # Enable autocommit for migration or commit explicitly
    try:
        cursor.execute("ALTER TABLE system_metrics ADD COLUMN net_sent_bytes INTEGER")
        cursor.execute("ALTER TABLE system_metrics ADD COLUMN net_recv_bytes INTEGER")
        conn.commit()
        print("Success: Added net_sent_bytes and net_recv_bytes columns.")
    except sqlite3.OperationalError as e:
        print(f"Migration info: {e} (Column might already exist)")
        
    conn.close()

if __name__ == "__main__":
    migrate()
