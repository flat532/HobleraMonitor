#!/usr/bin/env python3
"""
Alert Manager - wysyła maile przy anomaliach
Modyfikacja:
- Wysyłka zbiorcza (summary)
- Ignorowanie 'failed_login' w mailach (tylko oznaczane jako wysłane)
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
from config import Config
from datetime import datetime

def send_summary_email(alerts_to_send):
    """Wyślij zbiorczy email o alertach (tylko security_ban)"""
    
    if not alerts_to_send:
        return True

    count = len(alerts_to_send)
    subject = f"⚠️ Hoblera Summary: {count} Banned IPs"
    
    alerts_html = ""
    for alert in alerts_to_send:
        # Determine icon/color based on alert type
        icon = "🚫" 
        color = "#e74c3c" # Red
        title = "IP Banned"
        
        alerts_html += f"""
        <div style="background-color: #ffffff; border-left: 4px solid {color}; padding: 15px; margin-bottom: 15px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <strong style="color: #2c3e50; font-size: 16px;">{icon} {title}: {alert['details']}</strong>
                <span style="color: #95a5a6; font-size: 12px;">{alert['created_at']}</span>
            </div>
            <div style="color: #34495e; font-size: 14px; line-height: 1.5;">
                {alert['message']}
            </div>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f7fa; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; margin-top: 20px; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); padding: 20px; text-align: center;">
                <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;">Hoblera Monitoring</h1>
                <p style="margin: 5px 0 0; color: #ecf0f1; font-size: 14px;">Security Alert Notification</p>
            </div>
            
            <!-- Content -->
            <div style="padding: 30px;">
                <p style="margin-top: 0; color: #7f8c8d; font-size: 14px; margin-bottom: 25px;">
                    The following security events have been detected and acted upon by your monitoring system.
                </p>
                
                {alerts_html}
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="http://10.10.10.111:8002" style="background-color: #3498db; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: 600; font-size: 14px;">Open Dashboard</a>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background-color: #ecf0f1; padding: 15px; text-align: center; color: #95a5a6; font-size: 12px;">
                &copy; {datetime.now().year} Hoblera Monitoring System<br>
                Automated Security Report
            </div>
        </div>
    </body>
    </html>
    """
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    # Format: "Name <email@domain.com>"
    msg['From'] = f"Hoblera Monitoring <{Config.EMAIL_FROM}>"
    msg['To'] = Config.EMAIL_TO
    msg.attach(MIMEText(html, 'html'))
    
    try:
        server = smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT)
        server.starttls()
        server.login(Config.SMTP_USER, Config.SMTP_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def check_and_send_alerts():
    """Sprawdź niewysłane alerty i wyślij maile"""
    conn = sqlite3.connect(Config.DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Pobierz niewysłane alerty
    cursor.execute('''
        SELECT * FROM alerts 
        WHERE email_sent = 0
        ORDER BY created_at ASC
    ''')
    
    alerts = cursor.fetchall()
    
    if not alerts:
        print("No new alerts to process.")
        conn.close()
        return

    # Filter alerts
    alerts_to_email = []
    ids_to_mark_sent = []

    print(f"Processing {len(alerts)} new alerts...")

    for alert in alerts:
        alert_dict = dict(alert)
        ids_to_mark_sent.append(alert['id'])

        # Logic: 
        # - 'failed_login' -> Mark as sent, DO NOT EMAIL
        # - 'security_ban' (or others) -> Mark as sent, ADD TO EMAIL
        if alert['alert_type'] == 'failed_login':
            print(f"Skipping email for failed_login alert ID {alert['id']}")
            continue
        
        alerts_to_email.append(alert_dict)

    # Send valid alerts
    success = True
    if alerts_to_email:
        print(f"Sending summary email with {len(alerts_to_email)} alerts...")
        if send_summary_email(alerts_to_email):
            print("✓ Email sent successfully.")
        else:
            print("✗ Failed to send email.")
            success = False
    else:
        print("No alerts requiring email.")

    # Mark as sent ONLY if email was successful (or no email needed)
    if success:
        placeholders = ','.join('?' for _ in ids_to_mark_sent)
        if ids_to_mark_sent:
            cursor.execute(f'''
                UPDATE alerts SET email_sent = 1 WHERE id IN ({placeholders})
            ''', ids_to_mark_sent)
            conn.commit()
            print(f"Marked {len(ids_to_mark_sent)} alerts as processed.")

    conn.close()

if __name__ == "__main__":
    check_and_send_alerts()
