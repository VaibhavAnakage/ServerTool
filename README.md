# Domain & Server Monitoring Dashboard

A Flask-based web application for monitoring domain SSL certificates and server performance with automated email alerts.

## Features

### 🌐 Domain Monitoring
- Track SSL certificate expiration dates
- Monitor domain registration information
- Configure email alerts for certificate expiration
- Visual indicators for certificate status (expired, expiring soon, healthy)

### 🖥️ Server Monitoring
- Real-time server performance metrics
- CPU, Memory, and Disk usage monitoring
- Network port status checking
- Historical performance data tracking
- Beautiful dashboard with modern UI

### 🔔 Alert System
- Email notifications for SSL certificate expiration
- Configurable alert timing (7-180 days before expiry)
- Support for multiple recipients
- One-time or recurring alert options
- Manual alert triggering

## Recent Improvements

### ✅ Added Modern CSS Styling
- Responsive design that works on all devices
- Modern gradient themes and card-based layout
- Professional color scheme with status indicators
- Improved typography and spacing

### ✅ Enhanced Server Monitoring
- **New Database Table**: `server_monitoring` for historical data
- **Server History Page**: View past 50 monitoring records
- **Real-time Data Storage**: Automatic logging of server metrics
- **Performance Indicators**: Color-coded status badges for CPU, memory, and disk usage

### ✅ Improved User Interface
- **Navigation Bar**: Consistent navigation across all pages
- **Status Badges**: Visual indicators for domain and server status
- **Responsive Tables**: Mobile-friendly data display
- **Better Forms**: Improved alert configuration interface

## Installation & Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Initialize Database**:
   ```bash
   python 1.py
   ```

3. **Configure Email Settings** (in `1app.py`):
   ```python
   SMTP_CONFIG = {
       "host": "your-smtp-server.com",
       "port": 587,
       "username": "your-email@domain.com",
       "password": "your-password",
       "use_tls": True,
       "from_addr": "your-email@domain.com"
   }
   ```

4. **Run the Application**:
   ```bash
   python 1app.py
   ```

5. **Access the Dashboard**: Open `http://localhost:5000` in your browser

## Usage

### Domain Monitoring
1. Navigate to **Domain Monitoring**
2. Add domains to monitor SSL certificates
3. Configure email alerts for each domain
4. View certificate status and expiration dates

### Server Monitoring
1. Visit **Server Info** for current system status
2. Check **Server History** for performance trends
3. Monitor CPU, memory, and disk usage over time

### Alert Management
1. Set up alerts in the domain configuration
2. Use **Run Alerts** to manually trigger notifications
3. Configure cron jobs for automated monitoring

## Database Schema

### Tables
- `domains`: Domain information and SSL certificate data
- `domain_alerts`: Email alert configurations
- `server_monitoring`: Historical server performance data

### Key Features
- Automatic data collection and storage
- Indexed queries for fast performance
- Foreign key relationships for data integrity

## File Structure

```
├── 1app.py              # Main Flask application
├── 1.py                 # Database initialization script
├── requirements.txt     # Python dependencies
├── monitoring.db        # SQLite database
├── static/
│   └── style.css       # Modern CSS styling
└── templates/
    ├── index.html       # Dashboard homepage
    ├── domain.html      # Domain monitoring page
    ├── server.html      # Server status page
    ├── server_history.html # Server performance history
    └── alert_form.html  # Alert configuration form
```

## Security Considerations

⚠️ **Important**: The current version has hardcoded SMTP credentials. For production use:
- Move credentials to environment variables
- Use secure configuration management
- Implement proper authentication
- Add input validation and sanitization

## Future Enhancements

- [ ] User authentication and authorization
- [ ] Bulk domain operations
- [ ] Export functionality for reports
- [ ] Advanced alert scheduling
- [ ] API endpoints for external integrations
- [ ] Dashboard widgets and charts
- [ ] Mobile app companion
