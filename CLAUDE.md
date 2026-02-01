# StrongSales Entry Analytics Dashboard

A complete entry/visit analytics dashboard for Zoezi gyms.

## Overview

This application provides comprehensive analytics for gym entry/check-in data from the Zoezi platform. It mirrors the design and functionality of the Group Training Analytics dashboard but focuses specifically on entry data.

## Features

### Analytics & Insights
- **Total Entries**: Overall count with success rate
- **Success/Failed Breakdown**: Track entry success and failure rates
- **Unique Visitors**: Count of distinct members entering
- **Average Entries per Day**: Daily entry averages
- **Peak Hour Analysis**: Identify busiest times of day
- **Peak Day Analysis**: Identify busiest days of week
- **Daily Trend Chart**: Visualize entries over time
- **Door Usage**: See which doors/access points are most used
- **Card Type Distribution**: Analyze which card types are being used
- **Top Visitors**: Leaderboard of most frequent visitors
- **Failed Entry Reasons**: Breakdown of why entries fail

### Filtering
- **Date Range**: Custom date selection with presets (7, 30, 90 days)
- **Door Filter**: Multi-select filter by access door
- **Status Filter**: Filter by successful/failed entries

### Export
- CSV export of filtered entry data

### Embed Mode
- Secure token-based embedding for iframe integration
- Hide header/gym selector for embedded views
- Single-club restricted access via tokens

## Tech Stack

- **Backend**: Node.js + Express.js
- **Frontend**: Vanilla HTML/CSS/JS (single-page app)
- **Styling**: Tailwind CSS (via CDN)
- **Charts**: Chart.js 4.x
- **Database**: Supabase (PostgreSQL)
- **Authentication**: Express-session + HMAC-SHA256 tokens

## Environment Variables

Required environment variables:

```env
SUPABASE_API_KEY=your_supabase_key
SESSION_SECRET=your_session_secret_min_32_chars
ADMIN_PASSWORD=your_login_password
ADMIN_KEY=your_admin_api_key_24_chars
EMBED_SECRET=your_embed_token_secret_32_chars
PORT=3000
```

## API Endpoints

### Authentication
- `GET /login` - Login page
- `POST /login` - Submit login
- `GET /logout` - Logout

### Public
- `GET /api/health` - Health check
- `GET /api/verify-token?token=xxx` - Verify embed token

### Protected (requires session)
- `GET /api/gyms` - List all configured clubs
- `GET /api/analytics/:clubId?fromDate=X&toDate=Y` - Get entry analytics

### Embed (requires valid token)
- `GET /api/embed/analytics?token=xxx&fromDate=X&toDate=Y` - Token-authenticated analytics

### Admin (requires X-Admin-Key header)
- `POST /api/admin/embed-token` - Generate token for one club
- `GET /api/admin/embed-tokens` - Generate tokens for all clubs

## Zoezi API Integration

This app uses the following Zoezi API endpoints:

### Entry Data
```
GET /api/entry/get?fromDate=X&toDate=Y
```
Returns array of entry records with:
- `entryTime` - Timestamp of entry
- `success` - Boolean success status
- `user_id` - Member ID
- `Member` - Member object with name, etc.
- `cardName` - Type of card used
- `door` - Door/resource ID
- `reason` - Failure reason if applicable

### Resources (Doors)
```
GET /api/resource/get/all
```
Returns list of doors/resources for labeling.

## Supabase Schema

Uses the existing `Clubs` table:
- `Club_Zoezi_ID` - Zoezi club identifier
- `Club_name` - Display name
- `Zoezi_Domain` - API domain (e.g., "fysiken.zoezi.se")
- `Zoezi_Api_Key` - API authentication key

## File Structure

```
StrongSales-zoezi-entry-dashboard/
├── index.js                    # Express server (main entry point)
├── public/
│   ├── index.html              # Single-page app frontend
│   ├── Strongsales logo WHITE.png
│   └── Strongsales logo black & purple Transparent.png
├── dateextensions.js           # Date utility functions
├── package.json                # Dependencies
├── .replit                     # Replit config
├── .gitignore
└── CLAUDE.md                   # This file
```

## Development

```bash
# Install dependencies
npm install

# Start server
npm start
```

## Deployment

### Replit
1. Create new Repl with Node.js template
2. Upload all files
3. Add environment variables as Secrets
4. Deploy

### Other Platforms
Standard Node.js deployment. Ensure environment variables are set.

## Security Features

- Timing-safe password comparison
- HMAC-SHA256 embed tokens
- HTTP-only secure cookies
- Session-based authentication
- Per-club token isolation
- 1-year token expiration

## Design System

Uses StrongSales purple branding:
- Primary: `#AFACFB`
- Secondary: `#8b5cf6`
- Accent: `#6d28d9`

Tailwind extended config:
```javascript
colors: {
  strongsales: {
    50: '#f5f3ff',
    100: '#ede9fe',
    200: '#ddd6fe',
    300: '#AFACFB',  // Primary
    400: '#a78bfa',
    500: '#8b5cf6',
    600: '#7c3aed',
    700: '#6d28d9',
    800: '#5b21b6',
    900: '#4c1d95'
  }
}
```

## Analytics Processing

The backend processes raw entry data into:

1. **Summary Statistics**
   - Total, successful, failed entries
   - Success rate percentage
   - Unique visitors count
   - Average entries per day
   - Peak hour and day

2. **Time-based Analysis**
   - By hour (5am-11pm)
   - By day of week
   - Daily trend

3. **Segmented Analysis**
   - By door/access point
   - By card type
   - Top visitors
   - Failed entry reasons

Client-side filtering recalculates all metrics in real-time.
