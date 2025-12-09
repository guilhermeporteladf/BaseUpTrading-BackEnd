# BaseUp Trading Backend

Backend server for BaseUp Trading Educational Website.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Set up environment variables in `.env`:
- `PORT` - Server port (default: 4000)
- `FRONTEND_URL` - Frontend URL for CORS
- `DISCORD_CLIENT_ID` - Discord OAuth client ID
- `DISCORD_CLIENT_SECRET` - Discord OAuth client secret
- `DISCORD_REDIRECT_URI` - Discord OAuth redirect URI
- `DISCORD_BOT_TOKEN` - Discord bot token
- `DISCORD_GUILD_ID` - Discord guild/server ID
- `JWT_SECRET` - JWT secret for token signing
- `FIREBASE_SERVICE_ACCOUNT` - Firebase service account JSON (stringified)

## Development

```bash
npm run dev
```

## Production

```bash
npm start
```

## Deployment

This backend is configured for Vercel deployment.
