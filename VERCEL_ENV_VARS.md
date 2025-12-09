# Vercel Environment Variables Configuration

## Required Environment Variables

Add these in your Vercel project settings under **Settings → Environment Variables**.

### 1. **PORT** (Optional - Vercel sets this automatically)
```
PORT=4000
```
- **Note**: Vercel automatically sets the PORT, but you can override it if needed
- **Default**: Vercel will assign automatically

---

### 2. **FRONTEND_URL**
```
FRONTEND_URL=https://your-netlify-site.netlify.app
```
- **Value**: Your Netlify frontend URL (e.g., `https://baseup-trading.netlify.app`)
- **Where to get**: After deploying to Netlify, copy the site URL
- **Important**: Must include `https://` and no trailing slash

---

### 3. **DISCORD_CLIENT_ID**
```
DISCORD_CLIENT_ID=your_discord_client_id_here
```
- **Where to get**: 
  1. Go to https://discord.com/developers/applications
  2. Select your application
  3. Go to "OAuth2" section
  4. Copy the "Client ID"
- **Format**: Numeric string (e.g., `123456789012345678`)

---

### 4. **DISCORD_CLIENT_SECRET**
```
DISCORD_CLIENT_SECRET=your_discord_client_secret_here
```
- **Where to get**:
  1. Same Discord Developer Portal
  2. In "OAuth2" section
  3. Click "Reset Secret" if needed
  4. Copy the "Client Secret"
- **Format**: Alphanumeric string (keep this secret!)

---

### 5. **DISCORD_REDIRECT_URI**
```
DISCORD_REDIRECT_URI=https://your-vercel-backend.vercel.app/auth/discord/callback
```
- **Value**: Your Vercel backend URL + `/auth/discord/callback`
- **Example**: `https://baseup-backend.vercel.app/auth/discord/callback`
- **Important**: 
  - Must match exactly what's in Discord OAuth settings
  - Update this in Discord Developer Portal after getting your Vercel URL
  - Must use `https://` (not `http://`)

---

### 6. **DISCORD_BOT_TOKEN**
```
DISCORD_BOT_TOKEN=your_discord_bot_token_here
```
- **Where to get**:
  1. Discord Developer Portal → Your Application
  2. Go to "Bot" section
  3. Click "Reset Token" if needed
  4. Copy the token
- **Format**: Long alphanumeric string starting with letters
- **Important**: Keep this secret! Never commit to git.

---

### 7. **DISCORD_GUILD_ID**
```
DISCORD_GUILD_ID=your_discord_server_id_here
```
- **Where to get**:
  1. Enable Developer Mode in Discord (User Settings → Advanced → Developer Mode)
  2. Right-click on your Discord server
  3. Click "Copy Server ID"
- **Format**: Numeric string (e.g., `987654321098765432`)
- **Purpose**: Used to check user roles for membership levels

---

### 8. **JWT_SECRET**
```
JWT_SECRET=your_super_secret_jwt_key_here
```
- **Value**: A strong, random secret key for signing JWT tokens
- **Generate**: Use a secure random string generator
- **Example**: `baseup_jwt_secret_2024_secure_random_string_xyz123`
- **Important**: 
  - Must be at least 32 characters
  - Use a different secret for production
  - Keep this secret!

---

### 9. **FIREBASE_SERVICE_ACCOUNT**
```
FIREBASE_SERVICE_ACCOUNT={"type":"service_account","project_id":"...","private_key_id":"...","private_key":"...","client_email":"...","client_id":"...","auth_uri":"...","token_uri":"...","auth_provider_x509_cert_url":"...","client_x509_cert_url":"..."}
```
- **Where to get**:
  1. Go to Firebase Console: https://console.firebase.google.com
  2. Select your project
  3. Go to Project Settings → Service Accounts
  4. Click "Generate New Private Key"
  5. Download the JSON file
  6. Copy the entire JSON content
  7. **Convert to single line**: Remove all line breaks and spaces (or use a JSON minifier)
- **Format**: Single-line JSON string (no line breaks)
- **Important**: 
  - This is sensitive data - keep it secret
  - Must be valid JSON
  - Used for Firebase Admin SDK (video signed URLs)

---

### 10. **NODE_ENV** (Optional - Vercel sets this automatically)
```
NODE_ENV=production
```
- **Note**: Vercel automatically sets this to `production` in production deployments
- **Default**: Set automatically by Vercel

---

## Example Complete Configuration

Here's what your Vercel environment variables should look like (with placeholder values):

```
PORT=4000
FRONTEND_URL=https://baseup-trading.netlify.app
DISCORD_CLIENT_ID=123456789012345678
DISCORD_CLIENT_SECRET=abcdefghijklmnopqrstuvwxyz123456
DISCORD_REDIRECT_URI=https://baseup-backend.vercel.app/auth/discord/callback
DISCORD_BOT_TOKEN=your_discord_bot_token_here
DISCORD_GUILD_ID=987654321098765432
JWT_SECRET=baseup_super_secret_jwt_key_2024_xyz123_secure_random
FIREBASE_SERVICE_ACCOUNT={"type":"service_account","project_id":"baseup-9e25b",...}
NODE_ENV=production
```

---

## Setup Steps

1. **Deploy to Vercel first** to get your backend URL
2. **Add all environment variables** in Vercel dashboard
3. **Update Discord OAuth Redirect URI**:
   - Go to Discord Developer Portal
   - Add your Vercel callback URL: `https://your-backend.vercel.app/auth/discord/callback`
4. **Update Frontend**:
   - In Netlify, add environment variable: `VITE_API_URL=https://your-backend.vercel.app`
5. **Redeploy** both frontend and backend after setting variables

---

## Security Notes

- ✅ Never commit these values to git
- ✅ Use Vercel's environment variables (not hardcoded)
- ✅ Rotate secrets periodically
- ✅ Use different values for development and production
- ✅ Keep `DISCORD_CLIENT_SECRET`, `DISCORD_BOT_TOKEN`, `JWT_SECRET`, and `FIREBASE_SERVICE_ACCOUNT` secure

---

## Testing

After deployment, test the flow:
1. Visit your Netlify frontend
2. Click "Login with Discord"
3. Should redirect to Discord OAuth
4. After authorization, should redirect back and log you in
