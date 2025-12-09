import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import admin from 'firebase-admin';
import { authMiddleware, type AuthenticatedRequest } from './authMiddleware';

dotenv.config();

// Initialize Firebase Admin
if (!admin.apps.length) {
  try {
    const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (serviceAccount) {
      admin.initializeApp({
        credential: admin.credential.cert(JSON.parse(serviceAccount)),
      });
    } else {
      // Fallback: use default credentials (for local development with gcloud)
      admin.initializeApp({
        credential: admin.credential.applicationDefault(),
      });
    }
  } catch (error) {
    console.error('Firebase Admin initialization error:', error);
    console.warn('Video signed URL functionality will not work without Firebase Admin');
  }
}

const app = express();
const PORT = process.env.PORT || 4000;

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));

app.use(cookieParser());
app.use(express.json());

// Types
type BaseUpLevel = 1 | 2 | 3 | 4;

interface BaseUpMembership {
  level: BaseUpLevel;
  plan: 'FREE' | 'STARTER' | 'PRO' | 'MENTOR';
}

interface DiscordUser {
  id: string;
  username: string;
  discriminator: string;
  avatar: string | null;
  email: string | null;
}

interface JWTPayload {
  discordId: string;
  username: string;
  avatar: string | null;
  email: string | null;
  membership: BaseUpMembership;
  isOwner: boolean; // Owner role for admin access
}

// Discord role to BaseUp membership mapping
// Role names: "Beginner" → Level 2, "BluePrint" → Level 3, "Mastery" → Level 4
async function getMembershipFromDiscordRoles(discordId: string, accessToken: string): Promise<BaseUpMembership> {
  const botToken = process.env.DISCORD_BOT_TOKEN;
  const guildId = process.env.DISCORD_GUILD_ID;

  // If bot token or guild ID not configured, default to FREE
  if (!botToken || !guildId) {
    console.warn('Discord Bot Token or Guild ID not configured. Defaulting to FREE membership.');
    return { level: 1, plan: 'FREE' };
  }

  try {
    // Get user's guild member info to check their roles
    const memberResponse = await axios.get(
      `https://discord.com/api/v10/guilds/${guildId}/members/${discordId}`,
      {
        headers: {
          Authorization: `Bot ${botToken}`,
        },
      }
    );

    const roles = memberResponse.data.roles || [];
    
    // Get all role names from the guild
    const guildResponse = await axios.get(
      `https://discord.com/api/v10/guilds/${guildId}/roles`,
      {
        headers: {
          Authorization: `Bot ${botToken}`,
        },
      }
    );

    const guildRoles = guildResponse.data || [];
    const userRoleNames = guildRoles
      .filter((role: any) => roles.includes(role.id))
      .map((role: any) => role.name.toLowerCase());

    // Debug logging
    console.log(`[Discord Roles] User ${discordId} has roles:`, userRoleNames);
    console.log(`[Discord Roles] All user role IDs:`, roles);
    console.log(`[Discord Roles] Checking for membership roles...`);

    // Check for membership roles (case-insensitive)
    // Priority: Mastery > BluePrint > Beginner
    if (userRoleNames.includes('mastery')) {
      console.log(`[Discord Roles] Found Mastery role → Level 4 (MENTOR)`);
      return { level: 4, plan: 'MENTOR' };
    }
    if (userRoleNames.includes('blueprint')) {
      console.log(`[Discord Roles] Found BluePrint role → Level 3 (PRO)`);
      return { level: 3, plan: 'PRO' };
    }
    if (userRoleNames.includes('beginner')) {
      console.log(`[Discord Roles] Found Beginner role → Level 2 (STARTER)`);
      return { level: 2, plan: 'STARTER' };
    }

    // No membership role found, default to FREE
    console.log(`[Discord Roles] No membership role found. User roles:`, userRoleNames);
    return { level: 1, plan: 'FREE' };
  } catch (error: any) {
    // If user is not in the guild or other error, default to FREE
    if (error.response?.status === 404) {
      console.log(`User ${discordId} not found in guild ${guildId}`);
    } else {
      console.error('Error fetching Discord roles:', error.response?.data || error.message);
    }
    return { level: 1, plan: 'FREE' };
  }
}

// Check if user has Owner role for admin access
async function checkOwnerRole(discordId: string): Promise<boolean> {
  const botToken = process.env.DISCORD_BOT_TOKEN;
  const guildId = process.env.DISCORD_GUILD_ID;

  if (!botToken || !guildId) {
    return false;
  }

  try {
    // Get user's guild member info to check their roles
    const memberResponse = await axios.get(
      `https://discord.com/api/v10/guilds/${guildId}/members/${discordId}`,
      {
        headers: {
          Authorization: `Bot ${botToken}`,
        },
      }
    );

    const roles = memberResponse.data.roles || [];
    
    // Get all role names from the guild
    const guildResponse = await axios.get(
      `https://discord.com/api/v10/guilds/${guildId}/roles`,
      {
        headers: {
          Authorization: `Bot ${botToken}`,
        },
      }
    );

    const guildRoles = guildResponse.data || [];
    const userRoleNames = guildRoles
      .filter((role: any) => roles.includes(role.id))
      .map((role: any) => role.name.toLowerCase());

    // Check for Owner role (case-insensitive)
    const isOwner = userRoleNames.includes('owner');
    console.log(`[Admin Check] User ${discordId} isOwner:`, isOwner);
    return isOwner;
  } catch (error: any) {
    // If user is not in the guild or other error, not an owner
    if (error.response?.status === 404) {
      console.log(`User ${discordId} not found in guild ${guildId}`);
    } else {
      console.error('Error checking Owner role:', error.response?.data || error.message);
    }
    return false;
  }
}

// GET /auth/discord/login - Redirect to Discord OAuth
app.get('/auth/discord/login', (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID?.trim();
  const redirectUri = (process.env.DISCORD_REDIRECT_URI || 'http://localhost:4000/auth/discord/callback').trim();

  if (!clientId || clientId === 'your_discord_client_id_here') {
    return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=config`);
  }

  // Validate redirect URI format
  try {
    new URL(redirectUri);
  } catch (error) {
    console.error('Invalid redirect URI:', redirectUri);
    return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=config`);
  }

  const discordAuthUrl = new URL('https://discord.com/api/oauth2/authorize');
  discordAuthUrl.searchParams.set('client_id', clientId);
  discordAuthUrl.searchParams.set('redirect_uri', redirectUri);
  discordAuthUrl.searchParams.set('response_type', 'code');
  discordAuthUrl.searchParams.set('scope', 'identify email');
  discordAuthUrl.searchParams.set('prompt', 'consent');

  // Debug logging
  console.log('Discord OAuth URL:', discordAuthUrl.toString());
  console.log('Redirect URI being used:', redirectUri);
  console.log('Client ID:', clientId);

  res.redirect(discordAuthUrl.toString());
});

// GET /auth/discord/callback - Handle Discord OAuth callback
app.get('/auth/discord/callback', async (req, res) => {
  const { code } = req.query;

  if (!code || typeof code !== 'string') {
    return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=no_code`);
  }

  try {
    const clientId = process.env.DISCORD_CLIENT_ID?.trim();
    const clientSecret = process.env.DISCORD_CLIENT_SECRET?.trim();
    const redirectUri = (process.env.DISCORD_REDIRECT_URI || 'http://localhost:4000/auth/discord/callback').trim();

    if (!clientId || !clientSecret) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=config`);
    }

    // Exchange code for access token
    const tokenResponse = await axios.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const { access_token } = tokenResponse.data;

    // Fetch user info from Discord
    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    });

    const discordUser: DiscordUser = {
      id: userResponse.data.id,
      username: userResponse.data.username,
      discriminator: userResponse.data.discriminator || '0',
      avatar: userResponse.data.avatar,
      email: userResponse.data.email,
    };

    // Get membership from Discord roles
    const membership = await getMembershipFromDiscordRoles(discordUser.id, access_token);
    console.log(`[Auth] User ${discordUser.username} (${discordUser.id}) membership:`, membership);

    // Check for Owner role (admin access)
    const isOwner = await checkOwnerRole(discordUser.id);

    // Save/update user in Firebase (via frontend will handle this)
    // For now, we'll just create the JWT and let the frontend handle user storage
    
    // Create JWT
    const jwtSecret = process.env.JWT_SECRET || 'super_secret_jwt_for_baseup';
    const payload: JWTPayload = {
      discordId: discordUser.id,
      username: discordUser.username,
      avatar: discordUser.avatar,
      email: discordUser.email,
      membership,
      isOwner,
    };

    const token = jwt.sign(payload, jwtSecret, { expiresIn: '7d' });

    // Set HTTP-only cookie
    res.cookie('baseup_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
      domain: process.env.NODE_ENV === 'production' ? undefined : undefined, // Let browser set domain
    });

    // Redirect to processing page
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth/discord/processing`);
  } catch (error) {
    console.error('Discord OAuth error:', error);
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=oauth_failed`);
  }
});

// GET /auth/me - Get current user from JWT
app.get('/auth/me', (req, res) => {
  const token = req.cookies.baseup_token;

  if (!token) {
    // Return 401 for unauthenticated requests (expected behavior)
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const jwtSecret = process.env.JWT_SECRET || 'super_secret_jwt_for_baseup';
    const decoded = jwt.verify(token, jwtSecret) as JWTPayload;
    res.json(decoded);
  } catch (error) {
    // Token is invalid or expired
    res.clearCookie('baseup_token', { path: '/' });
    res.status(401).json({ error: 'Invalid token' });
  }
});

// POST /auth/logout - Logout user
app.post('/auth/logout', (req, res) => {
  res.clearCookie('baseup_token', { path: '/' });
  res.json({ success: true });
});

// POST /api/videos/signed-url - Get signed URL for video
app.post('/api/videos/signed-url', authMiddleware, async (req: AuthenticatedRequest, res) => {
  try {
    const { storagePath } = req.body;

    if (!storagePath || typeof storagePath !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid storagePath' });
    }

    // Validate user is authenticated (already done by authMiddleware)
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Optional: Validate user membership/role here
    // For now, we'll allow any authenticated user to access videos
    // You can add checks like:
    // if (req.user.membership.level < 2) {
    //   return res.status(403).json({ error: 'Insufficient membership level' });
    // }

    try {
      const bucket = admin.storage().bucket();
      const file = bucket.file(storagePath);

      // Check if file exists
      const [exists] = await file.exists();
      if (!exists) {
        return res.status(404).json({ error: 'Video not found' });
      }

      // Generate signed URL (5 minutes expiry)
      const [signedUrl] = await file.getSignedUrl({
        action: 'read',
        expires: Date.now() + 5 * 60 * 1000, // 5 minutes
        version: 'v4',
      });

      return res.json({ url: signedUrl });
    } catch (storageError: any) {
      console.error('Storage error:', storageError);
      return res.status(500).json({ error: 'Failed to generate video URL' });
    }
  } catch (err) {
    console.error('signed-url error', err);
    return res.status(500).json({ error: 'Failed to generate video URL' });
  }
});

// POST /api/discord/send-message - Send message to Discord channel
app.post('/api/discord/send-message', async (req, res) => {
  const { channelId, message } = req.body;
  const botToken = process.env.DISCORD_BOT_TOKEN?.trim();

  if (!botToken || !channelId || !message) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  try {
    const response = await axios.post(
      `https://discord.com/api/v10/channels/${channelId}/messages`,
      {
        content: message,
      },
      {
        headers: {
          Authorization: `Bot ${botToken}`,
          'Content-Type': 'application/json',
        },
      }
    );

    res.json({ success: true, messageId: response.data.id });
  } catch (error: any) {
    console.error('Error sending Discord message:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to send Discord message' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`🚀 BaseUp server running on http://localhost:${PORT}`);
});

