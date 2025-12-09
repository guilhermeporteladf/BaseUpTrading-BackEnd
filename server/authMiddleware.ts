import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JWTPayload {
  discordId: string;
  username: string;
  avatar: string | null;
  email: string | null;
  membership: {
    level: 1 | 2 | 3 | 4;
    plan: 'FREE' | 'STARTER' | 'PRO' | 'MENTOR';
  };
  isOwner: boolean;
}

export interface AuthenticatedRequest extends Request {
  user?: JWTPayload;
}

export function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const token = req.cookies.baseup_token;

  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const jwtSecret = process.env.JWT_SECRET || 'super_secret_jwt_for_baseup';
    const decoded = jwt.verify(token, jwtSecret) as JWTPayload;
    req.user = decoded;
    next();
  } catch (error) {
    res.clearCookie('baseup_token', { path: '/' });
    return res.status(401).json({ error: 'Invalid token' });
  }
}
