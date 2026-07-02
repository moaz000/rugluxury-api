import type { Request, Response, NextFunction } from "express"
import jwt from "jsonwebtoken"
import { config } from "../config"

export interface AuthRequest extends Request {
  user?: { id: string; role: string; name: string; email: string }
}

export function authenticate(req: AuthRequest, res: Response, next: NextFunction) {
  const token = req.cookies?.token || req.headers.authorization?.replace("Bearer ", "")
  if (!token) return res.status(401).json({ error: "Authentication required" })

  try {
    const decoded = jwt.verify(token, config.jwtSecret) as AuthRequest["user"]
    req.user = decoded
    next()
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" })
  }
}

export function authorize(...roles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ error: "Authentication required" })
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Insufficient permissions" })
    next()
  }
}
