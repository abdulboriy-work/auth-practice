import { Request, Response } from 'express';
import jwt, { SignOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { User } from '../models/user.model';
import { config } from '../config/config';
import { sendResetPasswordEmail } from '../utils/email';

export class AuthController {
  static async register(req: Request, res: Response) {
    try {
      const { email, password } = req.body;

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        res
          .status(400)
          .json({ message: 'Email already registered', statusCode: 400 });
        return;
      }

      const user = new User({ email, password });
      await user.save();

      const accessToken = jwt.sign(
        { userId: user._id, role: user.role },
        config.jwtSecret as jwt.Secret,
        { expiresIn: config.jwtExpiresIn } as SignOptions,
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        config.jwtRefreshSecret as jwt.Secret,
        { expiresIn: config.jwtRefreshExpiresIn } as SignOptions,
      );

      user.refreshToken = refreshToken;
      await user.save();

      res.status(201).json({
        message: 'User registered successfully',
        accessToken,
        refreshToken,
        statusCode: 201,
      });
    } catch (error) {
      res
        .status(500)
        .json({ message: 'Error registering user', statusCode: 500 });
    }
  }

  static async login(req: Request, res: Response) {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        res
          .status(401)
          .json({ message: 'Invalid credentials', statusCode: 401 });
        return;
      }

      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        res.status(401).json({ message: 'Invalid credentials' });
        return;
      }

      const accessToken = jwt.sign(
        { userId: user._id, role: user.role },
        config.jwtSecret as jwt.Secret,
        { expiresIn: config.jwtExpiresIn } as SignOptions,
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        config.jwtRefreshSecret as jwt.Secret,
        { expiresIn: config.jwtRefreshExpiresIn } as SignOptions,
      );

      user.refreshToken = refreshToken;
      await user.save();

      res.json({
        accessToken,
        refreshToken,
        statusCode: 200,
      });
    } catch (error) {
      res.status(500).json({ message: 'Error logging in', statusCode: 500 });
    }
  }

  static async refreshToken(req: Request, res: Response) {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        res
          .status(401)
          .json({ message: 'Refresh token is required', statusCode: 401 });
        return;
      }

      const user = await User.findOne({ refreshToken });
      if (!user) {
        res.status(403).json({ message: 'Invalid refresh token' });
        return;
      }

      try {
        jwt.verify(refreshToken, config.jwtRefreshSecret as jwt.Secret);
      } catch (error) {
        user.refreshToken = undefined;
        await user.save();
        res.status(403).json({ message: 'Invalid refresh token' });
        return;
      }

      const accessToken = jwt.sign(
        { userId: user._id, role: user.role },
        config.jwtSecret as jwt.Secret,
        { expiresIn: config.jwtExpiresIn } as SignOptions,
      );

      const newRefreshToken = jwt.sign(
        { userId: user._id },
        config.jwtRefreshSecret as jwt.Secret,
        { expiresIn: config.jwtRefreshExpiresIn } as SignOptions,
      );

      user.refreshToken = newRefreshToken;
      await user.save();

      res.json({ accessToken, refreshToken: newRefreshToken, statusCode: 200 });
    } catch (error) {
      res
        .status(500)
        .json({ message: 'Error refreshing token', statusCode: 500 });
    }
  }

  static async forgotPassword(req: Request, res: Response) {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email });

      if (!user) {
        res.status(404).json({ message: 'User not found', statusCode: 404 });
        return;
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      user.resetPasswordToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
      user.resetPasswordExpires = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

      await user.save();

      await sendResetPasswordEmail(user.email, resetToken);

      res.json({ message: 'Password reset email sent', statusCode: 200 });
    } catch (error) {
      res
        .status(500)
        .json({ message: 'Error sending reset email', statusCode: 500 });
    }
  }

  static async resetPassword(req: Request, res: Response) {
    try {
      const { token, newPassword } = req.body;

      const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      const user = await User.findOne({
        resetPasswordToken: hashedToken,
        resetPasswordExpires: { $gt: Date.now() },
      });

      if (!user) {
        res.status(400).json({ message: 'Invalid or expired reset token' });
        return;
      }

      user.password = newPassword;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      res.json({ message: 'Password reset successful', statusCode: 200 });
    } catch (error) {
      res
        .status(500)
        .json({ message: 'Error resetting password', statusCode: 500 });
    }
  }

  static async logout(req: Request, res: Response) {
    try {
      const { refreshToken } = req.body;

      const user = await User.findOne({ refreshToken });
      if (user) {
        user.refreshToken = undefined;
        await user.save();
      }

      res.json({ message: 'Logged out successfully', statusCode: 200 });
    } catch (error) {
      res.status(500).json({ message: 'Error logging out', statusCode: 500 });
    }
  }

  static async verifyToken(req: Request, res: Response) {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res
          .status(401)
          .json({ message: 'No token provided', statusCode: 401 });
      }

      const token = authHeader.split(' ')[1];

      try {
        const decoded = jwt.verify(
          token,
          config.jwtSecret as jwt.Secret,
        ) as jwt.JwtPayload;
        const user = await User.findById(decoded.userId, {
          password: 0,
          refreshToken: 0,
          __v: 0,
          _id: 0,
        });
        res.json({ valid: true, user, statusCode: 200 });
      } catch (error) {
        res.status(401).json({ valid: false, message: 'Invalid token' });
      }
    } catch (error) {
      res
        .status(500)
        .json({ message: 'Error verifying token', statusCode: 500 });
    }
  }
}
