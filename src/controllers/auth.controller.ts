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
        res.status(400).json({ message: 'Email already registered' });
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
      });
    } catch (error) {
      res.status(500).json({ message: 'Error registering user' });
    }
  }

  static async login(req: Request, res: Response) {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        res.status(401).json({ message: 'Invalid credentials' });
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

      res.json({ accessToken, refreshToken });
    } catch (error) {
      res.status(500).json({ message: 'Error logging in' });
    }
  }

  static async refreshToken(req: Request, res: Response) {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        res.status(401).json({ message: 'Refresh token is required' });
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

      res.json({ accessToken, refreshToken: newRefreshToken });
    } catch (error) {
      res.status(500).json({ message: 'Error refreshing token' });
    }
  }

  static async forgotPassword(req: Request, res: Response) {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email });

      if (!user) {
        res.status(404).json({ message: 'User not found' });
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

      res.json({ message: 'Password reset email sent' });
    } catch (error) {
      res.status(500).json({ message: 'Error sending reset email' });
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

      res.json({ message: 'Password reset successful' });
    } catch (error) {
      res.status(500).json({ message: 'Error resetting password' });
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

      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Error logging out' });
    }
  }
}
