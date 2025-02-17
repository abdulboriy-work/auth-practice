import nodemailer from 'nodemailer';
import { config } from '../config/config';

const transporter = nodemailer.createTransport({
  service: config.emailService,
  auth: {
    user: config.emailUser,
    pass: config.emailPassword,
  },
});

export const sendResetPasswordEmail = async (
  email: string,
  resetToken: string,
) => {
  const resetUrl = `http://localhost:5173/reset-password?token=${resetToken}`;

  const mailOptions = {
    from: config.emailUser,
    to: email,
    subject: 'Password Reset Request',
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h1 style="color: #4CAF50;">You requested a password reset</h1>
        <p>Click this link to reset your password:</p>
        <a href="${resetUrl}" style="color: #1E90FF; text-decoration: none;">${resetUrl}</a>
        <p style="font-size: 0.9em; color: #555;">This link will expire in 30 minutes</p>
        <p style="font-size: 0.9em; color: #555;">If you didn't request this, please ignore this email</p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
};
