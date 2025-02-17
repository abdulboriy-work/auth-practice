import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import { config } from './config/config';
import authRoutes from './routes/auth.routes';

const app = express();

app.use(cors());
app.use(express.json());

mongoose
  .connect(config.mongoUri)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

app.use('/api/auth', authRoutes);

app.listen(config.port, () => {
  console.log(`Server running on port ${config.port}`);
});
