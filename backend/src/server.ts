import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import webauthnRoutes from './routes/webauthn';

dotenv.config();

const app = express();
const PORT = 3001;

export const pool = new Pool({
  host: 'localhost',
  port: 5000,
  database: 'passwordless_auth',
  user: 'postgres',
  password: process.env.DB_PASSWORD,
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ DATABASE CONNECTION FAILED!');
    console.error('Error:', err.message);
    console.error('💡 Check your password in .env file');
    process.exit(1);
  } else {
    console.log('✅ Database connected successfully!');
    release();
  }
});

app.use(helmet());
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(express.json());

app.use('/api/webauthn', webauthnRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', database: 'connected', timestamp: new Date() });
});

app.get('/api/test', (req, res) => {
  res.json({ message: '🚀 Backend is working perfectly!' });
});

app.listen(PORT, () => {
  console.log('\n' + '='.repeat(50));
  console.log('🚀 PASSWORDLESS AUTH SERVER STARTED!');
  console.log('='.repeat(50));
  console.log(`📡 Server URL: http://localhost:${PORT}`);
  console.log(`🧪 Health Check: http://localhost:${PORT}/health`);
  console.log(`🔐 WebAuthn API: http://localhost:${PORT}/api/webauthn`);
  console.log('='.repeat(50) + '\n');
});

export default app;