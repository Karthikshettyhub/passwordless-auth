import express from 'express';
import { 
  generateRegistrationOptions, 
  verifyRegistrationResponse, 
  generateAuthenticationOptions, 
  verifyAuthenticationResponse 
} from '@simplewebauthn/server';
import { pool } from '../server';
import crypto from 'crypto';

const router = express.Router();
const rpName = 'Passwordless Auth System';
const rpID = 'localhost';
const origin = 'http://localhost:5173';

console.log('🔐 WebAuthn routes loaded');

// REGISTER - Step 1: Generate Options
router.post('/register/options', async (req, res) => {
  try {
    const { email, username } = req.body;
    
    if (!email || !username) {
      return res.status(400).json({ error: 'Email and username required' });
    }

    console.log(`📝 Registration request for: ${email}`);

    let userResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    let userId: string;

    if (userResult.rows.length === 0) {
      const newUser = await pool.query(
        'INSERT INTO users (email, username, display_name) VALUES ($1, $2, $3) RETURNING id',
        [email, username, username]
      );
      userId = newUser.rows[0].id;
      console.log(`✅ Created new user: ${email}`);
    } else {
      userId = userResult.rows[0].id;
      console.log(`ℹ️  Existing user: ${email}`);
    }

    // Get existing credentials
    const existingCreds = await pool.query(
      'SELECT credential_id FROM webauthn_credentials WHERE user_id = $1',
      [userId]
    );

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: userId,
      userName: email,
      attestationType: 'none',
      excludeCredentials: existingCreds.rows.map((cred: any) => ({
        id: cred.credential_id,
        type: 'public-key' as const,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    await pool.query(
      'INSERT INTO auth_challenges (user_id, challenge, challenge_type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'5 minutes\')',
      [userId, options.challenge, 'webauthn']
    );

    console.log(`🔑 Generated registration challenge for user ${userId}`);
    res.json({ options, userId });
  } catch (error: any) {
    console.error('❌ Registration options error:', error);
    res.status(500).json({ error: 'Failed to generate registration options', details: error.message });
  }
});

// REGISTER - Step 2: Verify Credential
router.post('/register/verify', async (req, res) => {
  try {
    const { userId, credential, deviceName } = req.body;
    
    if (!userId || !credential) {
      return res.status(400).json({ error: 'Missing userId or credential' });
    }

    console.log(`🔍 Verifying registration for user: ${userId}`);

    const challengeResult = await pool.query(
      'SELECT challenge FROM auth_challenges WHERE user_id = $1 AND challenge_type = $2 AND used = false AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
      [userId, 'webauthn']
    );

    if (challengeResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    const expectedChallenge = challengeResult.rows[0].challenge;

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    if (!verification.verified) {
      console.log('❌ Registration verification failed');
      return res.status(400).json({ error: 'Registration verification failed' });
    }

    const regInfo = verification.registrationInfo;
    if (!regInfo) {
      return res.status(400).json({ error: 'Registration info missing' });
    }

    // Store credential
    await pool.query(
      'INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, device_name, device_type) VALUES ($1, $2, $3, $4, $5, $6)',
      [
        userId,
        credential.id,
        Buffer.from(regInfo.credentialPublicKey).toString('base64'),
        regInfo.counter,
        deviceName || 'Unknown Device',
        'platform'
      ]
    );

    await pool.query(
      'UPDATE auth_challenges SET used = true WHERE user_id = $1 AND challenge = $2',
      [userId, expectedChallenge]
    );

    const sessionToken = crypto.randomBytes(32).toString('base64url');
    await pool.query(
      'INSERT INTO sessions (user_id, session_token, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'7 days\')',
      [userId, sessionToken]
    );

    console.log(`✅ Registration successful for user: ${userId}`);
    res.json({ success: true, sessionToken, message: 'Registration successful!' });
  } catch (error: any) {
    console.error('❌ Registration verification error:', error);
    res.status(500).json({ error: 'Registration verification failed', details: error.message });
  }
});

// LOGIN - Step 1: Generate Options
router.post('/authenticate/options', async (req, res) => {
  try {
    const { email } = req.body;
    
    console.log(`🔐 Authentication request for: ${email || 'discoverable credential'}`);

    let userId = null;
    let allowCredentials: any[] = [];

    if (email) {
      const result = await pool.query(
        'SELECT wc.credential_id, u.id FROM webauthn_credentials wc JOIN users u ON wc.user_id = u.id WHERE u.email = $1',
        [email]
      );
      
      if (result.rows.length > 0) {
        userId = result.rows[0].id;
        allowCredentials = result.rows.map((row: any) => ({
          id: row.credential_id,
          type: 'public-key' as const,
        }));
      }
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
      userVerification: 'preferred',
    });

    await pool.query(
      'INSERT INTO auth_challenges (user_id, challenge, challenge_type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'5 minutes\')',
      [userId, options.challenge, 'webauthn']
    );

    console.log(`🔑 Generated authentication challenge`);
    res.json({ options });
  } catch (error: any) {
    console.error('❌ Authentication options error:', error);
    res.status(500).json({ error: 'Failed to generate authentication options', details: error.message });
  }
});

// LOGIN - Step 2: Verify Credential
router.post('/authenticate/verify', async (req, res) => {
  try {
    const { credential } = req.body;
    
    if (!credential) {
      return res.status(400).json({ error: 'Missing credential' });
    }

    console.log(`🔍 Verifying authentication...`);

    const credResult = await pool.query(
      'SELECT wc.*, u.id as user_id, u.email, u.username FROM webauthn_credentials wc JOIN users u ON wc.user_id = u.id WHERE wc.credential_id = $1',
      [credential.id]
    );

    if (credResult.rows.length === 0) {
      return res.status(400).json({ error: 'Credential not found' });
    }

    const dbCred = credResult.rows[0];
    
    const challengeResult = await pool.query(
      'SELECT challenge FROM auth_challenges WHERE challenge_type = $1 AND used = false AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
      ['webauthn']
    );

    if (challengeResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    const authenticator = {
      credentialID: dbCred.credential_id,
      credentialPublicKey: Buffer.from(dbCred.public_key, 'base64'),
      counter: dbCred.counter,
    };

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challengeResult.rows[0].challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Authentication failed' });
    }

    await pool.query(
      'UPDATE webauthn_credentials SET counter = $1, last_used = NOW() WHERE credential_id = $2',
      [verification.authenticationInfo.newCounter, credential.id]
    );

    await pool.query(
      'UPDATE auth_challenges SET used = true WHERE challenge = $1',
      [challengeResult.rows[0].challenge]
    );

    const sessionToken = crypto.randomBytes(32).toString('base64url');
    await pool.query(
      'INSERT INTO sessions (user_id, session_token, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'7 days\')',
      [dbCred.user_id, sessionToken]
    );

    console.log(`✅ Authentication successful for: ${dbCred.email}`);
    res.json({
      success: true,
      sessionToken,
      user: { id: dbCred.user_id, email: dbCred.email, username: dbCred.username }
    });
  } catch (error: any) {
    console.error('❌ Authentication verification error:', error);
    res.status(500).json({ error: 'Authentication verification failed', details: error.message });
  }
});

export default router;