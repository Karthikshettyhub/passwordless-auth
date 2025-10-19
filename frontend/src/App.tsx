import { useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import axios from 'axios';
import './App.css';

const API_URL = 'http://localhost:3001/api';

function App() {
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [sessionToken, setSessionToken] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async () => {
    try {
      setLoading(true);
      setMessage('🔄 Starting registration...');
      
      const optionsRes = await axios.post(`${API_URL}/webauthn/register/options`, {
        email,
        username,
        displayName: username,
      });

      const { options, userId } = optionsRes.data;

      setMessage('👆 Please authenticate with your device...');
      const credential = await startRegistration(options);

      setMessage('🔄 Verifying...');
      const verifyRes = await axios.post(`${API_URL}/webauthn/register/verify`, {
        userId,
        credential,
        deviceName: 'My Device',
      });

      setSessionToken(verifyRes.data.sessionToken);
      setIsLoggedIn(true);
      setMessage('✅ Registration successful! 🎉');
    } catch (error: any) {
      console.error('Registration error:', error);
      setMessage('❌ Error: ' + (error.response?.data?.error || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    try {
      setLoading(true);
      setMessage('🔄 Starting login...');

      const optionsRes = await axios.post(`${API_URL}/webauthn/authenticate/options`, {
        email,
      });

      setMessage('👆 Authenticate with your device...');
      const credential = await startAuthentication(optionsRes.data.options);

      setMessage('🔄 Verifying...');
      const verifyRes = await axios.post(`${API_URL}/webauthn/authenticate/verify`, {
        credential,
      });

      setSessionToken(verifyRes.data.sessionToken);
      setIsLoggedIn(true);
      setMessage('✅ Login successful! Welcome back! 🎉');
    } catch (error: any) {
      console.error('Login error:', error);
      setMessage('❌ Error: ' + (error.response?.data?.error || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setSessionToken('');
    setEmail('');
    setUsername('');
    setMessage('👋 Logged out');
  };

  return (
    <div className="App">
      <div className="container">
        <h1>🔐 Passwordless Authentication</h1>
        <p className="subtitle">Secure login with biometrics - no passwords!</p>

        {!isLoggedIn ? (
          <div className="auth-form">
            <input
              type="email"
              placeholder="Email (e.g., user@example.com)"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading}
            />
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={loading}
            />

            <div className="button-group">
              <button onClick={handleRegister} disabled={!email || !username || loading}>
                {loading ? '⏳ Processing...' : '🆕 Register'}
              </button>
              <button onClick={handleLogin} disabled={!email || loading}>
                {loading ? '⏳ Processing...' : '🔑 Login'}
              </button>
            </div>
          </div>
        ) : (
          <div className="success-card">
            <h2>Welcome, {username}! 🎉</h2>
            <p><strong>Email:</strong> {email}</p>
            <p className="token"><strong>Session:</strong> {sessionToken.slice(0, 30)}...</p>
            <button onClick={handleLogout}>Logout</button>
          </div>
        )}

        {message && (
          <div className={`message ${message.includes('❌') ? 'error' : 'success'}`}>
            {message}
          </div>
        )}

        <div className="info-box">
          <h3>✨ How it works:</h3>
          <ol>
            <li><strong>Register:</strong> Create account with biometric authentication</li>
            <li><strong>Login:</strong> Just your email + biometric verification</li>
            <li><strong>Secure:</strong> No passwords to steal or forget!</li>
          </ol>
        </div>

        <div className="tech-info">
          <p>🛠️ Built with: React + TypeScript + Node.js + PostgreSQL + WebAuthn (FIDO2)</p>
        </div>
      </div>
    </div>
  );
}

export default App;