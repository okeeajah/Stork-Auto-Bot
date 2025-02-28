const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const { HttpsProxyAgent }= require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

global.navigator = { userAgent: 'node' };

// Load configuration from config.json
function loadConfig() {
  try {
    const configPath = path.join(__dirname, 'config.json');
    if (!fs.existsSync(configPath)) {
      log(`Config file not found at ${configPath}, using default configuration`, 'WARN');
      // Create default config file if it doesn't exist
      const defaultConfig = {
        accounts: [
          {
            region: 'ap-northeast-1',
            clientId: '5msns4n49hmg3dftp2tp1t2iuh',
            userPoolId: 'ap-northeast-1_M22I44OpC',
            username: '',  // To be filled by user
            password: ''   // To be filled by user
          }
        ],
        stork: {
          intervalSeconds: 10
        },
        threads: {
          maxWorkers: 10,
          proxyFile: 'proxies.txt'
        }
      };
      fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2), 'utf8');
      return defaultConfig;
    }

    const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    log('Configuration loaded successfully from config.json');
    return userConfig;
  } catch (error) {
    log(`Error loading config: ${error.message}`, 'ERROR');
    throw new Error('Failed to load configuration');
  }
}

function validateAccountConfig(cognitoConfig) {
  if (!cognitoConfig.username || !cognitoConfig.password) {
    log('ERROR: Username and password must be set in config.json', 'ERROR');
    console.log('\nPlease update your config.json file with your credentials:');
    console.log(JSON.stringify({
      accounts: [{
        username: "YOUR_EMAIL",
        password: "YOUR_PASSWORD"
      }]
    }, null, 2));
    return false;
  }
  return true;
}

function getTimestamp() {
  const now = new Date();
  return now.toISOString().replace('T', ' ').substr(0, 19);
}

function getFormattedDate() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
}

function log(message, type = 'INFO') {
  console.log(`[${getFormattedDate()}] [${type}] ${message}`);
}

function loadProxies(config) {
  try {
    const proxyFile = path.join(__dirname, config.threads.proxyFile);
    if (!fs.existsSync(proxyFile)) {
      log(`Proxy file not found at ${proxyFile}, creating empty file`, 'WARN');
      fs.writeFileSync(proxyFile, '', 'utf8');
      return [];
    }
    const proxyData = fs.readFileSync(proxyFile, 'utf8');
    const proxies = proxyData
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    log(`Loaded ${proxies.length} proxies from ${proxyFile}`);
    return proxies;
  } catch (error) {
    log(`Error loading proxies: ${error.message}`, 'ERROR');
    return [];
  }
}

class CognitoAuth {
  constructor(config) {
    this.config = config;
    this.userPool = new AmazonCognitoIdentity.CognitoUserPool({
      UserPoolId: config.cognito.userPoolId,
      ClientId: config.cognito.clientId
    });
  }

  authenticate(username, password) {
    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
      Username: username,
      Password: password
    });
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
      Username: username,
      Pool: this.userPool
    });

    return new Promise((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (result) => resolve({
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: result.getRefreshToken().getToken(),
          expiresIn: result.getAccessToken().getExpiration() * 1000 - Date.now()
        }),
        onFailure: (err) => reject(err),
        newPasswordRequired: () => reject(new Error('New password required'))
      });
    });
  }

  refreshSession(refreshToken) {
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
      Username: this.config.cognito.username,
      Pool: this.userPool
    });
    const refreshTokenObj = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: refreshToken });
    return new Promise((resolve, reject) => {
      cognitoUser.refreshSession(refreshTokenObj, (err, result) => {
        if (err) reject(err);
        else resolve({
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: refreshToken,
          expiresIn: result.getAccessToken().getExpiration() * 1000 - Date.now()
        });
      });
    });
  }
}

class TokenManager {
  constructor(config) {
    this.config = config;
    this.accessToken = null;
    this.refreshToken = null;
    this.idToken = null;
    this.expiresAt = null;
    this.auth = new CognitoAuth(config);
    this.tokenPath = path.join(__dirname, `tokens_${config.cognito.username.replace(/[^a-zA-Z0-9]/g, '_')}.json`); // Unique token path per account
  }

  async getValidToken() {
    if (!this.accessToken || this.isTokenExpired()) await this.refreshOrAuthenticate();
    return this.accessToken;
  }

  isTokenExpired() {
    return Date.now() >= this.expiresAt;
  }

  async refreshOrAuthenticate() {
    try {
      let tokens = await this.loadTokens();
      let result;

      if (tokens && tokens.refreshToken) {
        try {
          result = await this.auth.refreshSession(tokens.refreshToken);
        } catch (refreshError) {
          log(`Token refresh failed for ${this.config.cognito.username}: ${refreshError.message}, attempting authentication`, 'WARN');
          result = await this.auth.authenticate(this.config.cognito.username, this.config.cognito.password);
        }
      } else {
        result = await this.auth.authenticate(this.config.cognito.username, this.config.cognito.password);
      }

      await this.updateTokens(result);
    } catch (error) {
      log(`Token refresh/auth error for ${this.config.cognito.username}: ${error.message}`, 'ERROR');
      throw error;
    }
  }

  async updateTokens(result) {
    this.accessToken = result.accessToken;
    this.idToken = result.idToken;
    this.refreshToken = result.refreshToken;
    this.expiresAt = Date.now() + result.expiresIn;
    const tokens = { accessToken: this.accessToken, idToken: this.idToken, refreshToken: this.refreshToken, isAuthenticated: true, isVerifying: false };
    await this.saveTokens(tokens);
    log(`Tokens updated and saved to ${this.tokenPath} for ${this.config.cognito.username}`);
  }

  async loadTokens() {
    try {
      if (!fs.existsSync(this.tokenPath)) {
        return null;
      }
      const tokensData = await fs.promises.readFile(this.tokenPath, 'utf8');
      const tokens = JSON.parse(tokensData);
      log(`Successfully read tokens from ${this.tokenPath} for ${this.config.cognito.username}`);
      return tokens;
    } catch (error) {
      log(`Error reading tokens from ${this.tokenPath} for ${this.config.cognito.username}: ${error.message}`, 'ERROR');
      return null;
    }
  }

  async saveTokens(tokens) {
    try {
      await fs.promises.writeFile(this.tokenPath, JSON.stringify(tokens, null, 2), 'utf8');
      log(`Tokens saved successfully to ${this.tokenPath} for ${this.config.cognito.username}`);
      return true;
    } catch (error) {
      log(`Error saving tokens to ${this.tokenPath} for ${this.config.cognito.username}: ${error.message}`, 'ERROR');
      return false;
    }
  }
}

function getProxyAgent(proxy) {
  if (!proxy) return null;
  if (proxy.startsWith('http')) return new HttpsProxyAgent(proxy);
  if (proxy.startsWith('socks4') || proxy.startsWith('socks5')) return new SocksProxyAgent(proxy);
  throw new Error(`Unsupported proxy protocol: ${proxy}`);
}

async function refreshTokens(refreshToken, config) {
  try {
    log('Refreshing access token via Stork API...');
    const response = await axios({
      method: 'POST',
      url: `https://api.jp.stork-oracle.network/auth/refresh`,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
        'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl'
      },
      data: { refresh_token: refreshToken }
    });
    const tokens = {
      accessToken: response.data.access_token,
      idToken: response.data.id_token || '',
      refreshToken: response.data.refresh_token || refreshToken,
      isAuthenticated: true,
      isVerifying: false
    };
    return tokens;
  } catch (error) {
    log(`Token refresh failed: ${error.message}`, 'ERROR');
    throw error;
  }
}

async function getSignedPrices(tokens, config) {
  try {
    log('Fetching signed prices data...');
    const response = await axios({
      method: 'GET',
      url: 'https://app-api.jp.stork-oracle.network/v1/stork_signed_prices',
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
      }
    });
    const dataObj = response.data.data;
    const result = Object.keys(dataObj).map(assetKey => {
      const assetData = dataObj[assetKey];
      return {
        asset: assetKey,
        msg_hash: assetData.timestamped_signature.msg_hash,
        price: assetData.price,
        timestamp: new Date(assetData.timestamped_signature.timestamp / 1000000).toISOString(),
        ...assetData
      };
    });
    log(`Successfully retrieved ${result.length} signed prices`);
    return result;
  } catch (error) {
    log(`Error getting signed prices: ${error.message}`, 'ERROR');
    throw error;
  }
}

async function sendValidation(tokens, msgHash, isValid, proxy) {
  try {
    const agent = getProxyAgent(proxy);
    const response = await axios({
      method: 'POST',
      url: 'https://app-api.jp.stork-oracle.network/v1/stork_signed_prices/validations',
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
      },
      httpsAgent: agent,
      data: { msg_hash: msgHash, valid: isValid }
    });
    log(`✓ Validation successful for ${msgHash.substring(0, 10)}... via ${proxy || 'direct'}`);
    return response.data;
  } catch (error) {
    log(`✗ Validation failed for ${msgHash.substring(0, 10)}...: ${error.message}`, 'ERROR');
    throw error;
  }
}

async function getUserStats(tokens) {
  try {
    log('Fetching user stats...');
    const response = await axios({
      method: 'GET',
      url: 'https://app-api.jp.stork-oracle.network/v1/me',
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
      }
    });
    return response.data.data;
  } catch (error) {
    log(`Error getting user stats: ${error.message}`, 'ERROR');
    throw error;
  }
}

function validatePrice(priceData) {
  try {
    log(`Validating data for ${priceData.asset || 'unknown asset'}`);
    if (!priceData.msg_hash || !priceData.price || !priceData.timestamp) {
      log('Incomplete data, considered invalid', 'WARN');
      return false;
    }
    const currentTime = Date.now();
    const dataTime = new Date(priceData.timestamp).getTime();
    const timeDiffMinutes = (currentTime - dataTime) / (1000 * 60);
    if (timeDiffMinutes > 60) {
      log(`Data too old (${Math.round(timeDiffMinutes)} minutes ago)`, 'WARN');
      return false;
    }
    return true;
  } catch (error) {
    log(`Validation error: ${error.message}`, 'ERROR');
    return false;
  }
}

if (!isMainThread) {
  const { priceData, tokens, proxy } = workerData;

  async function validateAndSend() {
    try {
      const isValid = validatePrice(priceData);
      await sendValidation(tokens, priceData.msg_hash, isValid, proxy);
      parentPort.postMessage({ success: true, msgHash: priceData.msg_hash, isValid });
    } catch (error) {
      parentPort.postMessage({ success: false, error: error.message, msgHash: priceData.msg_hash });
    }
  }

  validateAndSend();
} else {
  let previousStats = { validCount: 0, invalidCount: 0 };

  async function runValidationProcess(tokenManager, config) {
    try {
      log(`--------- STARTING VALIDATION PROCESS for ${config.cognito.username} ---------`);
      const tokens = await getTokens(config);
      const initialUserData = await getUserStats(tokens);

      if (!initialUserData || !initialUserData.stats) {
        throw new Error('Could not fetch initial user stats');
      }

      const initialValidCount = initialUserData.stats.stork_signed_prices_valid_count || 0;
      const initialInvalidCount = initialUserData.stats.stork_signed_prices_invalid_count || 0;

      if (previousStats.validCount === 0 && previousStats.invalidCount === 0) {
        previousStats.validCount = initialValidCount;
        previousStats.invalidCount = initialInvalidCount;
      }

      const signedPrices = await getSignedPrices(tokens, config);
      const proxies = loadProxies(config);

      if (!signedPrices || signedPrices.length === 0) {
        log('No data to validate');
        const userData = await getUserStats(tokens);
        displayStats(userData, config);
        return;
      }

      log(`Processing ${signedPrices.length} data points with ${config.threads.maxWorkers} workers...`);
      const workers = [];

      const chunkSize = Math.ceil(signedPrices.length / config.threads.maxWorkers);
      const batches = [];
      for (let i = 0; i < signedPrices.length; i += chunkSize) {
        batches.push(signedPrices.slice(i, i + chunkSize));
      }

      for (let i = 0; i < Math.min(batches.length, config.threads.maxWorkers); i++) {
        const batch = batches[i];
        const proxy = proxies.length > 0 ? proxies[i % proxies.length] : null;

        batch.forEach(priceData => {
          workers.push(new Promise((resolve) => {
            const worker = new Worker(__filename, {
              workerData: { priceData, tokens, proxy }
            });
            worker.on('message', resolve);
            worker.on('error', (error) => resolve({ success: false, error: error.message }));
            worker.on('exit', () => resolve({ success: false, error: 'Worker exited' }));
          }));
        });
      }

      const results = await Promise.all(workers);
      const successCount = results.filter(r => r.success).length;
      log(`Processed ${successCount}/${results.length} validations successfully`);

      const updatedUserData = await getUserStats(tokens);
      const newValidCount = updatedUserData.stats.stork_signed_prices_valid_count || 0;
      const newInvalidCount = updatedUserData.stats.stork_signed_prices_invalid_count || 0;

      const actualValidIncrease = newValidCount - previousStats.validCount;
      const actualInvalidIncrease = newInvalidCount - previousStats.invalidCount;

      previousStats.validCount = newValidCount;
      previousStats.invalidCount = newInvalidCount;

      displayStats(updatedUserData, config);
      log(`--------- VALIDATION SUMMARY ---------`);
      log(`Total data processed: ${actualValidIncrease + actualInvalidIncrease}`);
      log(`Successful: ${actualValidIncrease}`);
      log(`Failed: ${actualInvalidIncrease}`);
      log('--------- COMPLETE ---------');
    } catch (error) {
      log(`Validation process stopped: ${error.message}`, 'ERROR');
    }
  }

  async function getTokens(config) {
    const tokenManager = new TokenManager(config);
    try {
      await tokenManager.getValidToken();
      const tokensData = await tokenManager.loadTokens();
      if (!tokensData || !tokensData.accessToken) {
        throw new Error('No valid access token found');
      }
      return tokensData;
    } catch (error) {
      log(`Error getting tokens: ${error.message}`, 'ERROR');
      throw error;
    }
  }

  function displayStats(userData, config) {
    if (!userData || !userData.stats) {
      log('No valid stats data available to display', 'WARN');
      return;
    }

    console.clear();
    console.log('=============================================');
    console.log('   STORK ORACLE AUTO BOT - AIRDROP INSIDERS  ');
    console.log('=============================================');
    console.log(`Time: ${getTimestamp()}`);
    console.log('---------------------------------------------');
    console.log(`User: ${userData.email || 'N/A'}`);
    console.log(`ID: ${userData.id || 'N/A'}`);
    console.log(`Referral Code: ${userData.referral_code || 'N/A'}`);
    console.log('---------------------------------------------');
    console.log('VALIDATION STATISTICS:');
    console.log(`✓ Valid Validations: ${userData.stats.stork_signed_prices_valid_count || 0}`);
    console.log(`✗ Invalid Validations: ${userData.stats.stork_signed_prices_invalid_count || 0}`);
    console.log(`↻ Last Validated At: ${userData.stats.stork_signed_prices_last_verified_at || 'Never'}`);
    console.log(`👥 Referral Usage Count: ${userData.stats.referral_usage_count || 0}`);
    console.log('---------------------------------------------');
    console.log(`Next validation in ${config.stork.intervalSeconds} seconds...`);
    console.log('=============================================');
  }

  async function main() {
    const userConfig = loadConfig();

    if (!userConfig.accounts || userConfig.accounts.length === 0) {
      log('No accounts configured in config.json', 'ERROR');
      process.exit(1);
    }

    for (const account of userConfig.accounts) {
      const config = {
        cognito: {
          region: account.region,
          clientId: account.clientId,
          userPoolId: account.userPoolId,
          username: account.username,
          password: account.password
        },
        stork: userConfig.stork,
        threads: userConfig.threads
      };

      if (!validateAccountConfig(config.cognito)) {
        log(`Invalid configuration for account ${account.username}`, 'ERROR');
        continue;
      }

      const tokenManager = new TokenManager(config);

      try {
        await tokenManager.getValidToken();
        log(`Authentication successful for ${account.username}`);
        
        runValidationProcess(tokenManager, config);
      } catch (error) {
        log(`Error with account ${account.username}: ${error.message}`, 'ERROR');
      }
    }
  }

  main();
}
