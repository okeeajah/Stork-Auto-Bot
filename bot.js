const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

global.navigator = { userAgent: 'node' };

// Color codes for console output
const colors = {
    RESET: "\x1b[0m",
    BRIGHT: "\x1b[1m",
    DIM: "\x1b[2m",
    UNDERSCORE: "\x1b[4m",
    BLINK: "\x1b[5m",
    REVERSE: "\x1b[7m",
    HIDDEN: "\x1b[8m",
    FG_BLACK: "\x1b[30m",
    FG_RED: "\x1b[31m",
    FG_GREEN: "\x1b[32m",
    FG_YELLOW: "\x1b[33m",
    FG_BLUE: "\x1b[34m",
    FG_MAGENTA: "\x1b[35m",
    FG_CYAN: "\x1b[36m",
    FG_WHITE: "\x1b[37m",
    BG_BLACK: "\x1b[40m",
    BG_RED: "\x1b[41m",
    BG_GREEN: "\x1b[42m",
    BG_YELLOW: "\x1b[43m",
    BG_BLUE: "\x1b[44m",
    BG_MAGENTA: "\x1b[45m",
    BG_CYAN: "\x1b[46m",
    BG_WHITE: "\x1b[47m"
};

// Load configuration from config.json
function loadConfig() {
    try {
        const configPath = path.join(__dirname, 'config.json');
        if (!fs.existsSync(configPath)) {
            coloredLog(`Config file not found at ${configPath}, using default configuration`, 'WARN');
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
                    maxWorkers: 10
                }
            };
            fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2), 'utf8');
            return defaultConfig;
        }

        const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        coloredLog('Configuration loaded successfully from config.json', 'INFO', 'green');
        return userConfig;
    } catch (error) {
        coloredLog(`Error loading config: ${error.message}`, 'ERROR');
        throw new Error('Failed to load configuration');
    }
}

function validateAccountConfig(cognitoConfig) {
    if (!cognitoConfig.username || !cognitoConfig.password) {
        coloredLog('ERROR: Username and password must be set in config.json', 'ERROR');
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

function coloredLog(message, type = 'INFO', color = 'white') {
    let colorCode = colors.FG_WHITE;
    switch (type) {
        case 'INFO':
            colorCode = colors.FG_GREEN;
            break;
        case 'WARN':
            colorCode = colors.FG_YELLOW;
            break;
        case 'ERROR':
            colorCode = colors.FG_RED;
            break;
        default:
            colorCode = colors.FG_WHITE;
    }
    console.log(`${colors.BRIGHT}[${getFormattedDate()}] ${colorCode}[${type}] ${message}${colors.RESET}`);
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
                    coloredLog(`Token refreshed successfully for ${this.config.cognito.username}`, 'INFO', 'green');
                } catch (refreshError) {
                    coloredLog(`Token refresh failed for ${this.config.cognito.username}: ${refreshError.message}, attempting authentication`, 'WARN');
                    result = await this.auth.authenticate(this.config.cognito.username, this.config.cognito.password);
                }
            } else {
                result = await this.auth.authenticate(this.config.cognito.username, this.config.cognito.password);
            }

            await this.updateTokens(result);
        } catch (error) {
            coloredLog(`Token refresh/auth error for ${this.config.cognito.username}: ${error.message}`, 'ERROR');
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
        coloredLog(`Tokens updated and saved to ${this.tokenPath} for ${this.config.cognito.username}`, 'INFO', 'green');
    }

    async loadTokens() {
        try {
            if (!fs.existsSync(this.tokenPath)) {
                return null;
            }
            const tokensData = await fs.promises.readFile(this.tokenPath, 'utf8');
            const tokens = JSON.parse(tokensData);
            coloredLog(`Successfully read tokens from ${this.tokenPath} for ${this.config.cognito.username}`, 'INFO', 'green');
            return tokens;
        } catch (error) {
            coloredLog(`Error reading tokens from ${this.tokenPath} for ${this.config.cognito.username}: ${error.message}`, 'ERROR');
            return null;
        }
    }

    async saveTokens(tokens) {
        try {
            await fs.promises.writeFile(this.tokenPath, JSON.stringify(tokens, null, 2), 'utf8');
            coloredLog(`Tokens saved successfully to ${this.tokenPath} for ${this.config.cognito.username}`, 'INFO', 'green');
            return true;
        } catch (error) {
            coloredLog(`Error saving tokens to ${this.tokenPath} for ${this.config.cognito.username}: ${error.message}`, 'ERROR');
            return false;
        }
    }
}

async function refreshTokens(refreshToken, config) {
    try {
        coloredLog('Refreshing access token via Stork API...', 'INFO', 'cyan');
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
        coloredLog(`Token refresh failed: ${error.message}`, 'ERROR');
        throw error;
    }
}

async function getSignedPrices(tokens, config) {
    try {
        coloredLog('Fetching signed prices data...', 'INFO', 'cyan');
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
        coloredLog(`Successfully retrieved ${result.length} signed prices`, 'INFO', 'green');
        return result;
    } catch (error) {
        coloredLog(`Error getting signed prices: ${error.message}`, 'ERROR');
        throw error;
    }
}

async function sendValidation(tokens, msgHash, isValid) {
    try {
        const response = await axios({
            method: 'POST',
            url: 'https://app-api.jp.stork-oracle.network/v1/stork_signed_prices/validations',
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Content-Type': 'application/json',
                'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            },
            data: { msg_hash: msgHash, valid: isValid }
        });
        coloredLog(`? Validation successful for ${msgHash.substring(0, 10)}...`, 'INFO', 'green');
        return response.data;
    } catch (error) {
        coloredLog(`? Validation failed for ${msgHash.substring(0, 10)}...: ${error.message}`, 'ERROR');
        throw error;
    }
}

async function getUserStats(tokens) {
    try {
        coloredLog('Fetching user stats...', 'INFO', 'cyan');
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
        coloredLog(`Error getting user stats: ${error.message}`, 'ERROR');
        throw error;
    }
}

function validatePrice(priceData) {
    try {
        coloredLog(`Validating data for ${priceData.asset || 'unknown asset'}`, 'INFO', 'cyan');
        if (!priceData.msg_hash || !priceData.price || !priceData.timestamp) {
            coloredLog('Incomplete data, considered invalid', 'WARN');
            return false;
        }
        const currentTime = Date.now();
        const dataTime = new Date(priceData.timestamp).getTime();
        const timeDiffMinutes = (currentTime - dataTime) / (1000 * 60);
        if (timeDiffMinutes > 60) {
            coloredLog(`Data too old (${Math.round(timeDiffMinutes)} minutes ago)`, 'WARN');
            return false;
        }
        return true;
    } catch (error) {
        coloredLog(`Validation error: ${error.message}`, 'ERROR');
        return false;
    }
}

if (!isMainThread) {
    const { priceData, tokens } = workerData;

    async function validateAndSend() {
        try {
            const isValid = validatePrice(priceData);
            await sendValidation(tokens, priceData.msg_hash, isValid);
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
            coloredLog(`--------- STARTING VALIDATION PROCESS for ${config.cognito.username} ---------`, 'INFO', 'blue');
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

            if (!signedPrices || signedPrices.length === 0) {
                coloredLog('No data to validate', 'WARN');
                const userData = await getUserStats(tokens);
                displayStats(userData, config);
                return;
            }

            coloredLog(`Processing ${signedPrices.length} data points with ${config.threads.maxWorkers} workers...`, 'INFO', 'cyan');
            const workers = [];

            const chunkSize = Math.ceil(signedPrices.length / config.threads.maxWorkers);
            const batches = [];
            for (let i = 0; i < signedPrices.length; i += chunkSize) {
                batches.push(signedPrices.slice(i, i + chunkSize));
            }

            for (let i = 0; i < Math.min(batches.length, config.threads.maxWorkers); i++) {
                const batch = batches[i];

                batch.forEach(priceData => {
                    workers.push(new Promise((resolve) => {
                        const worker = new Worker(__filename, {
                            workerData: { priceData, tokens }
                        });
                        worker.on('message', resolve);
                        worker.on('error', (error) => resolve({ success: false, error: error.message }));
                        worker.on('exit', () => resolve({ success: false, error: 'Worker exited' }));
                    }));
                });
            }

            const results = await Promise.all(workers);
            const successCount = results.filter(r => r.success).length;
            coloredLog(`Processed ${successCount}/${results.length} validations successfully`, 'INFO', 'green');

            const updatedUserData = await getUserStats(tokens);
            const newValidCount = updatedUserData.stats.stork_signed_prices_valid_count || 0;
            const newInvalidCount = updatedUserData.stats.stork_signed_prices_invalid_count || 0;

            const actualValidIncrease = newValidCount - previousStats.validCount;
            const actualInvalidIncrease = newInvalidCount - previousStats.invalidCount;

            previousStats.validCount = newValidCount;
            previousStats.invalidCount = newInvalidCount;

            displayStats(updatedUserData, config);
            coloredLog(`--------- VALIDATION SUMMARY ---------`, 'INFO', 'blue');
            coloredLog(`Total data processed: ${actualValidIncrease + actualInvalidIncrease}`, 'INFO', 'cyan');
            coloredLog(`Successful: ${actualValidIncrease}`, 'INFO', 'green');
            coloredLog(`Failed: ${actualInvalidIncrease}`, 'INFO', 'red');
            coloredLog('--------- COMPLETE ---------', 'INFO', 'blue');
        } catch (error) {
            coloredLog(`Validation process stopped: ${error.message}`, 'ERROR');
        } finally {
            // Immediately reschedule the next run
            setTimeout(() => runValidationProcess(tokenManager, config), 0);  // Run immediately
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
            coloredLog(`Error getting tokens: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    function displayStats(userData, config) {
        if (!userData || !userData.stats) {
            coloredLog('No valid stats data available to display', 'WARN');
            return;
        }

        console.clear();
        console.log(colors.BRIGHT + colors.FG_CYAN + '=============================================' + colors.RESET);
        console.log(colors.BRIGHT + colors.FG_CYAN + '   STORK ORACLE AUTO BOT - AIRDROP INSIDERS  ' + colors.RESET);
        console.log(colors.BRIGHT + colors.FG_CYAN + '=============================================' + colors.RESET);
        console.log(colors.FG_WHITE + `Time: ${getTimestamp()}` + colors.RESET);
        console.log(colors.FG_CYAN + '---------------------------------------------' + colors.RESET);
        console.log(colors.FG_WHITE + `User: ${userData.email || 'N/A'}` + colors.RESET);
        console.log(colors.FG_WHITE + `ID: ${userData.id || 'N/A'}` + colors.RESET);
        console.log(colors.FG_WHITE + `Referral Code: ${userData.referral_code || 'N/A'}` + colors.RESET);
        console.log(colors.FG_CYAN + '---------------------------------------------' + colors.RESET);
        console.log(colors.BRIGHT + colors.FG_GREEN + 'VALIDATION STATISTICS:' + colors.RESET);
        console.log(colors.FG_GREEN + `? Valid Validations: ${userData.stats.stork_signed_prices_valid_count || 0}` + colors.RESET);
        console.log(colors.FG_RED + `? Invalid Validations: ${userData.stats.stork_signed_prices_invalid_count || 0}` + colors.RESET);
        console.log(colors.FG_WHITE + `? Last Validated At: ${userData.stats.stork_signed_prices_last_verified_at || 'Never'}` + colors.RESET);
        console.log(colors.FG_WHITE + `?? Referral Usage Count: ${userData.stats.referral_usage_count || 0}` + colors.RESET);
        console.log(colors.FG_CYAN + '---------------------------------------------' + colors.RESET);
        //Removed: console.log(colors.FG_YELLOW + `Next validation in ${config.stork.intervalSeconds} seconds...` + colors.RESET);
        console.log(colors.BRIGHT + colors.FG_CYAN + '=============================================' + colors.RESET);
    }

    async function main() {
        const userConfig = loadConfig();

        if (!userConfig.accounts || userConfig.accounts.length === 0) {
            coloredLog('No accounts configured in config.json', 'ERROR');
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
                coloredLog(`Invalid configuration for account ${account.username}`, 'ERROR');
                continue;
            }

            const tokenManager = new TokenManager(config);

            try {
                await tokenManager.getValidToken();
                coloredLog(`Authentication successful for ${account.username}`, 'INFO', 'green');

                // Remove initial delay
                runValidationProcess(tokenManager, config);
            } catch (error) {
                coloredLog(`Error with account ${account.username}: ${error.message}`, 'ERROR');
            }
        }
    }

    main();
}
