// Import Modul yang Diperlukan
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const { CognitoIdentityProviderClient, InitiateAuthCommand } = require("@aws-sdk/client-cognito-identity-provider");
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// Konfigurasi Global
global.navigator = { userAgent: 'node' };

// Kode Warna untuk Output Konsol
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
    FG_YELLOW: "\x1b[33m",
    BG_BLUE: "\x1b[44m",
    BG_MAGENTA: "\x1b[45m",
    BG_CYAN: "\x1b[46m",
    BG_WHITE: "\x1b[47m"
};

// Fungsi untuk Memuat Konfigurasi dari config.json
function loadConfig() {
    try {
        const configPath = path.join(__dirname, 'config.json');
        if (!fs.existsSync(configPath)) {
            coloredLog(`File konfigurasi tidak ditemukan di ${configPath}, menggunakan konfigurasi default`, 'WARN');
            // Membuat file konfigurasi default jika tidak ada
            const defaultConfig = {
                accounts: [
                    {
                        region: 'ap-northeast-1',
                        clientId: '5msns4n49hmg3dftp2tp1t2iuh',
                        userPoolId: 'ap-northeast-1_M22I44OpC',
                        username: '',  // Diisi oleh pengguna
                        password: ''   // Diisi oleh pengguna
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
        coloredLog('Konfigurasi berhasil dimuat dari config.json', 'INFO', 'green');
        return userConfig;
    } catch (error) {
        coloredLog(`Error memuat konfigurasi: ${error.message}`, 'ERROR');
        throw new Error('Gagal memuat konfigurasi');
    }
}

function validateAccountConfig(cognitoConfig) {
    if (!cognitoConfig.username || !cognitoConfig.password) {
        coloredLog('ERROR: Username dan password harus diatur di config.json', 'ERROR');
        console.log('\nHarap perbarui file config.json Anda dengan kredensial Anda:');
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

function randomDelay(min, max) {
    return new Promise(resolve => setTimeout(resolve, Math.random() * (max - min) + min));
}

class CognitoAuth {
    constructor(config) {
        this.config = config;
        this.userPool = new AmazonCognitoIdentity.CognitoUserPool({
            UserPoolId: config.userPoolId,
            ClientId: config.clientId
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
            Username: this.config.username,
            Pool: this.userPool
        });
        const refreshTokenObj = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: refreshToken });
        return new Promise((resolve, reject) => {
            cognitoUser.refreshSession(refreshTokenObj, (err, result) => {
                if (err) {
                    console.error("Failed to refresh session:", err);
                    reject(err);
                    return;
                }

                resolve({
                    accessToken: result.getAccessToken().getJwtToken(),
                    idToken: result.getIdToken().getJwtToken(),
                    refreshToken: refreshToken, // Use the same refresh token
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
        this.tokenPath = path.join(__dirname, `tokens_${config.username.replace(/[^a-zA-Z0-9]/g, '_')}.json`); // Unique token path per account
    }

    async getValidToken() {
        if (!this.accessToken || this.isTokenExpired()) {
            try {
                await this.refreshOrAuthenticate();
            } catch (error) {
                coloredLog(`Failed to refresh/authenticate token: ${error.message}`, 'ERROR');
                throw error;
            }
        }
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
                    coloredLog(`Token berhasil disegarkan untuk ${this.config.username}`, 'INFO', 'green');
                } catch (refreshError) {
                    coloredLog(`Penyegaran token gagal untuk ${this.config.username}: ${refreshError.message}, mencoba autentikasi`, 'WARN');
                    result = await this.auth.authenticate(this.config.username, this.config.password);
                }
            } else {
                result = await this.auth.authenticate(this.config.username, this.config.password);
            }

            await this.updateTokens(result);
        } catch (error) {
            coloredLog(`Error penyegaran/autentikasi token untuk ${this.config.username}: ${error.message}`, 'ERROR');
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
        coloredLog(`Token diperbarui dan disimpan ke ${this.tokenPath} untuk ${this.config.username}`, 'INFO', 'green');
    }

    async loadTokens() {
        try {
            if (!fs.existsSync(this.tokenPath)) {
                return null;
            }
            const tokensData = await fs.promises.readFile(this.tokenPath, 'utf8');
            const tokens = JSON.parse(tokensData);
            coloredLog(`Berhasil membaca token dari ${this.tokenPath} untuk ${this.config.username}`, 'INFO', 'green');
            return tokens;
        } catch (error) {
            coloredLog(`Error membaca token dari ${this.tokenPath} untuk ${this.config.username}: ${error.message}`, 'ERROR');
            return null;
        }
    }

    async saveTokens(tokens) {
        try {
            await fs.promises.writeFile(this.tokenPath, JSON.stringify(tokens, null, 2), 'utf8');
            coloredLog(`Token berhasil disimpan ke ${this.tokenPath} untuk ${this.config.username}`, 'INFO', 'green');
            return true;
        } catch (error) {
            coloredLog(`Error menyimpan token ke ${this.tokenPath} untuk ${this.config.username}: ${error.message}`, 'ERROR');
            return false;
        }
    }
}

async function refreshTokensStork(refreshToken, config) {
    try {
        coloredLog('Menyegarkan access token via Stork API...', 'INFO', 'cyan');
        const axiosConfig = {
            method: 'POST',
            url: `https://api.jp.stork-oracle.network/auth/refresh`,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl'
            }
        };

        const response = await axios(axiosConfig, { data: { refresh_token: refreshToken } });
        const tokens = {
            accessToken: response.data.access_token,
            idToken: response.data.id_token || '',
            refreshToken: response.data.refresh_token || refreshToken,
            isAuthenticated: true,
            isVerifying: false
        };
        return tokens;
    } catch (error) {
        coloredLog(`Token refresh gagal: ${error.message}`, 'ERROR');
        throw error;
    }
}

async function getSignedPrices(tokens, config) {
    try {
        coloredLog('Mengambil data harga yang ditandatangani...', 'INFO', 'cyan');
        const axiosConfig = {
            method: 'GET',
            url: 'https://app-api.jp.stork-oracle.network/v1/stork_signed_prices',
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Content-Type': 'application/json',
                'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            }
        };
        const response = await axios(axiosConfig);
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
        coloredLog(`Berhasil mengambil ${result.length} harga yang ditandatangani`, 'INFO', 'green');
        return result;
    } catch (error) {
        coloredLog(`Error mendapatkan harga yang ditandatangani: ${error.message}`, 'ERROR');
        throw error;
    }
}

async function sendValidation(tokens, msgHash, isValid) {
    try {
        await randomDelay(1000, 3000); // Delay sebelum permintaan

        const axiosConfig = {
            method: 'POST',
            url: 'https://app-api.jp.stork-oracle.network/v1/stork_signed_prices/validations',
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Content-Type': 'application/json',
                'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            },
            data: { msg_hash: msgHash, valid: isValid }
        };
        const response = await axios(axiosConfig);
        coloredLog(`? Validasi berhasil untuk ${msgHash.substring(0, 10)}...`, 'INFO', 'green');
        return response.data;
    } catch (error) {
        coloredLog(`? Validasi gagal untuk ${msgHash.substring(0, 10)}...: ${error.message}`, 'ERROR');
        throw error;
    }
}

async function getUserStats(tokens) {
    try {
        coloredLog('Mengambil statistik pengguna...', 'INFO', 'cyan');
        const axiosConfig = {
            method: 'GET',
            url: 'https://app-api.jp.stork-oracle.network/v1/me',
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Content-Type': 'application/json',
                'Origin': 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            }
        };

        const response = await axios(axiosConfig);
        return response.data.data;
    } catch (error) {
        coloredLog(`Error mendapatkan statistik pengguna: ${error.message}`, 'ERROR');
        throw error;
    }
}

function validatePrice(priceData) {
    try {
        coloredLog(`Memvalidasi data untuk ${priceData.asset || 'aset tidak dikenal'}`, 'INFO', 'cyan');
        if (!priceData.msg_hash || !priceData.price || !priceData.timestamp) {
            coloredLog('Data tidak lengkap, dianggap tidak valid', 'WARN');
            return false;
        }
        const currentTime = Date.now();
        const dataTime = new Date(priceData.timestamp).getTime();
        const timeDiffMinutes = (currentTime - dataTime) / (1000 * 60);
        if (timeDiffMinutes > 60) {
            coloredLog(`Data terlalu lama (${Math.round(timeDiffMinutes)} menit yang lalu)`, 'WARN');
            return false;
        }
        return true;
    } catch (error) {
        coloredLog(`Validasi error: ${error.message}`, 'ERROR');
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
            coloredLog(`--------- MEMULAI PROSES VALIDASI untuk ${config.cognito.username} ---------`, 'INFO', 'blue');
            const tokens = await getTokens(config);
            const initialUserData = await getUserStats(tokens);

            if (!initialUserData || !initialUserData.stats) {
                throw new Error('Tidak dapat mengambil statistik pengguna awal');
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

            coloredLog(`Memproses ${signedPrices.length} titik data dengan ${config.threads.maxWorkers} pekerja...`, 'INFO', 'cyan');
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
            // Segera jadwalkan ulang proses berikutnya
            setTimeout(() => runValidationProcess(tokenManager, config), 0);  // Jalankan segera
        }
    }

    async function getTokens(config) {
        const tokenManager = new TokenManager(config.cognito); // Pass config.cognito here
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
        console.log(colors.FG_WHITE + `User: ${userData.username || 'N/A'}` + colors.RESET);
        console.log(colors.FG_WHITE + `ID: ${userData.id || 'N/A'}` + colors.RESET);
        console.log(colors.FG_WHITE + `Referral Code: ${userData.referral_code || 'N/A'}` + colors.RESET);
        console.log(colors.FG_CYAN + '---------------------------------------------' + colors.RESET);
        console.log(colors.BRIGHT + colors.FG_GREEN + 'VALIDATION STATISTICS:' + colors.RESET);
        console.log(colors.FG_GREEN + `? Valid Validations: ${userData.stats.stork_signed_prices_valid_count || 0}` + colors.RESET);
        console.log(colors.FG_RED + `? Invalid Validations: ${userData.stats.stork_signed_prices_invalid_count || 0}` + colors.RESET);
        console.log(colors.FG_WHITE + `? Terakhir Divalidasi Pada: ${userData.stats.stork_signed_prices_last_verified_at || 'Tidak Pernah'}` + colors.RESET);
        console.log(colors.FG_WHITE + `?? Penggunaan Referral: ${userData.stats.referral_usage_count || 0}` + colors.RESET);
        console.log(colors.FG_CYAN + '---------------------------------------------' + colors.RESET);
        //Removed: console.log(colors.FG_YELLOW + `Next validation in ${config.stork.intervalSeconds} seconds...` + colors.RESET);
        console.log(colors.BRIGHT + colors.FG_CYAN + '=============================================' + colors.RESET);
    }

    async function main() {
        const userConfig = loadConfig();

        if (!userConfig.accounts || userConfig.accounts.length === 0) {
            coloredLog('Tidak ada akun yang dikonfigurasi di config.json', 'ERROR');
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

            try {
                const tokenManager = new TokenManager(config.cognito);
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
