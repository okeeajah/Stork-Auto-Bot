const fs = require('fs');
const path = require('path');
const { CognitoUserPool, CognitoUser, AuthenticationDetails, CognitoRefreshToken } = require('amazon-cognito-identity-js');

// Konfigurasi Global
global.navigator = { userAgent: 'node.js' };

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
    FG_WHITE: "\x1b[37m"
};

// Fungsi untuk Logging dengan Warna
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
    console.log(`${colors.BRIGHT}[${new Date().toISOString()}] ${colorCode}[${type}] ${message}${colors.RESET}`);
}

// Fungsi untuk Memuat Konfigurasi dari account.json
function loadConfig() {
    try {
        const configPath = path.join(__dirname, 'account.json');
        if (!fs.existsSync(configPath)) {
            throw new Error(`File konfigurasi tidak ditemukan di ${configPath}`);
        }
        const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        coloredLog('Konfigurasi berhasil dimuat dari account.json', 'INFO', 'green');
        return userConfig;
    } catch (error) {
        coloredLog(`Error memuat konfigurasi: ${error.message}`, 'ERROR');
        throw new Error('Gagal memuat konfigurasi');
    }
}

// Fungsi untuk Membaca Akun dari account.txt
function loadAccounts() {
    try {
        const accountPath = path.join(__dirname, 'account.txt');
        if (!fs.existsSync(accountPath)) {
            throw new Error(`File account.txt tidak ditemukan di ${accountPath}`);
        }
        const accounts = fs.readFileSync(accountPath, 'utf8')
            .split('\n')
            .map(line => line.trim())
            .filter(line => line && line.includes('|'))
            .map(line => {
                const [username, password] = line.split('|');
                return { username, password };
            });
        if (accounts.length === 0) {
            throw new Error('Tidak ada akun yang valid di account.txt');
        }
        coloredLog(`Berhasil memuat ${accounts.length} akun dari account.txt`, 'INFO', 'green');
        return accounts;
    } catch (error) {
        coloredLog(`Error memuat akun dari account.txt: ${error.message}`, 'ERROR');
        throw new Error('Gagal memuat akun');
    }
}

// Fungsi untuk Autentikasi dengan Cognito
async function authenticateWithCognito(username, password, userPoolId, clientId) {
    return new Promise((resolve, reject) => {
        const authenticationDetails = new AuthenticationDetails({
            Username: username,
            Password: password,
        });

        const userPool = new CognitoUserPool({
            UserPoolId: userPoolId,
            ClientId: clientId,
        });

        const cognitoUser = new CognitoUser({
            Username: username,
            Pool: userPool,
        });

        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: (result) => {
                const accessToken = result.getAccessToken().getJwtToken();
                const idToken = result.getIdToken().getJwtToken();
                const refreshToken = result.getRefreshToken().getToken();
                const expiresIn = result.getAccessToken().getExpiration();

                const expirationDate = new Date(expiresIn * 1000);
                const formattedDateTime = expirationDate.toLocaleString();

                const tokens = {
                    accessToken: accessToken,
                    idToken: idToken,
                    refreshToken: refreshToken,
                    expiresIn: formattedDateTime
                };
                resolve(tokens);
            },
            onFailure: (err) => {
                reject(err);
            },
        });
    });
}

// Fungsi Utama
async function main() {
    try {
        // Muat konfigurasi global dari account.json
        const config = loadConfig();

        // Muat daftar akun dari account.txt
        const accounts = loadAccounts();

        for (const account of accounts) {
            try {
                coloredLog(`Memulai autentikasi untuk akun ${account.username}`, 'INFO', 'cyan');

                // Lakukan autentikasi dengan Cognito
                const tokens = await authenticateWithCognito(
                    account.username,
                    account.password,
                    config.cognito.userPoolId,
                    config.cognito.clientId
                );

                // Tampilkan hasil token
                coloredLog(`Autentikasi berhasil untuk akun ${account.username}`, 'INFO', 'green');
                console.log('Tokens:', tokens);

                // Simpan token ke file jika diperlukan
                const tokenPath = path.join(__dirname, `tokens_${account.username.replace(/[^a-zA-Z0-9]/g, '_')}.json`);
                fs.writeFileSync(tokenPath, JSON.stringify(tokens, null, 2), 'utf8');
                coloredLog(`Tokens disimpan ke ${tokenPath}`, 'INFO', 'green');

            } catch (error) {
                coloredLog(`Autentikasi gagal untuk akun ${account.username}: ${error.message}`, 'ERROR', 'red');
            }
        }
    } catch (error) {
        coloredLog(`Error utama dalam script: ${error.message}`, 'ERROR', 'red');
    }
}

main();
