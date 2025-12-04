const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const axios = require('axios');
const cheerio = require('cheerio');
const Iyzipay = require('iyzipay');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// --- RENDER PORT AYARI (KRİTİK) ---
const PORT = process.env.PORT || 3000;

// --- IYZICO AYARLARI ---
const iyzipay = new Iyzipay({
    apiKey: 'sandbox-D7Ngq1esOoGbGTSG6dXCV4XHiPFIsXJx',
    secretKey: 'sandbox-K0SibrJUgIfp35HxguHVGRZoDo4ihrHP',
    uri: 'https://sandbox-api.iyzipay.com'
});

// --- MYSQL BAĞLANTISI VE HATA YÖNETİMİ ---
let db;

function handleDisconnect() {
    const dbConfig = {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || 'Melekirem14.',
        database: process.env.DB_NAME || 'benchmark_db',
        port: process.env.DB_PORT || 3306
    };

    db = mysql.createConnection(dbConfig);

    db.connect((err) => {
        if (err) {
            console.error('MySQL Bağlantı Hatası:', err.code);
            console.log('⚠️ UYARI: Sunucu veritabanına bağlanamadı. Render kullanıyorsan "localhost" veritabanına erişemezsin.');
            console.log('Sunucu yine de çalışmaya devam ediyor...');
            // Bağlantı koparsa 5 saniye sonra tekrar dene
            setTimeout(handleDisconnect, 5000);
        } else {
            console.log('✅ BAŞARILI: MySQL Veritabanına Bağlandı!');
            initTables(); // Tabloları oluştur
        }
    });

    db.on('error', (err) => {
        console.error('MySQL Hatası:', err);
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            handleDisconnect();
        } else {
            // throw err; // Sunucuyu çökertmemek için throw yapmıyoruz
            console.error("Kritik DB Hatası, tekrar bağlanılmaya çalışılacak.");
        }
    });
}

// Tabloları oluşturma fonksiyonu
function initTables() {
    const createDonationTableQuery = `
    CREATE TABLE IF NOT EXISTS donation_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        title VARCHAR(255) NOT NULL,
        category VARCHAR(255),
        price INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`;

    const createHistoryTableQuery = `
    CREATE TABLE IF NOT EXISTS test_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        cpu VARCHAR(255),
        gpu VARCHAR(255),
        ram VARCHAR(255),
        score INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`;

    db.query(createDonationTableQuery, (err) => {
        if (err) console.error("Tablo Hatası (Donation):", err);
    });

    db.query(createHistoryTableQuery, (err) => {
        if (err) console.error("Tablo Hatası (History):", err);
    });
}

// Veritabanı bağlantısını başlat
handleDisconnect();


// --- ENDPOINTLER ---

// ANASAYFA (Render'ın çalıştığını anlamak için)
app.get('/', (req, res) => {
    res.send('Merhaba! Techbench Sunucusu Başarıyla Çalışıyor! (v1.0)');
});

// KAYIT OLMA API
app.post('/register', (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) return res.status(400).json({ success: false, message: "Eksik veri." });

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ success: false, message: "Şifreleme hatası." });

        const sql = "INSERT INTO kullanicilar (kullanici_adi, sifre_hash, email) VALUES (?, ?, ?)";
        db.query(sql, [username, hash, email], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') res.status(409).json({ success: false, message: "Bu kullanıcı adı alınmış." });
                else res.status(500).json({ success: false, message: "Veritabanı hatası." });
            } else {
                res.status(200).json({ success: true, message: "Kayıt Başarılı" });
            }
        });
    });
});

// GİRİŞ YAPMA API
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM kullanicilar WHERE kullanici_adi = ?";
    
    db.query(sql, [username], (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ success: false, message: "Kullanıcı bulunamadı." });

        const user = results[0];
        bcrypt.compare(password, user.sifre_hash, (err, isMatch) => {
            if (isMatch) {
                const { sifre_hash, ...userData } = user;
                res.status(200).json({ success: true, message: "Giriş Başarılı", user: userData });
            } else {
                res.status(401).json({ success: false, message: "Hatalı şifre." });
            }
        });
    });
});

// HESAP SİLME API
app.post('/delete-account', (req, res) => {
    const { username } = req.body;
    db.query("DELETE FROM kullanicilar WHERE kullanici_adi = ?", [username], (err, result) => {
        if (err) res.status(500).json({ success: false, message: "Hata" });
        else res.status(200).json({ success: true, message: "Silindi" });
    });
});

// SKOR KAYDETME API
app.post('/save-score', (req, res) => {
    const { username, cpu, gpu, ram, score } = req.body;
    const sqlUpdate = "UPDATE kullanicilar SET cpu = ?, gpu = ?, ram = ?, score = ? WHERE kullanici_adi = ?";
    
    db.query(sqlUpdate, [cpu, gpu, ram, score, username], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Hata" });

        const sqlInsert = "INSERT INTO test_history (username, cpu, gpu, ram, score) VALUES (?, ?, ?, ?, ?)";
        db.query(sqlInsert, [username, cpu, gpu, ram, score]);
        res.status(200).json({ success: true, message: "Kaydedildi" });
    });
});

// TEST GEÇMİŞİNİ GETİRME API
app.get('/score-history', (req, res) => {
    const { username } = req.query;
    const sql = "SELECT * FROM test_history WHERE username = ? ORDER BY created_at DESC LIMIT 20";
    db.query(sql, [username], (err, results) => {
        if (err) res.status(500).json({ success: false });
        else res.status(200).json(results);
    });
});

// TEST GEÇMİŞİNİ SİLME API
app.post('/delete-history', (req, res) => {
    const { username } = req.body;
    db.query("DELETE FROM test_history WHERE username = ?", [username], (err) => {
        if (err) return res.status(500).json({ success: false });
        
        db.query("UPDATE kullanicilar SET score = 0, cpu = NULL, gpu = NULL, ram = NULL WHERE kullanici_adi = ?", [username]);
        res.status(200).json({ success: true });
    });
});

// RAKİPLERİ GETİRME API
app.get('/rivals', (req, res) => {
    const sql = "SELECT kullanici_adi AS username, cpu, gpu, ram, score FROM kullanicilar ORDER BY score DESC LIMIT 50";
    db.query(sql, (err, results) => {
        if (err) res.status(500).json({ success: false });
        else res.status(200).json(results);
    });
});

// NODEMAILER AYARLARI
const verificationCodes = {};
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'sadettinboylan80@gmail.com',
        pass: 'zaei jepx rppc mwuu'
    }
});

// BAĞIŞ İSTEĞİ OLUŞTURMA API
app.post('/create-donation-request', (req, res) => {
    const { username, title, category, price } = req.body;
    const sql = "INSERT INTO donation_requests (username, title, category, price) VALUES (?, ?, ?, ?)";
    db.query(sql, [username, title, category, price], (err, result) => {
        if (err) res.status(500).json({ success: false });
        else res.status(200).json({ success: true });
    });
});

// BAĞIŞ İSTEKLERİNİ GETİRME API
app.get('/donation-requests', (req, res) => {
    const sql = "SELECT * FROM donation_requests ORDER BY created_at DESC";
    db.query(sql, (err, results) => {
        if (err) res.status(500).json({ success: false });
        else res.status(200).json(results);
    });
});

// FİYAT ÇEKME API
app.get('/get-price', async (req, res) => {
    const { productName } = req.query;
    if (!productName) return res.status(400).json({ success: false, message: "Ürün adı gerekli." });

    // Mock Data (Fallback)
    let mockPrice = "Bilinmiyor";
    const lowerName = productName.toLowerCase();
    if (lowerName.includes("4090")) mockPrice = "75.000 TL";
    else if (lowerName.includes("4060")) mockPrice = "14.500 TL";
    else mockPrice = "5.000 TL"; // Basitleştirildi

    res.status(200).json({ success: true, price: mockPrice, source: "Tahmini" });
});

// IYZICO ÖDEME BAŞLATMA
app.post('/payment/initialize', (req, res) => {
    const { price, basketId, user, productName } = req.body;
    const request = {
        locale: Iyzipay.LOCALE.TR,
        conversationId: '123456789',
        price: price.toString(),
        paidPrice: price.toString(),
        currency: Iyzipay.CURRENCY.TRY,
        basketId: basketId || 'B67832',
        paymentGroup: Iyzipay.PAYMENT_GROUP.PRODUCT,
        callbackUrl: 'https://oyun-serverim.onrender.com/payment/callback', // DİKKAT: Bunu kendi Render linkinle güncellemelisin!
        enabledInstallments: [2, 3, 6, 9],
        buyer: {
            id: 'BY789',
            name: user?.name || 'John',
            surname: user?.surname || 'Doe',
            gsmNumber: '+905350000000',
            email: user?.email || 'email@email.com',
            identityNumber: '74300864791',
            lastLoginDate: '2015-10-05 12:43:35',
            registrationDate: '2013-04-21 15:12:09',
            registrationAddress: 'Istanbul',
            ip: '85.34.78.112',
            city: 'Istanbul',
            country: 'Turkey',
            zipCode: '34732'
        },
        shippingAddress: { contactName: 'Jane Doe', city: 'Istanbul', country: 'Turkey', address: 'Istanbul', zipCode: '34742' },
        billingAddress: { contactName: 'Jane Doe', city: 'Istanbul', country: 'Turkey', address: 'Istanbul', zipCode: '34742' },
        basketItems: [{ id: 'BI101', name: productName || 'Bagis', category1: 'Donation', itemType: Iyzipay.BASKET_ITEM_TYPE.PHYSICAL, price: price }]
    };

    iyzipay.checkoutFormInitialize.create(request, function (err, result) {
        if (err || result.status !== 'success') {
            res.status(400).json({ success: false, message: result?.errorMessage || "Ödeme hatası" });
        } else {
            res.status(200).json({ success: true, paymentPageUrl: result.paymentPageUrl, htmlContent: result.checkoutFormContent });
        }
    });
});

// ŞİFREMİ UNUTTUM
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    db.query("SELECT * FROM kullanicilar WHERE email = ?", [email], (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        verificationCodes[email] = { code, expires: Date.now() + 300000 };

        transporter.sendMail({
            from: 'Techbench App <sadettinboylan80@gmail.com>',
            to: email,
            subject: 'Şifre Sıfırlama Kodu',
            text: `Kodunuz: ${code}`
        }, (error) => {
            if (error) {
                console.log(`E-posta gönderilemedi. Kod: ${code}`); // Loga yaz
                return res.status(200).json({ success: true, message: "Simülasyon modu: Kod loglara yazıldı." });
            }
            res.status(200).json({ success: true, message: "Kod gönderildi." });
        });
    });
});

// ŞİFRE SIFIRLAMA
app.post('/reset-password', (req, res) => {
    const { email, code, newPassword } = req.body;
    const record = verificationCodes[email];

    if (!record || Date.now() > record.expires || record.code !== code) {
        return res.status(400).json({ success: false, message: "Geçersiz kod." });
    }

    bcrypt.hash(newPassword, 10, (err, hash) => {
        db.query("UPDATE kullanicilar SET sifre_hash = ? WHERE email = ?", [hash, email], (err) => {
            if (err) return res.status(500).json({ success: false });
            delete verificationCodes[email];
            res.status(200).json({ success: true, message: "Şifre güncellendi." });
        });
    });
});

// IYZICO CALLBACK
app.post('/payment/callback', (req, res) => {
    res.send('<h1>Ödeme Başarılı!</h1><p>Pencereyi kapatabilirsiniz.</p>');
});

// SUNUCUYU BAŞLAT
app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor...`);
});