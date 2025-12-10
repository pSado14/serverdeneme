require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');

const logFile = path.join(__dirname, 'server_log.txt');

function logToFile(message) {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${message}\n`;
    fs.appendFileSync(logFile, logMessage);
    console.log(message);
}

const Iyzipay = require('iyzipay');

const iyzipay = new Iyzipay({
    apiKey: process.env.IYZICO_API_KEY,
    secretKey: process.env.IYZICO_SECRET_KEY,
    uri: process.env.IYZICO_URI || 'https://sandbox-api.iyzipay.com'
});

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// --- MYSQL BAĞLANTISI (RENDER + AIVEN) ---
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// Render callback URL
const CALLBACK_URL = process.env.CALLBACK_URL;

db.connect((err) => {
    if (err) console.error('MySQL Bağlantı Hatası:', err);
    else {
        console.log('BAŞARILI: MySQL Veritabanına Bağlandı!');

        // Kullanıcılar tablosunu oluştur
        const createUsersTableQuery = `
        CREATE TABLE IF NOT EXISTS kullanicilar (
            id INT AUTO_INCREMENT PRIMARY KEY,
            kullanici_adi VARCHAR(255) NOT NULL UNIQUE,
            sifre_hash VARCHAR(255) NOT NULL,
            email VARCHAR(255),
            cpu VARCHAR(255),
            gpu VARCHAR(255),
            ram VARCHAR(255),
            score INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`;
        db.query(createUsersTableQuery, (err) => {
            if (err) console.error("Tablo oluşturma hatası (kullanicilar):", err);
            else console.log("Tablo kontrol edildi: kullanicilar");
        });

        const alterTableQuery = "ALTER TABLE product_prices ADD COLUMN category VARCHAR(50) DEFAULT 'General' AFTER product_name";
        db.query(alterTableQuery, (errAlter) => {
            if (errAlter && errAlter.code !== 'ER_DUP_FIELDNAME') { }
            else if (!errAlter) { console.log("Tablo güncellendi: category sütunu eklendi."); }
        });

        const createDonationRequestsTableQuery = `
        CREATE TABLE IF NOT EXISTS donation_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            title VARCHAR(255) NOT NULL,
            category VARCHAR(50),
            price DECIMAL(10,2) NOT NULL,
            collected_amount DECIMAL(10,2) DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`;

        db.query(createDonationRequestsTableQuery, (err) => {
            if (err) console.error("Tablo oluşturma hatası (donation_requests):", err);
            else {
                const alterDonationQuery = "ALTER TABLE donation_requests ADD COLUMN collected_amount DECIMAL(10,2) DEFAULT 0";
                db.query(alterDonationQuery, (errAlter) => {
                    if (errAlter && errAlter.code !== 'ER_DUP_FIELDNAME') { }
                    else if (!errAlter) { console.log("Tablo güncellendi: collected_amount sütunu eklendi."); }
                });
            }
        });
    }
});

// --- TABLO OLUŞTURMA ---
const createPricesTableQuery = `
CREATE TABLE IF NOT EXISTS product_prices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_name VARCHAR(255) NOT NULL,
    category VARCHAR(50) DEFAULT 'General',
    price VARCHAR(50) NOT NULL,
    source VARCHAR(50) DEFAULT 'DB',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_product (product_name)
)`;

db.query(createPricesTableQuery, (err) => {
    if (err) console.error("Tablo oluşturma hatası (product_prices):", err);
    else console.log("Tablo kontrol edildi: product_prices");
});

const createHistoryTableQuery = `
CREATE TABLE IF NOT EXISTS test_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    score INT NOT NULL,
    cpu VARCHAR(255),
    gpu VARCHAR(255),
    ram VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`;

db.query(createHistoryTableQuery, (err) => {
    if (err) console.error("Tablo oluşturma hatası (test_history):", err);
    else console.log("Tablo kontrol edildi: test_history");
});

// --- NODEMAILER AYARLARI ---
const verificationCodes = {};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- BAĞIŞ İSTEĞİ OLUŞTURMA API ---
app.post('/create-donation-request', (req, res) => {
    const { username, title, category, price } = req.body;
    if (!username || !title || !price) {
        return res.status(400).json({ success: false, message: "Eksik bilgi." });
    }

    const sql = "INSERT INTO donation_requests (username, title, category, price) VALUES (?, ?, ?, ?)";
    db.query(sql, [username, title, category, price], (err, result) => {
        if (err) {
            console.error("Bağış İsteği Kayıt Hatası:", err);
            res.status(500).json({ success: false, message: "Veritabanı hatası." });
        } else {
            console.log("Bağış isteği oluşturuldu:", title);
            res.status(200).json({ success: true, message: "Bağış isteği oluşturuldu." });
        }
    });
});

// --- BAĞIŞ İSTEKLERİNİ GETİRME API ---
app.get('/donation-requests', (req, res) => {
    const sql = "SELECT * FROM donation_requests ORDER BY created_at DESC";
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Bağış İstekleri Getirme Hatası:", err);
            res.status(500).json({ success: false, message: "Veritabanı hatası." });
        } else {
            console.log("Bağış istekleri gönderiliyor:", results.length, "adet");
            res.status(200).json(results);
        }
    });
});

// --- KAYIT OLMA API ---
app.post('/register', (req, res) => {
    console.log("Kayıt İsteği Geldi:", req.body);
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ success: false, message: "Eksik veri." });
    }

    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.error("Hash Hatası:", err);
            return res.status(500).json({ success: false, message: "Sunucu hatası (Şifreleme)." });
        }

        const sql = "INSERT INTO kullanicilar (kullanici_adi, sifre_hash, email) VALUES (?, ?, ?)";
        db.query(sql, [username, hash, email], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    res.status(409).json({ success: false, message: "Bu kullanıcı adı zaten alınmış." });
                } else {
                    console.error("SQL Hatası:", err);
                    res.status(500).json({ success: false, message: "Veritabanı hatası." });
                }
            } else {
                console.log("Kullanıcı oluşturuldu:", username);
                res.status(200).json({ success: true, message: "Kayıt Başarılı" });
            }
        });
    });
});

// --- GİRİŞ YAPMA API ---
app.post('/login', (req, res) => {
    console.log("Giriş İsteği Geldi:", req.body.username);
    const { username, password } = req.body;

    const sql = "SELECT * FROM kullanicilar WHERE kullanici_adi = ?";
    db.query(sql, [username], (err, results) => {
        if (err) {
            console.error("Giriş Hatası (SQL):", err);
            return res.status(500).json({ success: false, message: "Sunucu hatası" });
        }

        if (results.length === 0) {
            return res.status(401).json({ success: false, message: "Kullanıcı bulunamadı." });
        }

        const user = results[0];
        bcrypt.compare(password, user.sifre_hash, (err, isMatch) => {
            if (err) {
                console.error("Bcrypt Hatası:", err);
                return res.status(500).json({ success: false, message: "Sunucu hatası (Şifre Kontrolü)." });
            }

            if (isMatch) {
                console.log("Giriş Başarılı:", username);
                const { sifre_hash, ...userData } = user;
                res.status(200).json({ success: true, message: "Giriş Başarılı", user: userData });
            } else {
                console.log("Hatalı Şifre:", username);
                res.status(401).json({ success: false, message: "Hatalı şifre." });
            }
        });
    });
});

// --- HESAP SİLME API ---
app.post('/delete-account', (req, res) => {
    console.log("Hesap Silme İsteği:", req.body.username);
    const { username } = req.body;

    if (!username) return res.status(400).json({ success: false, message: "Kullanıcı adı eksik." });

    const sql = "DELETE FROM kullanicilar WHERE kullanici_adi = ?";
    db.query(sql, [username], (err, result) => {
        if (err) {
            console.error("Silme Hatası:", err);
            res.status(500).json({ success: false, message: "Veritabanı hatası." });
        } else if (result.affectedRows === 0) {
            res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });
        } else {
            console.log("Kullanıcı silindi:", username);
            res.status(200).json({ success: true, message: "Hesap başarıyla silindi." });
        }
    });
});

// --- SKOR KAYDETME API ---
app.post('/save-score', (req, res) => {
    console.log("Skor Kaydetme İsteği:", req.body.username);
    const { username, cpu, gpu, ram, score } = req.body;

    const sqlUpdate = "UPDATE kullanicilar SET cpu = ?, gpu = ?, ram = ?, score = ? WHERE kullanici_adi = ?";
    db.query(sqlUpdate, [cpu, gpu, ram, score, username], (err, result) => {
        if (err) {
            console.error("Skor Kaydetme Hatası:", err);
            return res.status(500).json({ success: false, message: "Veritabanı hatası." });
        }
        const sqlInsertHistory = "INSERT INTO test_history (username, score, cpu, gpu, ram) VALUES (?, ?, ?, ?, ?)";
        db.query(sqlInsertHistory, [username, score, cpu, gpu, ram], (errHist, resultHist) => {
            if (errHist) {
                console.error("Geçmişe Ekleme Hatası:", errHist);
            } else {
                console.log("Geçmişe eklendi:", username);
            }
            res.status(200).json({ success: true, message: "Skor ve geçmiş kaydedildi." });
        });
    });
});

// --- SKOR GEÇMİŞİ API ---
app.get('/score-history', (req, res) => {
    const { username } = req.query;
    if (!username) return res.status(400).json({ success: false, message: "Kullanıcı adı gerekli." });

    const sql = "SELECT * FROM test_history WHERE username = ? ORDER BY created_at DESC LIMIT 20";
    db.query(sql, [username], (err, results) => {
        if (err) {
            console.error("Geçmiş Getirme Hatası:", err);
            res.status(500).json({ success: false, message: "Veritabanı hatası." });
        } else {
            res.status(200).json(results);
        }
    });
});

// --- TEST GEÇMİŞİNİ SİLME API ---
app.post('/delete-history', (req, res) => {
    console.log("Geçmiş Silme İsteği:", req.body.username);
    const { username } = req.body;

    if (!username) return res.status(400).json({ success: false, message: "Kullanıcı adı eksik." });

    const sqlDeleteHistory = "DELETE FROM test_history WHERE username = ?";
    db.query(sqlDeleteHistory, [username], (err, result) => {
        if (err) {
            console.error("Geçmiş Silme Hatası:", err);
            return res.status(500).json({ success: false, message: "Veritabanı hatası (History)." });
        }

        const sqlResetUser = "UPDATE kullanicilar SET score = 0, cpu = NULL, gpu = NULL, ram = NULL WHERE kullanici_adi = ?";
        db.query(sqlResetUser, [username], (errUser, resultUser) => {
            if (errUser) {
                console.error("Puan Sıfırlama Hatası:", errUser);
            } else {
                console.log("Kullanıcı puanı sıfırlandı:", username);
            }

            console.log("Geçmiş silindi:", username);
            res.status(200).json({ success: true, message: "Geçmiş ve puanlar başarıyla silindi." });
        });
    });
});

// --- ÜRÜN ARAMA API ---
app.get('/search-products', (req, res) => {
    const { query, category } = req.query;
    if (!query) {
        return res.status(400).json({ success: false, message: "Arama terimi gerekli." });
    }

    console.log(`Ürün aranıyor(Liste): ${query} [${category || 'Tümü'}]`);

    let sql = "SELECT * FROM product_prices WHERE product_name LIKE ?";
    let params = [`%${query}%`];

    if (category) {
        sql += " AND category = ?";
        params.push(category);
    }

    sql += " ORDER BY price ASC LIMIT 20";

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error("Arama Hatası:", err);
            res.status(500).json({ success: false, message: "Veritabanı hatası." });
        } else {
            console.log(`Bulunan ürün sayısı: ${results.length}`);
            res.status(200).json({ success: true, results: results });
        }
    });
});

// --- FİYAT ÇEKME API ---
app.get('/get-price', async (req, res) => {
    const { productName, category } = req.query;
    if (!productName) {
        return res.status(400).json({ success: false, message: "Ürün adı gerekli." });
    }

    const cat = category || 'General';
    console.log(`Fiyat aranıyor: ${productName} (${cat})`);

    const sqlCheck = "SELECT * FROM product_prices WHERE product_name = ?";
    db.query(sqlCheck, [productName], async (err, results) => {
        if (err) {
            console.error("DB Fiyat Sorgu Hatası:", err);
            return res.status(500).json({ success: false, message: "Veritabanı hatası." });
        } else if (results.length > 0) {
            console.log("Fiyat DB'den bulundu:", results[0].price);
            return res.status(200).json({ success: true, price: results[0].price, source: "Veritabanı" });
        } else {
            console.log("DB'de bulunamadı.");
            return res.status(200).json({ success: false, message: "Fiyat bulunamadı.", price: "Bulunamadı", source: "Yok" });
        }
    });
});

// --- IYZICO ÖDEME BAŞLATMA API ---
app.post('/payment/initialize', (req, res) => {
    console.log("Ödeme Başlatma İsteği:", req.body);
    try {
        const { price, basketId, user, productName, receiverUsername, requestId } = req.body;

        if (!user) {
            return res.status(400).json({ success: false, message: "Kullanıcı bilgisi eksik." });
        }

        const senderUsername = user.name || 'UnknownSender';
        const receiver = receiverUsername || 'System';

        // FIX: conversationId sadece sayı olmalı - zararlı kod hatası için
        const reqId = requestId ? String(requestId) : '0';
        const conversationId = reqId.replace(/[^0-9]/g, '') || '0';

        // BasketId formatı: DONATION_requestId_timestamp (parse edilebilir format)
        const metadata = `DONATION_${reqId}_${Date.now()}`;

        const priceStr = price ? price.toString() : '0';

        const request = {
            locale: Iyzipay.LOCALE.TR,
            conversationId: conversationId,
            price: priceStr,
            paidPrice: priceStr,
            currency: Iyzipay.CURRENCY.TRY,
            basketId: metadata,
            paymentGroup: Iyzipay.PAYMENT_GROUP.PRODUCT,
            callbackUrl: CALLBACK_URL,
            enabledInstallments: [2, 3, 6, 9],
            buyer: {
                id: 'BY789',
                name: user.name || 'John',
                surname: user.surname || 'Doe',
                gsmNumber: '+905350000000',
                email: user.email || 'email@email.com',
                identityNumber: '74300864791',
                lastLoginDate: '2015-10-05 12:43:35',
                registrationDate: '2013-04-21 15:12:09',
                registrationAddress: 'Nidakule Göztepe, Merdivenköy Mah. Bora Sok. No:1',
                ip: '85.34.78.112',
                city: 'Istanbul',
                country: 'Turkey',
                zipCode: '34732'
            },
            shippingAddress: {
                contactName: 'Jane Doe',
                city: 'Istanbul',
                country: 'Turkey',
                address: 'Nidakule Göztepe, Merdivenköy Mah. Bora Sok. No:1',
                zipCode: '34742'
            },
            billingAddress: {
                contactName: 'Jane Doe',
                city: 'Istanbul',
                country: 'Turkey',
                address: 'Nidakule Göztepe, Merdivenköy Mah. Bora Sok. No:1',
                zipCode: '34742'
            },
            basketItems: [
                {
                    id: 'BI101',
                    name: productName || 'Bagis',
                    category1: 'Donation',
                    category2: 'Electronics',
                    itemType: Iyzipay.BASKET_ITEM_TYPE.PHYSICAL,
                    price: priceStr
                }
            ]
        };

        iyzipay.checkoutFormInitialize.create(request, function (err, result) {
            if (err) {
                console.error("Iyzico Hatası:", err);
                res.status(500).json({ success: false, message: "Ödeme başlatılamadı." });
            } else {
                if (result.status === 'success') {
                    res.status(200).json({ success: true, paymentPageUrl: result.paymentPageUrl, htmlContent: result.checkoutFormContent });
                } else {
                    console.error("Iyzico API Hatası:", result.errorMessage);
                    res.status(400).json({ success: false, message: "Iyzico Hatası: " + result.errorMessage });
                }
            }
        });
    } catch (error) {
        console.error("Sunucu İçi Hata (/payment/initialize):", error);
        res.status(500).json({ success: false, message: "Sunucu hatası: " + error.message });
    }
});

// --- ŞİFREMİ UNUTTUM API ---
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "E-posta gerekli." });

    db.query("SELECT * FROM kullanicilar WHERE email = ?", [email], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Veritabanı hatası." });
        if (results.length === 0) return res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = Date.now() + 5 * 60 * 1000;
        verificationCodes[email] = { code, expires };

        const mailOptions = {
            from: `Techbench App <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Techbench Şifre Sıfırlama Kodu',
            text: `Doğrulama kodunuz: ${code}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("EMAIL HATASI:", error.message);
                console.log(`🔑 DOĞRULAMA KODU: ${code}`);
                return res.status(200).json({ success: true, message: "E-posta gönderilemedi (Simülasyon)." });
            }
            res.status(200).json({ success: true, message: "Doğrulama kodu gönderildi." });
        });
    });
});

// --- ŞİFRE SIFIRLAMA API ---
app.post('/reset-password', (req, res) => {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ success: false, message: "Eksik bilgi." });

    const record = verificationCodes[email];
    if (!record || Date.now() > record.expires || record.code !== code) {
        return res.status(400).json({ success: false, message: "Geçersiz veya süresi dolmuş kod." });
    }

    bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) return res.status(500).json({ success: false, message: "Şifreleme hatası." });
        db.query("UPDATE kullanicilar SET sifre_hash = ? WHERE email = ?", [hash, email], (err, result) => {
            if (err) return res.status(500).json({ success: false, message: "Veritabanı hatası." });
            delete verificationCodes[email];
            res.status(200).json({ success: true, message: "Şifre güncellendi." });
        });
    });
});

// --- IYZICO CALLBACK ---
app.post('/payment/callback', (req, res) => {
    logToFile("Callback received: " + JSON.stringify(req.body));
    const { token } = req.body;

    iyzipay.checkoutForm.retrieve({ locale: Iyzipay.LOCALE.TR, conversationId: '123456789', token: token }, function (err, result) {
        if (err) {
            logToFile("Iyzico Retrieve Error: " + JSON.stringify(err));
            return res.send("Ödeme doğrulanamadı.");
        }

        logToFile("Iyzico Result Status: " + result.status + ", PaymentStatus: " + result.paymentStatus);
        logToFile("Full Iyzico Result: " + JSON.stringify(result));

        if (result.status === 'success' && result.paymentStatus === 'SUCCESS') {
            logToFile("Ödeme Başarılı. BasketID: " + result.basketId + ", ConversationID: " + result.conversationId);

            const basketId = result.basketId || "";
            const amount = parseFloat(result.paidPrice);

            // BasketId formatı: DONATION_requestId_timestamp - requestId'yi parse et
            let requestId = null;
            if (basketId.startsWith('DONATION_')) {
                const parts = basketId.split('_');
                if (parts.length >= 2) {
                    requestId = parts[1]; // DONATION_3_1234567890 -> "3"
                }
            }

            logToFile(`Bağış alındı. Tutar: ${amount}, RequestID: ${requestId}`);

            if (requestId && requestId !== '0') {
                // Veritabanında bağış isteğinin collected_amount'unu güncelle
                const updateSql = "UPDATE donation_requests SET collected_amount = collected_amount + ? WHERE id = ?";
                db.query(updateSql, [amount, requestId], (dbErr, dbResult) => {
                    if (dbErr) {
                        logToFile("Veritabanı Güncelleme Hatası: " + JSON.stringify(dbErr));
                    } else if (dbResult.affectedRows > 0) {
                        logToFile(`Bağış başarıyla kaydedildi! RequestID: ${requestId}, Tutar: ${amount} TL`);
                    } else {
                        logToFile(`Bağış isteği bulunamadı. RequestID: ${requestId}`);
                    }
                });
            } else {
                logToFile("BasketId DONATION ile başlamıyor veya RequestID geçersiz: " + basketId);
            }
        } else {
            logToFile("Ödeme başarısız veya onaylanmadı: " + JSON.stringify(result));
        }
        res.send("Ödeme İşlemi Tamamlandı. Pencereyi kapatabilirsiniz.");
    });
});

// --- P2P TRANSFER API ---
app.post('/p2p-transfer', (req, res) => {
    const { sender_id, receiver_id, amount } = req.body;
    if (!sender_id || !receiver_id || !amount) return res.status(400).json({ success: false, message: "Eksik bilgi." });

    const sqlCheckUsers = "SELECT kullanici_adi FROM kullanicilar WHERE kullanici_adi IN (?, ?)";
    db.query(sqlCheckUsers, [sender_id, receiver_id], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Veritabanı hatası." });

        const foundUsers = results.map(u => u.kullanici_adi);
        if (!foundUsers.includes(sender_id) || !foundUsers.includes(receiver_id)) {
            return res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });
        }

        const request = {
            locale: Iyzipay.LOCALE.TR,
            conversationId: String(Date.now()),
            price: amount.toString(),
            paidPrice: amount.toString(),
            currency: Iyzipay.CURRENCY.TRY,
            basketId: `BASKET${Date.now()}`,
            paymentGroup: Iyzipay.PAYMENT_GROUP.PRODUCT,
            callbackUrl: CALLBACK_URL,
            enabledInstallments: [2, 3, 6, 9],
            buyer: {
                id: sender_id,
                name: sender_id,
                surname: 'User',
                gsmNumber: '+905350000000',
                email: 'email@email.com',
                identityNumber: '74300864791',
                lastLoginDate: '2015-10-05 12:43:35',
                registrationDate: '2013-04-21 15:12:09',
                registrationAddress: 'Istanbul',
                ip: '85.34.78.112',
                city: 'Istanbul',
                country: 'Turkey',
                zipCode: '34732'
            },
            shippingAddress: { contactName: sender_id, city: 'Istanbul', country: 'Turkey', address: 'Istanbul', zipCode: '34742' },
            billingAddress: { contactName: sender_id, city: 'Istanbul', country: 'Turkey', address: 'Istanbul', zipCode: '34742' },
            basketItems: [{ id: `TRANSFER${Date.now()}`, name: `Transfer to ${receiver_id}`, category1: 'Transfer', itemType: Iyzipay.BASKET_ITEM_TYPE.VIRTUAL, price: amount.toString() }]
        };

        iyzipay.checkoutFormInitialize.create(request, function (err, result) {
            if (err) res.status(500).json({ success: false, message: "Transfer başlatılamadı." });
            else if (result.status === 'success') res.status(200).json({ success: true, paymentPageUrl: result.paymentPageUrl, htmlContent: result.checkoutFormContent });
            else res.status(400).json({ success: false, message: "Iyzico Hatası: " + result.errorMessage });
        });
    });
});

// --- SUNUCUYU KAPATMA API ---
app.get('/shutdown', (req, res) => {
    res.send("Sunucu kapatılıyor...");
    setTimeout(() => process.exit(0), 1000);
});

// --- KULLANICI SIRALAMASI API ---
app.get('/ranking', (req, res) => {
    const { username } = req.query;
    if (!username) return res.status(400).json({ success: false, message: "Kullanıcı adı gerekli." });

    const sqlSimple = "SELECT kullanici_adi, score FROM kullanicilar WHERE score > 0 ORDER BY score DESC";

    db.query(sqlSimple, (err, results) => {
        if (err) {
            console.error("Sıralama Hatası:", err);
            return res.status(500).json({ success: false, message: "Veritabanı hatası." });
        }

        let rank = -1;
        for (let i = 0; i < results.length; i++) {
            if (results[i].kullanici_adi === username) {
                rank = i + 1;
                break;
            }
        }

        if (rank !== -1) {
            res.status(200).json({ success: true, ranking: rank });
        } else {
            res.status(200).json({ success: false, message: "Sıralamaya henüz girmediniz (Puan: 0)." });
        }
    });
});

// --- RAKİPLERİ GETİRME API ---
app.get('/rivals', (req, res) => {
    const sql = "SELECT kullanici_adi, score, cpu, gpu, ram FROM kullanicilar WHERE score > 0 AND kullanici_adi != 'admin' ORDER BY score DESC LIMIT 20";
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Rakipleri Getirme Hatası:", err);
            res.status(500).json({ success: false, message: "Veritabanı hatası." });
        } else {
            res.status(200).json(results);
        }
    });
});

// Render için PORT environment variable kullan
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor...`);
});