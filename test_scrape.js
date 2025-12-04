const axios = require('axios');
const cheerio = require('cheerio');

async function getPrice(productName) {
    console.log("Fiyat aranıyor:", productName);

    try {
        // Google Search
        const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(productName + " fiyat")}&hl=tr`;
        console.log("URL:", searchUrl);

        const response = await axios.get(searchUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://www.google.com/',
                'Cache-Control': 'max-age=0'
            }
        });

        const html = response.data;
        const $ = cheerio.load(html);

        let priceText = "";

        // Google Shopping snippet usually appears in specific classes
        // Try to find text that matches price format
        const bodyText = $('body').text();
        const priceRegex = /(\d{1,3}(\.\d{3})*,\d{2}\s*TL)/;
        const match = bodyText.match(priceRegex);

        if (match) {
            priceText = match[0];
            console.log("Found by regex:", priceText);
        } else {
            console.log("Regex failed.");
            // console.log(bodyText.substring(0, 500));
        }

        if (priceText) {
            console.log("SUCCESS: Fiyat bulundu:", priceText);
        } else {
            console.log("FAIL: Fiyat bulunamadı.");
        }

    } catch (error) {
        console.error("Scraping Hatası:", error.message);
        if (error.response) {
            console.error("Status:", error.response.status);
        }
    }
}

// Test with some common hardware
getPrice("Intel Core i5 12400F");
