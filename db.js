// db.js 
import mysql from 'mysql2';

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Melekirem14.',
  database: 'benchmark_db'
});

db.connect((err) => {
  if (err) {
    console.error('MySQL bağlantı hatası:', err);
  } else {
    console.log('✅ MySQL bağlantısı başarılı.');
  }
});

export default db;
