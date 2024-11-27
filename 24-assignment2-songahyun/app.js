const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const cors = require('cors');

// Middleware 설정
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cors());

// MySQL 데이터베이스 연결 설정
const db = mysql.createConnection({
    host: process.env.MYSQL_HOST,
    port: process.env.MYSQL_PORT,
    user: process.env.MYSQL_USERNAME,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DB,
});

// 데이터베이스 연결
db.connect((err) => {
    if (err) throw err;
    console.log('Database connected!');
});

// JWT 비밀 키
const JWT_SECRET = process.env.JWT_SECRET;

// 회원가입
app.post('/register', async (req, res) => {
    const { id, password } = req.body;

    // 비밀번호 해시 처리
    const hashedPassword = await bcrypt.hash(password, 10);

    // 데이터베이스에 사용자 정보 저장
    db.query('INSERT INTO users (id, password) VALUES (?, ?)', [id, hashedPassword], (err, results) => {
        if (err) {
            console.error(err); // 로그에 에러 출력
            return res.status(500).json({ message: 'Database error' });
        }
        // JWT 토큰 발급
        const token = jwt.sign({ id }, JWT_SECRET, { expiresIn: '1h' });

        // 회원가입 성공 시 홈으로 리다이렉트 및 JWT 토큰 반환
        return res.json({ message: 'User registered successfully!', token }); // 토큰을 응답으로 반환
    });
});

// 로그인
app.post('/login', async (req, res) => {
    const { id, password } = req.body;

    // 데이터베이스에서 사용자 정보 조회
    db.query('SELECT * FROM users WHERE id = ?', [id], async (err, results) => {
        if (err) {
            console.error(err); // 로그에 에러 출력
            return res.status(500).json({ message: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: 'User not found' });
        }

        // 비밀번호 검증
        const isPasswordValid = await bcrypt.compare(password, results[0].password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // JWT 토큰 발급
        const token = jwt.sign({ id: results[0].id }, JWT_SECRET, { expiresIn: '1h' });
        // 로그인 성공 시 토큰 반환
        return res.json({ token });
    });
});


// 회원가입 페이지
app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/public/register.html'); // 회원가입 페이지를 제공
});

// 로그인 페이지
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/login.html'); // 로그인 페이지를 제공
});

// 기존의 코드에서 /home 경로 수정
app.get('/home', (req, res) => {
    res.sendFile(__dirname + '/public/home.html'); // 홈 페이지 제공
});

// 사용자 정보 제공 API 엔드포인트
app.get('/api/user', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; // Bearer 토큰 추출

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    // JWT 검증
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }

        // 사용자 ID 반환
        res.json({ id: decoded.id });
    });
});

// 로그아웃
app.get('/logout', (req, res) => {
    // 별도의 front 페이지가 없으므로, 로그인 페이지로 리다이렉트
    res.redirect('/login');
});

// 서버 시작
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
