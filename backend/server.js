const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_super_secret_key'; // Change this in production

// Middleware
app.use(cors());
app.use(express.json());
// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));
// Serve uploaded photos
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/sms_db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    fullname: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: String,
    studentId: { type: String, unique: true },
    class: String,
    gender: String,
    role: { type: String, default: 'Student' },
    password: { type: String, required: true },
    photo: String,
    // Dashboard specific fields
    section: { type: String, default: 'A' },
    attendance: { type: Number, default: 0 },
    feesStatus: { type: String, default: 'Pending' }
});

const User = mongoose.model('User', userSchema);

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir);
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });

// --- Routes ---

// 1. Registration Endpoint
app.post('/api/register', upload.single('photo'), async (req, res) => {
    try {
        const { fullname, email, phone, studentid, class: className, gender, role, password } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'Email already exists' });

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            fullname,
            email,
            phone,
            studentId: studentid,
            class: className,
            gender,
            role,
            password: hashedPassword,
            photo: req.file ? req.file.path : null
        });

        await newUser.save();
        res.status(201).json({ message: 'Registration successful' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// 2. Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(401).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token, user: { name: user.fullname, email: user.email } });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login' });
    }
});

// 3. Get Students Endpoint (Protected)
app.get('/api/students', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ message: 'No token provided' });

        const token = authHeader.split(' ')[1];
        jwt.verify(token, SECRET_KEY, async (err, decoded) => {
            if (err) return res.status(403).json({ message: 'Invalid token' });

            // Fetch all users with role 'Student'
            const students = await User.find({ role: 'Student' });
            
            // Map data to match frontend expectations
            const responseData = students.map(s => ({
                id: s._id,
                name: s.fullname,
                studentId: s.studentId,
                class: s.class,
                section: s.section,
                attendance: s.attendance,
                feesStatus: s.feesStatus
            }));

            res.json(responseData);
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching data' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});