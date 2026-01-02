const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const admin = require('firebase-admin');
const webpush = require('web-push');
const serviceAccount = require('./serviceAccountKey.json');

// Web Push Config
const publicVapidKey = 'BJQKFvycAUDrhCaS_0EgCTIEnDt9jgM1r4NAkJxXneKX8gUHhlfoXaygA1V6jmrzoHBz3yJrfoG-UECtY7EsYAA';
const privateVapidKey = 'yWDbSidVLLQbdZ28HYwMumQPCI3qNcFSQYTV88SQ190';

webpush.setVapidDetails(
    'mailto:your-email@example.com',
    publicVapidKey,
    privateVapidKey
);
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// Last updated: 2025-12-28 20:08 - Force Render rebuild

const app = express();

// ============= SECURITY SETTINGS =============
// Rate limiting - حماية من هجمات DDoS (تم تخفيفها)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 50000, // حد أقصى 50000 طلب لكل IP
    message: { success: false, message: 'طلبات كثيرة جداً. حاول لاحقاً.' }
});

const strictLimiter = rateLimit({
    windowMs: 60 * 1000, // دقيقة واحدة
    max: 100, // 100 محاولات فقط
    message: { success: false, message: 'محاولات كثيرة. انتظر دقيقة.' }
});

// CORS - تحديد المصادر المسموحة
const corsOptions = {
    origin: ['https://bankak-server.vercel.app', 'https://bankak-server.onrender.com', 'http://localhost:3000'],
    methods: ['GET', 'POST'],
    credentials: true
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(limiter); // Rate limiting على كل الطلبات

// Serve static files (admin panel)
const path = require('path');
app.use('/admin', express.static(path.join(__dirname, '../admin')));
app.use(express.static(path.join(__dirname, '../admin')));

// JWT Secret - من متغير بيئة
const JWT_SECRET = process.env.JWT_SECRET || 'snox_jwt_secret_2025_secure_key';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'snox_admin_2025';

// Firebase initialization
let db;
let firebaseError = null;
try {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;

    // Log environment check
    console.log('Firebase Config Check:', {
        hasProjectId: !!projectId,
        hasClientEmail: !!clientEmail,
        hasPrivateKey: !!privateKey,
        privateKeyLength: privateKey?.length
    });

    if (projectId && clientEmail && privateKey) {
        // Handle different formats of private key
        if (privateKey.includes('\\n')) {
            privateKey = privateKey.replace(/\\n/g, '\n');
        }

        if (!admin.apps.length) {
            admin.initializeApp({
                credential: admin.credential.cert({
                    projectId: projectId,
                    clientEmail: clientEmail,
                    privateKey: privateKey
                })
            });
        }
        db = admin.firestore();
        console.log('Firebase initialized successfully');
    } else {
        console.log('Firebase credentials missing');
        firebaseError = 'Missing credentials';
    }
} catch (error) {
    console.error('Firebase init error:', error.message);
    firebaseError = error.message;
}

// Secret key for HMAC - من متغير بيئة
const SECRET_KEY = process.env.HMAC_SECRET || 'jhgjhd757487gvgjdf687cb843gvgeg&%FGSVG&&766757dc^ggcjs9900';

// ============= ADMIN AUTH MIDDLEWARE =============
function verifyAdminToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1] || req.headers['x-admin-token'];

    if (!token) {
        return res.status(401).json({ success: false, message: 'غير مصرح - يرجى تسجيل الدخول' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'غير مصرح بالوصول' });
        }
        req.admin = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'جلسة منتهية - أعد تسجيل الدخول' });
    }
}

// ============= AGENT AUTH MIDDLEWARE =============
function verifyAgentToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1] || req.headers['x-agent-token'];

    if (!token) {
        return res.status(401).json({ success: false, message: 'غير مصرح - يرجى تسجيل الدخول' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'agent') {
            return res.status(403).json({ success: false, message: 'غير مصرح بالوصول' });
        }
        req.agent = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'جلسة منتهية - أعد تسجيل الدخول' });
    }
}

// Helper: Hash password
async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
}

// Helper: Verify password
async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// Generate auth hash (same algorithm as app)
function generateAuthHash(params) {
    const sortedKeys = Object.keys(params).filter(k => k !== 'auth_hash').sort();
    let dataToHash = '';
    sortedKeys.forEach(key => {
        dataToHash += key + '=' + params[key];
    });

    const hmac = crypto.createHmac('sha256', SECRET_KEY);
    hmac.update(dataToHash);
    return hmac.digest('hex');
}

// ============= LOGIN API =============
app.post('/api/login.php', async (req, res) => {
    try {
        const { account_number, password, device_id, app_version } = req.body;

        console.log('Login attempt:', { account_number, device_id });

        // Check if Firestore is available
        if (!db) {
            console.error('Firestore not available');
            return res.json({
                success: false,
                app_status: 'error',
                message: 'خطأ في الاتصال بقاعدة البيانات'
            });
        }

        // Check account in Firestore
        const accountRef = db.collection('accounts').doc(account_number);
        const doc = await accountRef.get();

        if (doc.exists) {
            const accountData = doc.data();

            // Check if password matches
            if (accountData.password && accountData.password !== password) {
                return res.json({
                    success: false,
                    app_status: 'error',
                    message: 'كلمة المرور غير صحيحة'
                });
            }

            // Check if active
            const status = accountData.status || 'inactive'; // Default to inactive for old accounts if field missing? Or active?
            // Actually, for backward compatibility, maybe default to active if missing?
            // But user said "don't work unless activated".
            // Let's check status.

            if (accountData.banned) {
                return res.json({
                    success: false,
                    app_status: 'banned',
                    message: 'تم حظر حسابك'
                });
            }

            if (status !== 'active') {
                return res.json({
                    success: false,
                    app_status: 'inactive',
                    message: 'الحساب غير نشط. يرجى التواصل مع أقرب وكيل لتفعيل حسابك.'
                });
            }

            // Update device_id and last_login
            await accountRef.update({
                device_id: device_id,
                last_login: admin.firestore.FieldValue.serverTimestamp()
            });

            return res.json({
                success: true,
                message: 'تم تسجيل الدخول بنجاح',
                username: accountData.account_name || 'مستخدم بنكك',
                balance: accountData.balance || 2000,
                general_message: '',
                app_status: 'success'
            });
        } else {
            // Account not found - reject login
            return res.json({
                success: false,
                app_status: 'error',
                message: 'الحساب غير موجود. يرجى إنشاء حساب جديد أولاً.'
            });
        }
    } catch (error) {
        console.error('Login error:', error);
        return res.json({
            success: false,
            app_status: 'error',
            message: 'حدث خطأ في تسجيل الدخول. يرجى المحاولة لاحقاً.'
        });
    }
});

// ============= CHECK INTERNAL ACCOUNT =============
app.post('/api/check_internal_account.php', async (req, res) => {
    try {
        const { account_number, short_number, short_account_number } = req.body;
        const searchNumber = account_number || short_number || short_account_number;

        console.log('Checking account:', searchNumber);

        if (!db) {
            return res.json({
                success: true,
                exists: true,
                message: 'الحساب موجود'
            });
        }

        // Search by account number or create if not exists
        const accountRef = db.collection('accounts').doc(searchNumber);
        const doc = await accountRef.get();

        if (doc.exists) {
            res.json({
                success: true,
                exists: true,
                message: 'الحساب موجود',
                account: doc.data()
            });
        } else {
            // Account not found - Log request and return error message
            try {
                const missingRef = db.collection('missing_accounts').doc(searchNumber);
                await missingRef.set({
                    account_number: searchNumber,
                    timestamp: admin.firestore.FieldValue.serverTimestamp(),
                    status: 'pending'
                });
            } catch (err) {
                console.error('Error logging missing account:', err);
            }

            res.json({
                success: false,
                exists: false,
                message: 'الرجاء الانتظار خمس دقائق فقط يتم اضافة الحساب فورا زبونا فوق راسنا وراحتك تهمنا'
            });
        }
    } catch (error) {
        res.json({ success: true, exists: true, message: 'الحساب صالح' });
    }
});

// ============= FETCH ACCOUNT DETAILS =============
app.post('/api/fetch_account_details.php', async (req, res) => {
    try {
        const { account_number, short_number, short_account_number } = req.body;
        const searchNumber = account_number || short_number || short_account_number;

        console.log('Fetching account details:', searchNumber);

        if (!db) {
            return res.json({
                success: true,
                account_number: searchNumber || '0033052713730001',
                account_name: 'محمد أحمد علي',
                account_type: 'حساب جاري',
                branch: 'الخرطوم'
            });
        }

        const accountRef = db.collection('accounts').doc(searchNumber);
        const doc = await accountRef.get();

        if (doc.exists) {
            const data = doc.data();
            res.json({
                success: true,
                account_number: data.account_number,
                account_name: data.account_name,
                account_type: data.account_type || 'حساب جاري',
                branch: data.branch || 'الخرطوم'
            });
        } else {

            // Log missing account for Agent
            try {
                const missingRef = db.collection('missing_accounts').doc(searchNumber);
                await missingRef.set({
                    account_number: searchNumber,
                    timestamp: admin.firestore.FieldValue.serverTimestamp(),
                    status: 'pending'
                });

                // Send Web Push to Agents
                db.collection('subscriptions').get().then(snapshot => {
                    snapshot.forEach(doc => {
                        const subscription = doc.data();
                        const payload = JSON.stringify({
                            title: '🚨 NEW MISSING ACCOUNT!',
                            body: `Request for Account: ${searchNumber}`,
                            icon: 'https://cdn-icons-png.flaticon.com/512/3602/3602145.png'
                        });
                        webpush.sendNotification(subscription, payload).catch(err => console.error("Push Error", err));
                    });
                });
            } catch (err) {
                console.error('Error logging missing account:', err);
            }

            // Return specific message to user
            res.json({
                success: false,
                message: 'الرجاء الانتظار خمس دقائق فقط يتم اضافة الحساب فورا زبونا فوق راسنا وراحتك تهمنا'
            });
        }
    } catch (error) {
        res.json({
            success: true,
            account_number: req.body.account_number || '0033052713730001',
            account_name: 'مستخدم',
            account_type: 'حساب جاري',
            branch: 'الخرطوم'
        });
    }
});

// ============= GET ACCOUNT BY NUMBER (for Agent Search) =============
app.get('/api/account/:account_number', async (req, res) => {
    try {
        const { account_number } = req.params;
        console.log('Agent searching for account:', account_number);

        if (!db) {
            return res.json({ success: false, message: 'Database not available' });
        }

        const accountRef = db.collection('accounts').doc(account_number);
        const doc = await accountRef.get();

        if (doc.exists) {
            const data = doc.data();
            res.json({
                success: true,
                account: {
                    account_number: account_number,
                    account_name: data.account_name || data.name || 'مستخدم',
                    name: data.account_name || data.name || 'مستخدم',
                    balance: data.balance || 0,
                    status: data.status || (data.banned ? 'banned' : 'active'),
                    banned: data.banned || false,
                    whatsapp: data.whatsapp || ''
                }
            });
        } else {
            res.json({ success: false, message: 'الحساب غير موجود' });
        }
    } catch (error) {
        console.error('Error fetching account:', error);
        res.json({ success: false, message: error.message });
    }
});

// ============= SAVE ACCOUNT DETAILS =============
app.post('/api/save_account_details.php', async (req, res) => {
    try {
        const data = req.body;
        console.log('Saving account:', data);

        if (!db) {
            return res.json({ success: true, message: 'تم الحفظ بنجاح' });
        }

        const accountRef = db.collection('accounts').doc(data.account_number);
        await accountRef.set(data, { merge: true });

        res.json({ success: true, message: 'تم حفظ بيانات الحساب بنجاح' });
    } catch (error) {
        res.json({ success: true, message: 'تم الحفظ' });
    }
});

// ============= FETCH BALANCE =============
app.post('/api/fetch_balance.php', async (req, res) => {
    try {
        const { account_number } = req.body;

        console.log('Fetching balance for:', account_number);

        if (!db) {
            return res.json({ success: true, balance: 100000 });
        }

        const accountRef = db.collection('accounts').doc(account_number);
        const doc = await accountRef.get();

        if (doc.exists) {
            res.json({ success: true, balance: doc.data().balance || 100000 });
        } else {
            res.json({ success: true, balance: 100000 });
        }
    } catch (error) {
        res.json({ success: true, balance: 100000 });
    }
});

// ============= UPDATE BALANCE (TRANSFER) =============
app.post('/api/update_balance.php', async (req, res) => {
    try {
        const {
            transfer_amount,       // App sends transfer_amount
            amount,               // Fallback
            target_account,
            target_account_identifier_for_server, // App sends this
            account_number,       // App sends account_number as source
            source_account,       // Fallback
            comment,
            transaction_id,
            is_internal_transfer,
            is_internal,
            device_time,
            timestamp
        } = req.body;

        console.log('Transfer request body:', req.body);

        // Handle different field names from app
        const transferAmount = parseFloat(transfer_amount) || parseFloat(amount) || 0;
        const sourceAcc = account_number || source_account || '';
        const targetAcc = target_account_identifier_for_server || target_account || '';
        const txId = transaction_id || 'TX' + Date.now();

        console.log('Parsed values:', { transferAmount, sourceAcc, targetAcc, txId });

        if (!db) {
            return res.json({
                success: false,
                message: 'خطأ في الاتصال بقاعدة البيانات'
            });
        }

        // Validate amount
        if (transferAmount <= 0) {
            return res.json({
                success: false,
                message: 'المبلغ يجب أن يكون أكبر من صفر'
            });
        }

        // Get source account and verify balance
        if (!sourceAcc) {
            return res.json({
                success: false,
                message: 'رقم الحساب المصدر مطلوب'
            });
        }

        const sourceRef = db.collection('accounts').doc(sourceAcc);
        const sourceDoc = await sourceRef.get();

        if (!sourceDoc.exists) {
            return res.json({
                success: false,
                message: 'الحساب المصدر غير موجود'
            });
        }

        const currentBalance = sourceDoc.data().balance || 0;

        // Check if balance is sufficient
        if (currentBalance < transferAmount) {
            return res.json({
                success: false,
                message: 'الرصيد غير كافي. رصيدك الحالي: ' + currentBalance + ' جنيه'
            });
        }

        const newBalance = currentBalance - transferAmount;

        // Update source balance
        await sourceRef.update({ balance: newBalance });

        // NOTE: Disabled adding to target account per user request
        // Only deduct from source account

        // Log transaction
        await db.collection('transactions').add({
            source_account: sourceAcc,
            target_account: targetAcc,
            amount: transferAmount,
            comment: comment || '',
            transaction_id: txId,
            is_internal: is_internal === 'true' || is_internal === true,
            type: 'transfer',
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({
            success: true,
            message: 'تمت عملية التحويل بنجاح',
            new_balance: newBalance,
            transaction_id: txId
        });
    } catch (error) {
        console.error('Transfer error:', error);
        res.json({
            success: true,
            message: 'تمت العملية',
            new_balance: 100000,
            transaction_id: 'TX' + Date.now()
        });
    }
});

// ============= GET TRANSACTIONS =============
app.post('/api/get_transactions1.php', async (req, res) => {
    try {
        const { account_number, filter_type } = req.body;
        console.log('Getting transactions for:', account_number);

        if (!db) {
            return res.json({ success: true, transactions: [] });
        }

        const allTransactions = await db.collection('transactions').limit(100).get();
        const transactions = [];

        allTransactions.forEach(doc => {
            const data = doc.data();
            let dateStr = new Date().toISOString().split('T')[0];

            try {
                if (data.timestamp && data.timestamp.toDate) {
                    dateStr = data.timestamp.toDate().toISOString().split('T')[0];
                }
            } catch (e) { }

            if (data.source_account === account_number) {
                transactions.push({
                    date: dateStr,
                    amount: data.amount || 0,
                    type: 'debit',
                    description: 'تحويل',
                    transaction_id: data.transaction_id || doc.id
                });
            } else if (data.target_account === account_number) {
                transactions.push({
                    date: dateStr,
                    amount: data.amount || 0,
                    type: 'credit',
                    description: 'إضافة رصيد',
                    transaction_id: data.transaction_id || doc.id
                });
            }
        });

        res.json({ success: true, transactions: transactions });
    } catch (error) {
        console.error('Get transactions error:', error);
        res.json({ success: true, transactions: [] });
    }
});

// ============= ENCRYPTION HANDLER =============
app.post('/api/encryption_handler.php', async (req, res) => {
    try {
        const data = req.body;
        const hash = generateAuthHash(data);
        res.json({ success: true, hash: hash });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ============= UPLOAD IMAGES =============
app.post('/api/upload_images.php', async (req, res) => {
    res.json({
        success: true,
        message: 'تم رفع الصورة بنجاح',
        url: '/uploads/placeholder.jpg'
    });
});

// ============= HEALTH CHECK =============
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        firebase: {
            connected: !!db,
            error: firebaseError
        }
    });
});

// ============= ADMIN APIs =============

// تسجيل دخول الأدمن
app.post('/api/admin/login', strictLimiter, async (req, res) => {
    try {
        const { password } = req.body;

        if (password === ADMIN_PASSWORD) {
            const token = jwt.sign(
                { role: 'admin', loginTime: Date.now() },
                JWT_SECRET,
                { expiresIn: '2h' }
            );

            return res.json({
                success: true,
                message: 'تم تسجيل الدخول بنجاح',
                token: token
            });
        }

        return res.status(401).json({
            success: false,
            message: 'كلمة المرور غير صحيحة'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'حدث خطأ في تسجيل الدخول'
        });
    }
});

// التحقق من صلاحية التوكن
app.get('/api/admin/verify', verifyAdminToken, (req, res) => {
    res.json({ success: true, message: 'التوكن صالح' });
});

// الحصول على الحسابات - محمي
app.get('/api/admin/accounts', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ accounts: [] });
        const snapshot = await db.collection('accounts').orderBy('created_at', 'desc').get();
        const accounts = [];
        // إخفاء كلمات المرور من النتائج
        snapshot.forEach(doc => {
            const data = doc.data();
            delete data.password_hash; // لا نرسل الـ hash
            accounts.push({ id: doc.id, ...data });
        });
        res.json({ accounts });
    } catch (error) {
        res.json({ accounts: [] });
    }
});

app.get('/api/admin/transactions', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ transactions: [] });
        const snapshot = await db.collection('transactions').orderBy('timestamp', 'desc').get();
        const transactions = [];
        snapshot.forEach(doc => transactions.push({ id: doc.id, ...doc.data() }));
        res.json({ transactions });
    } catch (error) {
        res.json({ transactions: [] });
    }
});

app.post('/api/admin/accounts', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true });
        const data = req.body;
        // تشفير كلمة المرور إذا وجدت
        if (data.password) {
            data.password_hash = await hashPassword(data.password);
            delete data.password;
        }
        await db.collection('accounts').doc(data.account_number).set(data);
        res.json({ success: true, message: 'تم إضافة الحساب' });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.post('/api/admin/ban', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true });
        const { account_number, banned, ban_reason } = req.body;
        await db.collection('accounts').doc(account_number).update({
            banned: banned,
            ban_reason: ban_reason
        });
        res.json({ success: true, message: banned ? 'تم حظر الحساب' : 'تم إلغاء الحظر' });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Mass Deactivate Accounts
app.post('/api/admin/deactivate-all', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true, message: 'No DB' });

        const snapshot = await db.collection('accounts').get();
        const batches = [];
        let batch = db.batch();
        let count = 0;
        let batchCount = 0;

        snapshot.forEach(doc => {
            const ref = db.collection('accounts').doc(doc.id);
            batch.update(ref, { status: 'inactive' });
            count++;
            batchCount++;

            if (batchCount >= 500) {
                batches.push(batch.commit());
                batch = db.batch();
                batchCount = 0;
            }
        });

        if (batchCount > 0) {
            batches.push(batch.commit());
        }

        await Promise.all(batches);

        res.json({ success: true, message: `تم إلغاء تنشيط ${count} حساب بنجاح` });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ============= PUBLIC REGISTRATION =============
app.post('/api/register', async (req, res) => {
    try {
        const { name, password, whatsapp } = req.body;

        // Validate
        if (!name || !password) {
            return res.json({ success: false, message: 'يرجى ملء جميع الحقول المطلوبة' });
        }

        if (password.length < 4) {
            return res.json({ success: false, message: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل' });
        }

        // Generate random 7-digit account number
        const accountNumber = String(Math.floor(1000000 + Math.random() * 9000000));

        const newAccount = {
            account_number: accountNumber,
            account_name: name,
            password: password,
            whatsapp: whatsapp || '',
            balance: 2000, // Fixed starting balance
            account_type: 'حساب جاري',
            branch: 'الخرطوم',
            account_type: 'حساب جاري',
            branch: 'الخرطوم',
            banned: false,
            status: 'inactive', // Default status for new users
            created_at: db ? admin.firestore.FieldValue.serverTimestamp() : new Date().toISOString()
        };

        if (db) {
            await db.collection('accounts').doc(accountNumber).set(newAccount);
        }

        console.log('New account created:', accountNumber);

        res.json({
            success: true,
            message: 'تم إنشاء الحساب بنجاح',
            account_number: accountNumber,
            name: name,
            balance: 2000
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.json({ success: false, message: 'حدث خطأ أثناء إنشاء الحساب: ' + error.message });
    }
});

// ============= ADMIN UPDATE ACCOUNT =============
app.post('/api/admin/update-account', async (req, res) => {
    try {
        if (!db) return res.json({ success: true });
        const { account_number, account_name, password, whatsapp } = req.body;

        const updateData = {};
        if (account_name) updateData.account_name = account_name;
        if (password) updateData.password = password;
        if (whatsapp !== undefined) updateData.whatsapp = whatsapp;

        await db.collection('accounts').doc(account_number).update(updateData);

        res.json({ success: true, message: 'تم تحديث الحساب بنجاح' });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ============= ADMIN ADD BALANCE =============
app.post('/api/admin/add-balance', async (req, res) => {
    try {
        if (!db) return res.json({ success: true });
        const { account_number, amount } = req.body;

        const accountRef = db.collection('accounts').doc(account_number);
        const doc = await accountRef.get();

        if (!doc.exists) {
            return res.json({ success: false, message: 'الحساب غير موجود' });
        }

        const currentBalance = doc.data().balance || 0;
        const newBalance = currentBalance + parseFloat(amount);

        await accountRef.update({ balance: newBalance });

        // Log the transaction
        await db.collection('transactions').add({
            target_account: account_number,
            amount: parseFloat(amount),
            type: 'admin_credit',
            comment: 'إضافة رصيد من الأدمن',
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });


        res.json({
            success: true,
            message: `تم إضافة ${amount} جنيه. الرصيد الجديد: ${newBalance}`,
            new_balance: newBalance
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ============= AGENT SYSTEM =============

// Admin: Get all agents
app.get('/api/admin/agents', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true, agents: [] });

        const snapshot = await db.collection('agents').get();
        const agents = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            agents.push({
                id: doc.id,
                username: data.username,
                name: data.name,
                balance: data.balance || 0,
                created_at: data.created_at,
                status: data.status || 'active'
            });
        });

        res.json({ success: true, agents });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Admin: Create new agent
app.post('/api/admin/agents', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true });
        const { username, password, name, balance } = req.body;

        if (!username || !password || !name) {
            return res.json({ success: false, message: 'جميع الحقول مطلوبة' });
        }

        // Check if username exists
        const existing = await db.collection('agents').doc(username.toLowerCase()).get();
        if (existing.exists) {
            return res.json({ success: false, message: 'اسم المستخدم موجود مسبقاً' });
        }

        const hashedPassword = await hashPassword(password);

        await db.collection('agents').doc(username.toLowerCase()).set({
            username: username.toLowerCase(),
            password_hash: hashedPassword,
            name: name,
            balance: parseFloat(balance) || 0,
            status: 'active',
            created_at: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ success: true, message: `تم إنشاء الوكيل ${name} بنجاح` });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Admin: Add balance to agent
app.post('/api/admin/agents/add-balance', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true });
        const { agent_id, amount } = req.body;

        const agentRef = db.collection('agents').doc(agent_id);
        const doc = await agentRef.get();

        if (!doc.exists) {
            return res.json({ success: false, message: 'الوكيل غير موجود' });
        }

        const currentBalance = doc.data().balance || 0;
        const newBalance = currentBalance + parseFloat(amount);

        await agentRef.update({ balance: newBalance });

        // Log transaction
        await db.collection('agent_transactions').add({
            agent_id: agent_id,
            type: 'admin_credit',
            amount: parseFloat(amount),
            balance_after: newBalance,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({
            success: true,
            message: `تم شحن ${amount} جنيه للوكيل. الرصيد الجديد: ${newBalance}`,
            new_balance: newBalance
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Admin: Delete/Disable agent
app.post('/api/admin/agents/toggle-status', verifyAdminToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true });
        const { agent_id } = req.body;

        const agentRef = db.collection('agents').doc(agent_id);
        const doc = await agentRef.get();

        if (!doc.exists) {
            return res.json({ success: false, message: 'الوكيل غير موجود' });
        }

        const currentStatus = doc.data().status || 'active';
        const newStatus = currentStatus === 'active' ? 'disabled' : 'active';

        await agentRef.update({ status: newStatus });

        res.json({
            success: true,
            message: newStatus === 'active' ? 'تم تفعيل الوكيل' : 'تم تعطيل الوكيل',
            new_status: newStatus
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Agent: Login
app.post('/api/agent/login', strictLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!db) {
            return res.json({ success: false, message: 'Database not available' });
        }

        const agentDoc = await db.collection('agents').doc(username.toLowerCase()).get();

        if (!agentDoc.exists) {
            return res.json({ success: false, message: 'اسم المستخدم غير موجود' });
        }

        const agentData = agentDoc.data();

        if (agentData.status === 'disabled') {
            return res.json({ success: false, message: 'الحساب معطل - تواصل مع الإدارة' });
        }

        const validPassword = await verifyPassword(password, agentData.password_hash);

        if (!validPassword) {
            return res.json({ success: false, message: 'كلمة المرور غير صحيحة' });
        }

        const token = jwt.sign(
            { role: 'agent', username: agentData.username, name: agentData.name },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({
            success: true,
            token: token,
            agent: {
                username: agentData.username,
                name: agentData.name,
                balance: agentData.balance || 0
            }
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Middleware: Verify Agent Token
function verifyAgentToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1] || req.headers['x-agent-token'];

    if (!token) {
        return res.status(401).json({ success: false, message: 'غير مصرح - يرجى تسجيل الدخول' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'agent') {
            return res.status(403).json({ success: false, message: 'غير مصرح بالوصول' });
        }
        req.agent = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'جلسة منتهية - أعد تسجيل الدخول' });
    }
}

// Agent: Get own balance
app.get('/api/agent/balance', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true, balance: 0 });

        const agentDoc = await db.collection('agents').doc(req.agent.username).get();

        if (!agentDoc.exists) {
            return res.json({ success: false, message: 'الحساب غير موجود' });
        }

        res.json({
            success: true,
            balance: agentDoc.data().balance || 0
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Agent: Recharge user account
app.post('/api/agent/recharge', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'Database not available' });

        const { account_number, amount } = req.body;
        const agentUsername = req.agent.username;

        if (!account_number || !amount || amount <= 0) {
            return res.json({ success: false, message: 'بيانات غير صالحة' });
        }

        // Get agent balance
        const agentRef = db.collection('agents').doc(agentUsername);
        const agentDoc = await agentRef.get();

        if (!agentDoc.exists) {
            return res.json({ success: false, message: 'حساب الوكيل غير موجود' });
        }

        const agentBalance = agentDoc.data().balance || 0;

        if (agentBalance < amount) {
            return res.json({
                success: false,
                message: `رصيدك غير كافي. رصيدك الحالي: ${agentBalance} جنيه`
            });
        }

        // Get user account
        const accountRef = db.collection('accounts').doc(account_number);
        const accountDoc = await accountRef.get();

        if (!accountDoc.exists) {
            return res.json({ success: false, message: 'حساب العميل غير موجود' });
        }

        const currentUserBalance = accountDoc.data().balance || 0;
        const newUserBalance = currentUserBalance + parseFloat(amount);
        const newAgentBalance = agentBalance - parseFloat(amount);

        // Update both balances
        await accountRef.update({ balance: newUserBalance });
        await agentRef.update({ balance: newAgentBalance });

        // Log transactions
        await db.collection('transactions').add({
            source_account: 'AGENT:' + agentUsername,
            target_account: account_number,
            amount: parseFloat(amount),
            type: 'agent_recharge',
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        await db.collection('agent_transactions').add({
            agent_id: agentUsername,
            type: 'user_recharge',
            target_account: account_number,
            amount: parseFloat(amount),
            balance_after: newAgentBalance,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({
            success: true,
            message: `تم شحن ${amount} جنيه بنجاح`,
            newUserBalance: newUserBalance,
            newAgentBalance: newAgentBalance
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Agent: Get recharge history
app.get('/api/agent/transactions', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true, transactions: [] });

        const snapshot = await db.collection('agent_transactions')
            .where('agent_id', '==', req.agent.username)
            .orderBy('timestamp', 'desc')
            .limit(50)
            .get();

        const transactions = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            transactions.push({
                id: doc.id,
                type: data.type,
                amount: data.amount,
                target_account: data.target_account,
                balance_after: data.balance_after,
                timestamp: data.timestamp?.toDate?.()?.toISOString() || null
            });
        });

        res.json({ success: true, transactions });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ============= AGENT ENDPOINTS =============

// Agent: Login
app.post('/api/agent/login', strictLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!db) {
            return res.json({ success: false, message: 'Database error' });
        }

        const agentRef = db.collection('agents').doc(username);
        const doc = await agentRef.get();

        if (!doc.exists) {
            return res.json({ success: false, message: 'اسم المستخدم غير موجود' });
        }

        const agentData = doc.data();

        // Check password
        const isValidPassword = await verifyPassword(password, agentData.password_hash);
        if (!isValidPassword && password !== agentData.password) {
            return res.json({ success: false, message: 'كلمة المرور غير صحيحة' });
        }

        // Check if agent is active
        if (agentData.status === 'inactive') {
            return res.json({ success: false, message: 'الحساب معطل' });
        }

        // Generate token
        const token = jwt.sign(
            { username: username, role: 'agent', name: agentData.name },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'تم تسجيل الدخول بنجاح',
            token: token,
            agent: {
                username: username,
                name: agentData.name,
                balance: agentData.balance || 0
            }
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Agent: Get Balance
app.get('/api/agent/balance', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'Database error' });

        const agentRef = db.collection('agents').doc(req.agent.username);
        const doc = await agentRef.get();

        if (!doc.exists) {
            return res.json({ success: false, message: 'الوكيل غير موجود' });
        }

        res.json({
            success: true,
            balance: doc.data().balance || 0
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Agent: Recharge User Account
app.post('/api/agent/recharge', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'Database error' });

        const { account_number, amount } = req.body;
        const agentUsername = req.agent.username;

        if (!account_number || !amount || amount <= 0) {
            return res.json({ success: false, message: 'بيانات غير صحيحة' });
        }

        // Get agent balance
        const agentRef = db.collection('agents').doc(agentUsername);
        const agentDoc = await agentRef.get();

        if (!agentDoc.exists) {
            return res.json({ success: false, message: 'الوكيل غير موجود' });
        }

        const agentBalance = agentDoc.data().balance || 0;

        if (agentBalance < amount) {
            return res.json({ success: false, message: 'رصيدك غير كافي' });
        }

        // Get user account
        const accountRef = db.collection('accounts').doc(account_number);
        const accountDoc = await accountRef.get();

        if (!accountDoc.exists) {
            return res.json({ success: false, message: 'الحساب غير موجود' });
        }

        const currentBalance = accountDoc.data().balance || 0;
        const newBalance = currentBalance + parseInt(amount);

        // Update user balance
        await accountRef.update({ balance: newBalance });

        // Deduct from agent balance
        await agentRef.update({ balance: agentBalance - parseInt(amount) });

        // Log transaction
        await db.collection('transactions').add({
            type: 'agent_recharge',
            source_account: 'AGENT:' + agentUsername,
            target_account: account_number,
            amount: parseInt(amount),
            balance_after: newBalance,
            agent_id: agentUsername,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({
            success: true,
            message: 'تم شحن الحساب بنجاح',
            new_balance: newBalance
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Agent: Get Transactions
app.get('/api/agent/transactions', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: true, transactions: [] });

        const agentUsername = req.agent.username;
        const snapshot = await db.collection('transactions')
            .where('agent_id', '==', agentUsername)
            .orderBy('timestamp', 'desc')
            .limit(50)
            .get();

        const transactions = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            transactions.push({
                id: doc.id,
                type: data.type,
                amount: data.amount,
                target_account: data.target_account,
                balance_after: data.balance_after,
                timestamp: data.timestamp?.toDate?.()?.toISOString() || null
            });
        });

        res.json({ success: true, transactions });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Agent: Update User Account
app.post('/api/agent/update-user-account', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'Database error' });
        const { account_number, account_name, password, whatsapp } = req.body;

        const accountRef = db.collection('accounts').doc(account_number);
        const doc = await accountRef.get();

        if (!doc.exists) {
            return res.json({ success: false, message: 'الحساب غير موجود' });
        }

        const updateData = {};
        if (account_name) updateData.account_name = account_name;
        if (password) updateData.password = password; // Only update if provided
        if (whatsapp !== undefined) updateData.whatsapp = whatsapp;

        await accountRef.update(updateData);

        // Log action
        await db.collection('agent_logs').add({
            agent_id: req.agent.username,
            action: 'update_user_info',
            target_account: account_number,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ success: true, message: 'تم تحديث بيانات الحساب بنجاح' });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Agent: Block/Unblock user account
app.post('/api/agent/toggle-account-status', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'Database error' });
        const { account_number } = req.body;

        const accountRef = db.collection('accounts').doc(account_number);
        const doc = await accountRef.get();

        if (!doc.exists) {
            return res.json({ success: false, message: 'الحساب غير موجود' });
        }

        const currentStatus = doc.data().status || 'active';
        const isCurrentlyBanned = doc.data().banned || false;

        if (currentStatus === 'active') {
            newStatus = 'inactive';
        } else {
            newStatus = 'active';
        }

        await accountRef.update({
            status: newStatus,
            banned: false // Ensure banned is false when activating/deactivating via this new flow
        });

        // Log action
        await db.collection('agent_logs').add({
            agent_id: req.agent.username,
            action: newStatus === 'active' ? 'activate_user' : 'deactivate_user',
            target_account: account_number,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({
            success: true,
            message: newStatus === 'active' ? 'تم تفعيل الحساب بنجاح' : 'تم تعطيل الحساب بنجاح',
            new_status: newStatus
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ============= QR BENEFICIARIES MANAGEMENT =============

// Save QR Beneficiary
app.post('/api/qr/save', async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'Database error' });

        const { qr_code, account_number, beneficiary_name, account_type, branch, user_id } = req.body;

        if (!qr_code || !account_number) {
            return res.json({ success: false, message: 'QR code and account number are required' });
        }

        await db.collection('qr_beneficiaries').doc(qr_code).set({
            qr_code: qr_code,
            account_number: account_number,
            beneficiary_name: beneficiary_name || '',
            account_type: account_type || '',
            branch: branch || '',
            user_id: user_id || '',
            created_at: admin.firestore.FieldValue.serverTimestamp(),
            updated_at: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        res.json({ success: true, message: 'تم حفظ المستفيد بنجاح' });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Get QR Beneficiary by code
app.get('/api/qr/get/:code', async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'Database error' });

        const { code } = req.params;
        const doc = await db.collection('qr_beneficiaries').doc(code).get();

        if (doc.exists) {
            res.json({ success: true, beneficiary: doc.data() });
        } else {
            res.json({ success: false, message: 'QR غير موجود' });
        }
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// List all QR Beneficiaries for a user
app.get('/api/qr/list', async (req, res) => {
    try {
        if (!db) return res.json({ success: true, beneficiaries: [] });

        const user_id = req.query.user_id || '';
        let query = db.collection('qr_beneficiaries');

        if (user_id) {
            query = query.where('user_id', '==', user_id);
        }

        const snapshot = await query.orderBy('created_at', 'desc').limit(50).get();
        const beneficiaries = [];

        snapshot.forEach(doc => {
            beneficiaries.push(doc.data());
        });

        res.json({ success: true, beneficiaries });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Delete QR Beneficiary
app.delete('/api/qr/delete/:code', async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'Database error' });

        const { code } = req.params;
        await db.collection('qr_beneficiaries').doc(code).delete();

        res.json({ success: true, message: 'تم حذف المستفيد بنجاح' });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});


// ============= MISSING ACCOUNTS API (Agent) =============

// Get all pending missing accounts
app.get('/api/agent/missing_accounts', verifyAgentToken, async (req, res) => {
    try {
        if (!db) return res.json({ success: false, message: 'DB Error' });

        const snapshot = await db.collection('missing_accounts')
            .where('status', '==', 'pending')
            .get();

        const requests = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            requests.push({
                account_number: doc.id,
                time: data.timestamp ? data.timestamp.toDate() : new Date(),
                status: data.status
            });
        });

        res.json({ success: true, requests });
    } catch (error) {
        console.error('Error fetching missing accounts:', error);
        res.json({ success: false, message: error.message });
    }
});

// Resolve missing account request
app.post('/api/agent/resolve_missing_account', verifyAgentToken, async (req, res) => {
    try {
        const { account_number } = req.body;
        if (!db) return res.json({ success: false, message: 'DB Error' });

        // Remove from missing_accounts or mark as resolved
        await db.collection('missing_accounts').doc(account_number).delete();

        res.json({ success: true, message: 'تمت إزالة الطلب بنجاح' });
    } catch (error) {
        console.error('Error resolving request:', error);
        res.json({ success: false, message: error.message });
    }
});

app.post('/api/subscribe', async (req, res) => {
    try {
        const subscription = req.body;
        // Save subscription to DB (keyed by endpoint to avoid duplicates)
        // In real app, associate with agent ID
        await db.collection('subscriptions').doc(crypto.createHash('md5').update(subscription.endpoint).digest("hex")).set(subscription);

        res.status(201).json({});
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Bankak Server running on port ${PORT}`);
});

module.exports = app;

