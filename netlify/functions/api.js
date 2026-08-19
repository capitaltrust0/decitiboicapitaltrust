const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const nodemailer = require('nodemailer'); 

// Configuration from Environment Variables
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const MASTER_ACCESS_KEY = process.env.MASTER_ACCESS_KEY;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

// HARDENED S3 CONFIGURATION
const rawEndpoint = process.env.E2_ENDPOINT;

// We only initialize the endpoint if it actually exists to prevent 502 crashes
const s3Config = {
    accessKeyId: (process.env.E2_ACCESS_KEY || '').trim(), 
    secretAccessKey: (process.env.E2_SECRET_KEY || '').trim(),
    region: process.env.E2_REGION || 'us-west-1',
    s3ForcePathStyle: true,
    signatureVersion: 'v4'
};

if (rawEndpoint) {
    s3Config.endpoint = new AWS.Endpoint(rawEndpoint);
}

const s3 = new AWS.S3(s3Config);

let cachedDb = null;

async function connectToDatabase() {
    if (cachedDb) return cachedDb;
    const client = await MongoClient.connect(MONGODB_URI);
    cachedDb = client.db('capital_suntrust');
    return cachedDb;
}

// Token Verification Helper
function verifyToken(event, requiredRole = null) {
    try {
        const authHeader = event.headers.authorization || event.headers.Authorization;
        if (!authHeader) return null;

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        if (requiredRole && decoded.role !== requiredRole) return null;
        return decoded;
    } catch (err) {
        return null;
    }
}

exports.handler = async (event, context) => {
    // 1. STANDARD HEADERS (Ensuring JSON content type)
    const headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Content-Type": "application/json"
    };

    // 2. PREFLIGHT HANDLING
    if (event.httpMethod === "OPTIONS") {
        return { statusCode: 200, headers, body: "OK" };
    }

    try {
        // 3. DATABASE CONNECTION
        const db = await connectToDatabase();
        
        if (!event.body) {
            return { 
                statusCode: 400, 
                headers, 
                body: JSON.stringify({ message: "Empty request body" }) 
            };
        }

        const body = JSON.parse(event.body);
        const { action } = body;
        console.log(`Action Received: ${action}`);

        // 4. ROUTER SWITCH
        switch (action) {
            // --- USER REGISTRATION ---
            case 'user-register':
                // 1. Verify if user already exists
                const existingUser = await db.collection('users').findOne({ email: body.email });
                if (existingUser) {
                    return { 
                        statusCode: 400, 
                        headers, 
                        body: JSON.stringify({ message: "Email already exists." }) 
                    };
                }

                // 2. Hash password for security
                const userHash = await bcrypt.hash(body.password, 10);
                
                // 3. Helper for account numbers
                const generateAccNo = () => Math.floor(1000000000 + Math.random() * 9000000000).toString();

               const countryToCurrency = { 
        // North America & Central America
        'US': 'USD', 'USA': 'USD', 'UNITED STATES': 'USD',
        'MX': 'MXN', 'MEXICO': 'MXN',
        'CA': 'CAD', 'CANADA': 'CAD',
        'SV': 'USD', 'EL SALVADOR': 'USD',
        'BZ': 'BZD', 'BELIZE': 'BZD',
        'CR': 'CRC', 'COSTA RICA': 'CRC',
        'GT': 'GTQ', 'GUATEMALA': 'GTQ',
        'HN': 'HNL', 'HONDURAS': 'HNL',
        'NI': 'NIO', 'NICARAGUA': 'NIO',
        'PA': 'PAB', 'PANAMA': 'PAB',
        
        // Caribbean (North America region)
        'BS': 'BSD', 'BAHAMAS': 'BSD',
        'BB': 'BBD', 'BARBADOS': 'BBD',
        'CU': 'CUP', 'CUBA': 'CUP',
        'DO': 'DOP', 'DOMINICAN REPUBLIC': 'DOP',
        'HT': 'HTG', 'HAITI': 'HTG',
        'JM': 'JMD', 'JAMAICA': 'JMD',
        'TT': 'TTD', 'TRINIDAD AND TOBAGO': 'TTD',

        // South America
        'AR': 'ARS', 'ARGENTINA': 'ARS',
        'BO': 'BOB', 'BOLIVIA': 'BOB',
        'BR': 'BRL', 'BRAZIL': 'BRL',
        'CL': 'CLP', 'CHILE': 'CLP',
        'CO': 'COP', 'COLOMBIA': 'COP',
        'EC': 'USD', 'ECUADOR': 'USD',
        'GY': 'GYD', 'GUYANA': 'GYD',
        'PY': 'PYG', 'PARAGUAY': 'PYG',
        'PE': 'PEN', 'PERU': 'PEN',
        'SR': 'SRD', 'SURINAME': 'SRD',
        'UY': 'UYU', 'URUGUAY': 'UYU',
        'VE': 'VES', 'VENEZUELA': 'VES',

        // UK
        'UK': 'GBP', 'GB': 'GBP', 'UNITED KINGDOM': 'GBP',
        
        // Euro Zone (Expanded)
        'DE': 'EUR', 'GERMANY': 'EUR',
        'FR': 'EUR', 'FRANCE': 'EUR',
        'IT': 'EUR', 'ITALY': 'EUR',
        'ES': 'EUR', 'SPAIN': 'EUR',
        'NL': 'EUR', 'NETHERLANDS': 'EUR',
        'BE': 'EUR', 'BELGIUM': 'EUR',
        'IE': 'EUR', 'IRELAND': 'EUR',
        'AT': 'EUR', 'AUSTRIA': 'EUR',
        'PT': 'EUR', 'PORTUGAL': 'EUR',
        'FI': 'EUR', 'FINLAND': 'EUR',
        'GR': 'EUR', 'GREECE': 'EUR',
        'LU': 'EUR', 'LUXEMBOURG': 'EUR',

       'JP': 'JPY', 'JAPAN': 'JPY',
        'KR': 'KRW', 'SOUTH KOREA': 'KRW', 'KOREA': 'KRW', 'REPUBLIC OF KOREA': 'KRW',
        'CN': 'CNY', 'CHINA': 'CNY', 'PEOPLES REPUBLIC OF CHINA': 'CNY',
        'HK': 'HKD', 'HONG KONG': 'HKD',
        'TW': 'TWD', 'TAIWAN': 'TWD',
        'MO': 'MOP', 'MACAO': 'MOP', 'MACAU': 'MOP',
        'SG': 'SGD', 'SINGAPORE': 'SGD',
        'MY': 'MYR', 'MALAYSIA': 'MYR',
        'TH': 'THB', 'THAILAND': 'THB',
        'ID': 'IDR', 'INDONESIA': 'IDR',
        'VN': 'VND', 'VIETNAM': 'VND',
        'PH': 'PHP', 'PHILIPPINES': 'PHP',
        'IN': 'INR', 'INDIA': 'INR',
        'PK': 'PKR', 'PAKISTAN': 'PKR',
        'BD': 'BDT', 'BANGLADESH': 'BDT',
        'LK': 'LKR', 'SRI LANKA': 'LKR',
        'NP': 'NPR', 'NEPAL': 'NPR',

        // Other
        'AU': 'AUD', 'AUSTRALIA': 'AUD',
        'NZ': 'NZD', 'NEW ZEALAND': 'NZD', 
        'PH': 'PHP', 'PHILIPPINES': 'PHP'
    };
                
                const countryKey = (body.country || 'US').toUpperCase();
                const userCurrency = countryToCurrency[countryKey] || 'USD';

                // 5. Build User Object
                const newUser = {
                    firstName: body.firstName,
                    lastName: body.lastName,
                    gender: body.gender,
                    email: body.email,
                    phone: body.phone,
                    dob: body.dob, 
                    address: { 
                        street: body.streetAddress, 
                        city: body.city, 
                        state: body.state, 
                        zip: body.zipCode, 
                        country: body.country 
                    },
                    employment: { 
                        status: body.employmentStatus, 
                        income: body.annualIncome 
                    },
                    password: userHash,
                    currency: userCurrency,
                    accounts: {
                        checking: {
                            accountName: '360 Checking',
                            accountNumber: generateAccNo(),
                            balance: 0.00,
                            currency: userCurrency,
                            status: 'Active'
                        },
                        savings: {
                            accountName: '360 Savings',
                            accountNumber: generateAccNo(),
                            balance: 0.00,
                            currency: userCurrency,
                            status: 'Active'
                        }
                    },
                    status: 'Pending Approval',
                    role: 'user',
                    profilePic: '', 
                    documents: [],
                    createdAt: new Date()
                };

                // 6. Database Operations
                const userResult = await db.collection('users').insertOne(newUser);

                await db.collection('applications').insertOne({
                    userId: userResult.insertedId,
                    fullName: `${body.firstName} ${body.lastName}`,
                    gender: body.gender,
                    email: body.email,
                    dob: body.dob,
                    country: body.country,
                    currency: userCurrency,
                    requestedType: body.accountType || '360 Checking',
                    status: 'Pending',
                    submittedAt: new Date()
                });

                return { 
                    statusCode: 201, 
                    headers, 
                    body: JSON.stringify({ 
                        message: "Registration successful", 
                        userId: userResult.insertedId,
                        currency: userCurrency 
                    }) 
                };

                // --- AUTO-LOGIN FOR NEW REGISTRATIONS ---
case 'user-login': {
                const { email, password } = body;
                const user = await db.collection('users').findOne({ email: email.toLowerCase().trim() });

                if (user && await bcrypt.compare(password, user.password)) {
                    if (!process.env.JWT_SECRET) {
                        return { statusCode: 500, headers, body: JSON.stringify({ message: "JWT Secret missing" }) };
                    }
                    const token = jwt.sign(
                        { id: user._id.toString(), email: user.email, role: 'user' },
                        process.env.JWT_SECRET,
                        { expiresIn: '7h' }
                    );
                    return { statusCode: 200, headers, body: JSON.stringify({ token, message: "Auto-login successful" }) };
                }
                return { statusCode: 401, headers, body: JSON.stringify({ message: "Auto-login failed" }) };
            }

   // --- STEP 1: INITIAL CREDENTIAL CHECK ---
case 'user-login-step1': {
    if (!body.email || !body.password) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "Email and password are required." }) };
    }

    const user = await db.collection('users').findOne({ email: body.email.toLowerCase().trim() });
    
    // Check password
    if (user && await bcrypt.compare(body.password, user.password)) {
        
        // Status check
        const allowedStatuses = ['Active', 'Approved', 'Pending Approval'];
        if (!allowedStatuses.includes(user.status)) {
            return { 
                statusCode: 403, 
                headers, 
                body: JSON.stringify({ message: "Account restricted. Contact support." }) 
            };
        }

        // IMPORTANT: We do NOT send the token here.
        // We just confirm the password is correct so the frontend can show Step 2.
        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ message: "Credentials verified. Please enter your login code.", status: user.status }) 
        };
    }

    return { statusCode: 401, headers, body: JSON.stringify({ message: "Invalid email or password." }) };
}
// --- STEP 2: VERIFY ADMIN-SET LOGIN PIN ---
case 'user-login-step2': {
    try {
        const { email, loginCode } = body;

        if (!email || !loginCode) {
            return { 
                statusCode: 400, 
                headers, 
                body: JSON.stringify({ message: "Email and Login Code are required." }) 
            };
        }

        const user = await db.collection('users').findOne({ email: email.toLowerCase().trim() });

        // 1. Check if user exists first to prevent crashes
        if (!user) {
            return { statusCode: 401, headers, body: JSON.stringify({ message: "User not found." }) };
        }

        // 2. Compare PIN (using String conversion for safety)
        if (user.loginPin && String(user.loginPin) === String(loginCode)) {
            
            // 3. Ensure JWT_SECRET exists
            if (!process.env.JWT_SECRET) {
                console.error("CRITICAL: JWT_SECRET is not defined in environment variables.");
                return { statusCode: 500, headers, body: JSON.stringify({ message: "Server configuration error." }) };
            }

            const token = jwt.sign(
                { id: user._id.toString(), email: user.email, role: 'user' },
                process.env.JWT_SECRET,
                { expiresIn: '7h' }
            );

            return { 
                statusCode: 200, 
                headers, 
                body: JSON.stringify({ 
                    token, 
                    name: user.firstName, 
                    role: 'user',
                    status: user.status 
                }) 
            };
        }

        return { 
            statusCode: 401, 
            headers, 
            body: JSON.stringify({ message: "Invalid login code. Access denied." }) 
        };

    } catch (err) {
        console.error("Step 2 Crash:", err);
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ message: "Internal Server Error", error: err.message }) 
        };
    }
}
          // --- PROFILE PICTURE UPLOAD (PRIVATE) ---
case 'upload-profile-pic':
    try {
        const userAuth = verifyToken(event);
        if (!userAuth) return { statusCode: 401, headers, body: JSON.stringify({ message: "Unauthorized" }) };

        const { imageBase64, fileName, fileType } = body;
        if (!imageBase64) throw new Error("No image data provided");

        const base64Content = imageBase64.split(';base64,').pop();
        const buffer = Buffer.from(base64Content, 'base64');
        
        // Define one unique key to use for both S3 and MongoDB
        const uniqueFileName = `${Date.now()}-${fileName}`;
        const uploadKey = `profiles/${userAuth.id}/${uniqueFileName}`;

        const uploadParams = {
            Bucket: process.env.E2_BUCKET_NAME.trim(), // Added trim() for safety
            Key: uploadKey, // Use the consistent key
            Body: buffer,
            ContentType: fileType
        };

        const uploadResult = await s3.upload(uploadParams).promise();

        await db.collection('users').updateOne(
            { _id: new ObjectId(userAuth.id) },
            { 
                $set: { 
                    profilePicKey: uploadKey,
                    profilePicUrl: uploadResult.Location,
                    updatedAt: new Date()
                }
            }
        );

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ message: "Upload successful", location: uploadResult.Location }) 
        };
    } catch (error) {
        console.error("Critical Upload Error:", error.message);
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ message: "Upload failed", error: error.message }) 
        };
    }

    case 'get-profile-pic':
    const auth = verifyToken(event);
    if (!auth) return { statusCode: 401, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    const userData = await db.collection('users').findOne({ _id: new ObjectId(auth.id) });
    
    if (!userData || !userData.profilePicKey) {
        return { statusCode: 404, headers, body: JSON.stringify({ message: "No photo found" }) };
    }

    // Generate a URL that expires in 15 minutes
    const signedUrl = s3.getSignedUrl('getObject', {
        Bucket: process.env.E2_BUCKET_NAME,
        Key: userData.profilePicKey,
        Expires: 900 
    });

    return { 
        statusCode: 200, 
        headers, 
        body: JSON.stringify({ url: signedUrl }) 
    };

          case 'admin-register':
    // Use process.env directly to ensure we don't hit "undefined" reference errors
    if (!process.env.MASTER_ACCESS_KEY || body.accessKey !== process.env.MASTER_ACCESS_KEY) {
        return { statusCode: 401, headers, body: JSON.stringify({ message: "Invalid Master Access Key. Registration blocked." }) };
    }

    const existingAdmin = await db.collection('admins').findOne({ email: body.email });
    if (existingAdmin) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "Admin email already registered." }) };
    }

    const adminHash = await bcrypt.hash(body.password, 10);
    const newAdmin = {
        name: body.name,
        email: body.email,
        branch: body.branch,
        password: adminHash,
        role: 'admin',
        createdAt: new Date(),
        active: true
    };

    await db.collection('admins').insertOne(newAdmin);
    return { statusCode: 201, headers, body: JSON.stringify({ message: "Admin account created successfully." }) };

            // --- ADMIN LOGIN ---
      case 'admin-login':
    if (!process.env.MASTER_ACCESS_KEY || body.accessKey !== process.env.MASTER_ACCESS_KEY) {
        return { statusCode: 401, headers, body: JSON.stringify({ message: "Access Denied: Master Key Invalid" }) };
    }

    const admin = await db.collection('admins').findOne({ 
        email: { $regex: new RegExp(`^${body.email}$`, 'i') } 
    });

    if (!admin) {
        return { statusCode: 401, headers, body: JSON.stringify({ message: "Invalid credentials" }) };
    }

    const isPasswordValid = await bcrypt.compare(body.password, admin.password);
    if (isPasswordValid) {
        const token = jwt.sign(
            { id: admin._id.toString(), email: admin.email, role: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '7h' }
        );
        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ token, adminName: admin.name, role: 'admin' }) 
        };
    } else {
        return { statusCode: 401, headers, body: JSON.stringify({ message: "Invalid credentials" }) };
    }

    case 'get-dashboard-data':
    const dashAuth = verifyToken(event, 'admin');
    if (!dashAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    const totalUsers = await db.collection('users').countDocuments();

    // Summing balances
    const balanceAgg = await db.collection('users').aggregate([
        {
            $group: {
                _id: null,
                total: { 
                    $sum: { 
                        $add: [
                            { $ifNull: ["$accounts.checking.balance", 0] },
                            { $ifNull: ["$accounts.savings.balance", 0] }
                        ]
                    }
                }
            }
        }
    ]).toArray();

    const pendingApps = await db.collection('applications').aggregate([
        { $match: { status: 'Pending' } },
        {
            $lookup: {
                from: 'users',
                localField: 'userId',
                foreignField: '_id',
                as: 'userProfile'
            }
        },
        { $unwind: '$userProfile' },
        {
            $project: {
                _id: 1,
                fullName: 1,
                email: 1,
                gender: 1, // Taken from the application document
                accountType: 1,
                status: 1,
                submittedAt: 1,
                profilePicUrl: '$userProfile.profilePicUrl', 
                profilePicKey: '$userProfile.profilePicKey',
                phone: '$userProfile.phone',
                dob: '$userProfile.dob',
                address: '$userProfile.address',
                employment: '$userProfile.employment'
            }
        },
        { $sort: { submittedAt: -1 } }
    ]).toArray();

    return { 
        statusCode: 200, 
        headers,
        body: JSON.stringify({ 
            totalUsers, 
            pendingCount: pendingApps.length, 
            recentApplications: pendingApps, 
            totalBalance: balanceAgg[0]?.total || 0 
        }) 
    };

  // --- ADMIN: DISPATCH SECURE EMAIL (GMAIL) ---
case 'admin-send-email': {
    const { recipientEmail, subject, message } = body;

    if (!recipientEmail || !subject || !message) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "Missing email fields" }) };
    }

    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS 
            }
        });

        const mailOptions = {
            from: `"Capital Suntrust" <${process.env.EMAIL_USER}>`,
            to: recipientEmail,
            subject: subject,
            text: message,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden;">
                    <div style="background-color: #002b49; padding: 30px; text-align: center;">
                        <h1 style="color: white; margin: 0; font-style: italic;">Capital<span style="color: #ef4444;">Suntrust</span></h1>
                        <p style="color: #93c5fd; font-size: 10px; text-transform: uppercase; letter-spacing: 2px; margin-top: 5px;">Secure Banking Correspondence</p>
                    </div>
                    <div style="padding: 30px; color: #334155; line-height: 1.6;">
                        ${message.replace(/\n/g, '<br>')}
                    </div>
                    <div style="background-color: #f8fafc; padding: 20px; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0;">
                        &copy; 2026 Capital Suntrust Private Wealth. This is a secure, encrypted message. <br>
                        If you did not expect this email, please contact our fraud department.
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ message: "Email dispatched successfully via Gmail" }) 
        };
        
    } catch (mailError) {
        console.error("Gmail Error:", mailError);
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ 
                message: "Gmail server error. Verify App Password and 2FA.", 
                details: mailError.message 
            }) 
        };
    }
}

case 'get-all-customers': {
    const adminAuth = verifyToken(event, 'admin');
    if (!adminAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Admin access required" }) };

    try {
        const { search, mode } = event.body ? JSON.parse(event.body) : {};
        let query = {};

        // 1. Search Logic: Priority #1
        if (search) {
            query = {
                $or: [
                    { firstName: { $regex: search, $options: 'i' } },
                    { lastName: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } }
                ]
            };
        } 
        // 2. Chat Support Mode: Only apply if explicitly requested
        else if (mode === 'support') {
            query = { supportMessages: { $exists: true, $not: { $size: 0 } } };
        }
        // 3. Default: Show all users (query remains {})

        const customers = await db.collection('users')
            .find(query)
            .project({  
                profilePicKey: 0, 
                __v: 0 
            })
            .sort({ 
                // If in support mode, sort by message date, otherwise alphabetical
                ...(mode === 'support' ? { lastMessageAt: -1 } : { lastName: 1 })
            }) 
            .limit(100) 
            .toArray();

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ 
                count: customers.length,
                customers 
            }) 
        };
    } catch (err) {
        console.error("Fetch Users Error:", err);
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ message: "Failed to fetch users", error: err.message }) 
        };
    }
}
    
case 'admin-update-user': {
    const updateAuth = verifyToken(event, 'admin');
    if (!updateAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    const { userId, updateData } = JSON.parse(event.body);
    
    // 1. Safety: Prevent unauthorized field overwrites
    // We remove sensitive credentials so they can only be changed via specialized flows
    delete updateData._id; 
    delete updateData.email; 

    const flatten = (obj, prefix = '') => {
        return Object.keys(obj).reduce((acc, k) => {
            const pre = prefix.length ? prefix + '.' : '';
            if (
                typeof obj[k] === 'object' && 
                obj[k] !== null && 
                !Array.isArray(obj[k]) && 
                Object.keys(obj[k]).length > 0
            ) {
                Object.assign(acc, flatten(obj[k], pre + k));
            } else {
                acc[pre + k] = obj[k];
            }
            return acc;
        }, {});
    };

    const flattenedUpdate = flatten(updateData);

    try {
        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(userId) },
            { $set: flattenedUpdate }
        );

        if (result.matchedCount === 0) {
            return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };
        }

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ 
                message: "User updated successfully",
                fieldsUpdated: Object.keys(flattenedUpdate) 
            }) 
        };
    } catch (err) {
        console.error("Admin Update Error:", err);
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ message: "DB Update Error", error: err.message }) 
        };
    }
}

   case 'admin-add-funds':
    const fundsAuth = verifyToken(event, 'admin');
    if (!fundsAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    const updateField = `accounts.${body.accountType.toLowerCase()}.balance`;
    
    // Use the provided transactionDate if available, otherwise default to current date/time
    const transactionDate = body.transactionDate ? new Date(body.transactionDate) : new Date();

    await db.collection('users').updateOne(
        { _id: new ObjectId(body.userId) },
        { 
            $inc: { [updateField]: parseFloat(body.amount) },
            $push: { transactions: {
                description: body.memo,
                amount: parseFloat(body.amount),
                date: transactionDate,
                type: body.amount > 0 ? 'credit' : 'debit',
                status: 'Completed',
                accountType: body.accountType
            }}
        }
    );
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Funds adjusted" }) };
    

case 'admin-bulk-history': {
            const bulkAuth = verifyToken(event, 'admin');
            if (!bulkAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };

            try {
                // Use 'body' (already defined at top), not 'data'
                const { userId, transactions } = body;

                if (!Array.isArray(transactions)) {
                    return { statusCode: 400, headers, body: JSON.stringify({ message: "Invalid input: transactions must be an array" }) };
                }

                const formattedTransactions = transactions.map(tx => ({
                    description: tx.description || 'No description',
                    date: tx.date ? new Date(tx.date) : new Date(),
                    amount: parseFloat(tx.amount) || 0,
                    type: tx.type || 'credit',
                    status: tx.status || 'Completed',
                    accountType: tx.accountType || 'Savings',
                    createdAt: new Date()
                }));

                // Native MongoDB syntax (not Mongoose findByIdAndUpdate)
                const result = await db.collection('users').updateOne(
                    { _id: new ObjectId(userId) },
                    { $push: { transactions: { $each: formattedTransactions } } }
                );

                if (result.matchedCount === 0) return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };

                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({ message: `${formattedTransactions.length} records injected` })
                };
            } catch (err) {
                return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
            }
        }

                        case 'admin-update-user': {
    const updateAuth = verifyToken(event, 'admin');
    if (!updateAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    const { userId, updateData } = body;

    if (!userId || !updateData) {
        return { 
            statusCode: 400, 
            headers, 
            body: JSON.stringify({ message: "Missing User ID or Update Data" }) 
        };
    }

    try {
        const { ObjectId } = require('mongodb');
        
        // We use $set to only update the fields provided in updateData
        // This allows us to update profile info OR transfer restrictions using the same API
        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(userId) },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };
        }

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ message: "User updated successfully", result }) 
        };
    } catch (err) {
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ message: "Internal Server Error", error: err.message }) 
        };
    }
}

        case 'admin-add-history': {
            try {
                const { userId, description, date, amount, type, status, accountType } = body;

                if (!userId || !description || !amount) {
                    return { statusCode: 400, headers, body: JSON.stringify({ message: "Missing required fields" }) };
                }

                const result = await db.collection('users').updateOne(
                    { _id: new ObjectId(userId) },
                    {
                        $push: {
                            transactions: {
                                transactionId,
                                description,
                                date: new Date(date),
                                amount: parseFloat(amount),
                                type,
                                status: status || 'Completed',
                                accountType: accountType || 'Checking',
                                createdAt: new Date()
                            }
                        }
                    }
                );

                if (result.matchedCount === 0) {
                    return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };
                }

                return { statusCode: 200, headers, body: JSON.stringify({ message: "Transaction record injected" }) };
            } catch (err) {
                console.error("History Injection Error:", err.message);
                return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
            }
        }

        case 'admin-generate-card': {
            try {
                const { userId, cardType, pin, currency } = body;

                if (!userId || !pin) {
                    return { statusCode: 400, headers, body: JSON.stringify({ message: "User ID and PIN are required" }) };
                }

                const prefix = cardType === 'Visa' ? '4' : '5';
                let cardNumber = prefix;
                for (let i = 0; i < 15; i++) {
                    cardNumber += Math.floor(Math.random() * 10);
                }

                const cvv = Math.floor(100 + Math.random() * 900).toString();
                const expiryDate = "08/29";

                const result = await db.collection('users').updateOne(
                    { _id: new ObjectId(userId) },
                    {
                        $set: {
                            card: {
                                cardNumber,
                                cardType,
                                pin,
                                cvv,
                                expiryDate,
                                currency,
                                status: "Active",
                                issuedAt: new Date()
                            }
                        }
                    }
                );

                if (result.matchedCount === 0) {
                    return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };
                }

                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({ 
                        message: "Card issued", 
                        cardDetails: { cardNumber, expiryDate, cvv } 
                    })
                };
            } catch (err) {
                return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
            }
        }
case 'get-user-profile': {
    const userProfileAuth = verifyToken(event);
    if (!userProfileAuth) return { statusCode: 401, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    // 1. Find user and simultaneously mark admin replies as "read"
    const fullUser = await db.collection('users').findOneAndUpdate(
        { _id: new ObjectId(userProfileAuth.id || userProfileAuth.userId) },
        { $set: { hasUnreadAdminReply: false } }, // Clear the notification flag
        { projection: { password: 0 }, returnDocument: 'after' } 
    );

    if (!fullUser) {
        return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };
    }

    // --- YOUR EXISTING MAPPING LOGIC ---
    const dbCard = fullUser.card || {};
    fullUser.card = {
        number: dbCard.cardNumber,
        cvv: dbCard.cvv || fullUser.cardCvv,
        expiry: dbCard.expiryDate || fullUser.expiry,
        status: dbCard.status || "Inactive",
        routingNumber: fullUser.routingNumber,
        swiftCode: fullUser.swiftCode,
        transitNumber: fullUser.transitNumber,
        institutionNumber: fullUser.institutionNumber,
        bsbCode: fullUser.bsbCode,
        sortCode: fullUser.sortCode,
        iban: fullUser.iban,
        clabe: fullUser.clabe,
        bankCode: fullUser.bankCode 
    };

    if (fullUser.profilePicKey) {
        try {
            fullUser.profilePicUrl = await getSignedUrlFromS3(fullUser.profilePicKey); 
        } catch (picError) {
            fullUser.profilePicUrl = null;
        }
    }

    return { 
        statusCode: 200, 
        headers, 
        body: JSON.stringify(fullUser) 
    };
}

    case 'change-password':
    const changePassAuth = verifyToken(event);
    if (!changePassAuth) {
        return { statusCode: 401, headers, body: JSON.stringify({ message: "Unauthorized" }) };
    }

    const { newPassword } = data;

    // 1. Basic Validation
    if (!newPassword || newPassword.length < 6) {
        return { 
            statusCode: 400, 
            headers, 
            body: JSON.stringify({ message: "Password must be at least 6 characters long." }) 
        };
    }

    try {
        // 2. Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // 3. Update the user document in MongoDB
        const updateResult = await db.collection('users').updateOne(
            { _id: new ObjectId(changePassAuth.id) },
            { $set: { password: hashedPassword } }
        );

        if (updateResult.modifiedCount === 0) {
            return { 
                statusCode: 404, 
                headers, 
                body: JSON.stringify({ message: "User not found or password unchanged." }) 
            };
        }

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ success: true, message: "Password updated successfully." }) 
        };

    } catch (error) {
        console.error("Password Update Error:", error);
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ message: "Internal server error." }) 
        };
    }

    // Add these two cases inside your switch (action) { ... } block
case 'lookup-bank':
    try {
        const { code, type } = body;
        if (!code) return { statusCode: 400, headers, body: JSON.stringify({ message: "Code required" }) };

        let bankName = null;

        // 1. STATIC FALLBACKS (Prevents 503 for common test cases)
     const manualRegistry = {
    // United States (ABA Routing Numbers)
    "021000021": "JPMorgan Chase Bank",
    "121000248": "Wells Fargo Bank",
    "061000104": "Bank of America",
    
    // Internal & Systems
    "CT-SYSTEM-01": "Capital Suntrust Internal",

    // Australia (BSB Codes)
    "BSB062000": "Commonwealth Bank of Australia",
    "BSB032000": "Westpac Banking Corporation",
    "BSB082000": "National Australia Bank (NAB)",
    "BSB012000": "Australia and New Zealand Banking Group (ANZ)",

    // Canada (Institution + Transit Numbers / EFT)
    "CC001": "Bank of Montreal (CA)",
    "CC003": "Royal Bank of Canada (RBC)",
    "CC004": "The Bank of Nova Scotia (Scotiabank)",
    "CC010": "Canadian Imperial Bank of Commerce (CIBC)",

    // United Kingdom (Sort Codes)
    "400242": "HSBC UK",
    "200000": "Barclays Bank",
    "309089": "Lloyds Bank",
    "502101": "NatWest",

    // New Zealand (BSB / Routing Codes)
    "NZ0101": "ANZ Bank New Zealand",
    "NZ0201": "Bank of New Zealand (BNZ)",
    "NZ0301": "Westpac New Zealand",
    "NZ0601": "ASB Bank",

    // Japan (Zengin & Branch Codes / US Routing)
    "021081406": "Bank of Japan (Operations Account 1 / NY Branch - US ABA Routing Number)",
    "0001001": "Mizuho Bank (Head Office - Zengin Code)",
    "0005001": "Mitsubishi UFJ Bank (Head Office - Zengin Code)",
    "0009001": "Sumitomo Mitsui Banking Corporation (Head Office - Zengin Code)"
};

        if (manualRegistry[code.trim()]) {
            return { statusCode: 200, headers, body: JSON.stringify({ bankName: manualRegistry[code.trim()] }) };
        }

        // 2. US ROUTING LOOKUP
        if (type === 'routing') {
            try {
                const res = await fetch(`https://routingnumber.info/api/data.json?rn=${code.trim()}`);
                const result = await res.json();
                bankName = result.name || null;
            } catch (e) { console.log("US Lookup Failed"); }
        } 
        
        // 3. INTERNATIONAL (SWIFT/BIC) LOOKUP
        // This handles CA, AU, NZ, PH, and Europe
        else if (type === 'swift') {
            try {
                // Using a more reliable validation endpoint
                const res = await fetch(`https://openiban.com/validate/${code.trim()}?getBIC=true`);
                const result = await res.json();
                bankName = result.bankData?.name || null;
            } catch (e) { console.log("International Lookup Failed"); }
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                bankName: bankName,
                verified: !!bankName 
            })
        };

    } catch (err) {
        // Return 200 even on error but with empty bankName so frontend allows manual entry
        return { statusCode: 200, headers, body: JSON.stringify({ bankName: null, error: "Service busy" }) };
    }

 case 'process-transfer': {
    const transferAuth = verifyToken(event);
    if (!transferAuth) return { statusCode: 401, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    const authId = transferAuth.id || transferAuth.userId;
    const { 
        fromAccount, toAccount, amount, transferType, 
        recName, recAccount, routingCode, memo, 
        bankName, transferPin 
    } = body;

    const transferAmount = parseFloat(amount);

    // 1. Basic Validation
    if (isNaN(transferAmount) || transferAmount <= 0) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "Invalid amount" }) };
    }

    if (!transferPin) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "Security PIN is required" }) };
    }

    try {
        const sender = await db.collection('users').findOne({ _id: new ObjectId(authId) });
        if (!sender) return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };

        // --- NEW SECURITY CHECK: BLOCK STATUS ---
        if (sender.transferBlocked === true) {
            return { 
                statusCode: 403, 
                headers, 
                body: JSON.stringify({ 
                    message: sender.restrictionMessage || "Transaction declined. This account is restricted from making transfers. Please contact support." 
                }) 
            };
        }

        // 2. SECURITY CHECK: Verify PIN
        if (sender.transferPin.toString() !== transferPin.toString()) {
            return { 
                statusCode: 403, 
                headers, 
                body: JSON.stringify({ message: "Incorrect Security PIN. Please try again." }) 
            };
        }

        const fromAccKey = fromAccount.toLowerCase();
        
        // 3. Balance Validation
        const currentBalance = sender.accounts[fromAccKey].balance;
        if (currentBalance < transferAmount) {
            return { statusCode: 400, headers, body: JSON.stringify({ message: "Insufficient funds" }) };
        }

        const transactionId = `CT-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

        // 4. Prepare Transaction Object
        const newTransaction = {
            transactionId,
            date: new Date(),
            description: memo || `${transferType.toUpperCase()} Transfer`,
            amount: -transferAmount,
            currency: sender.currency || 'USD', // Updated to use top-level currency
            type: 'debit',
            status: transferType === 'internal' ? 'Completed' : 'Processing',
            accountType: fromAccKey,
            details: {
                recipientName: recName,
                recipientAccount: recAccount || toAccount,
                routingNumber: routingCode || 'N/A',
                bankName: bankName || 'Capital Suntrust Internal',
                method: transferType,
                referenceMemo: memo
            }
        };

        // 5. Build Database Operations
        const updateOperations = {
            $inc: { [`accounts.${fromAccKey}.balance`]: -transferAmount },
            $push: { transactions: { $each: [newTransaction], $position: 0 } }
        };

        // Handle Internal Credit logic
        if (transferType === 'internal' && toAccount) {
            const toAccKey = toAccount.toLowerCase();
            updateOperations.$inc[`accounts.${toAccKey}.balance`] = transferAmount;
            
            const creditTransaction = { 
                ...newTransaction, 
                amount: transferAmount, 
                type: 'credit', 
                accountType: toAccKey,
                status: 'Completed'
            };
            updateOperations.$push.transactions.$each.push(creditTransaction);
        }

        // 6. Execute Atomic Update
        await db.collection('users').updateOne(
            { _id: new ObjectId(authId) },
            updateOperations
        );

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ 
                success: true, 
                message: "Transfer successful", 
                transactionId,
                recipient: recName 
            }) 
        };

    } catch (err) {
        console.error("Transfer Error:", err);
        return { statusCode: 500, headers, body: JSON.stringify({ message: "Transfer failed", error: err.message }) };
    }
}

         case 'admin-update-status': {
    const adminAuth = verifyToken(event, 'admin'); // Ensure your verifyToken supports admin checks
    if (!adminAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Forbidden" }) };

    const { userId, transactionId, newStatus, adminMemo } = body; // status can be: Pending, Failed, Declined, Refund, Completed

    try {
        const user = await db.collection('users').findOne({ 
            _id: new ObjectId(userId), 
            "transactions.transactionId": transactionId 
        });

        if (!user) return { statusCode: 404, headers, body: JSON.stringify({ message: "Transaction not found" }) };

        const txn = user.transactions.find(t => t.transactionId === transactionId);

        // Prevent updating a transaction that is already finished
        if (txn.status === 'Completed' || txn.status === 'Declined') {
            return { statusCode: 400, headers, body: JSON.stringify({ message: "Transaction already finalized" }) };
        }

        // --- ACTUAL MONEY MOVEMENT LOGIC ---
        if (newStatus === 'Completed') {
            const amountToDeduct = Math.abs(txn.amount);
            const sourceAcc = txn.accountType;

            // Final Balance Check
            if (user.accounts[sourceAcc].balance < amountToDeduct) {
                return { statusCode: 400, headers, body: JSON.stringify({ message: "User no longer has enough funds" }) };
            }

            // 1. Deduct from User
            await db.collection('users').updateOne(
                { _id: new ObjectId(userId) },
                { $inc: { [`accounts.${sourceAcc}.balance`]: -amountToDeduct } }
            );

            // 2. If Interbank (User to User), add to Recipient
            if (txn.details.method === 'interbank') {
                await db.collection('users').updateOne(
                    { "accounts.checking.accountNumber": txn.details.account },
                    { 
                        $inc: { "accounts.checking.balance": amountToDeduct },
                        $push: { transactions: {
                            transactionId: txn.transactionId,
                            date: new Date(),
                            description: `Received from ${user.firstName}`,
                            amount: amountToDeduct,
                            type: 'credit',
                            status: 'Completed',
                            accountType: 'checking'
                        }}
                    }
                );
            }

            // 3. If Internal (Self Transfer), add to target account
            if (txn.details.method === 'internal') {
                const targetAcc = txn.details.toAccount;
                await db.collection('users').updateOne(
                    { _id: new ObjectId(userId) },
                    { $inc: { [`accounts.${targetAcc}.balance`]: amountToDeduct } }
                );
            }
        }

        // --- UPDATE STATUS REGARDLESS OF TYPE ---
        await db.collection('users').updateOne(
            { _id: new ObjectId(userId), "transactions.transactionId": transactionId },
            { 
                $set: { 
                    "transactions.$.status": newStatus,
                    "transactions.$.adminNote": adminMemo || ""
                } 
            }
        );

        return { statusCode: 200, headers, body: JSON.stringify({ message: `Status updated to ${newStatus}` }) };

    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ message: err.message }) };
    }
}
     
case 'verify-pin': {
    const auth = verifyToken(event);
    if (!auth) return { statusCode: 401, body: JSON.stringify({ message: "Unauthorized" }) };
    
    const user = await db.collection('users').findOne({ _id: new ObjectId(auth.id || auth.userId) });
    if (user.transferPin.toString() === body.pin.toString()) {
        return { statusCode: 200, body: JSON.stringify({ success: true }) };
    } else {
        return { statusCode: 403, body: JSON.stringify({ message: "Invalid Security PIN" }) };
    }
}

case 'admin-get-all-transactions': {
    const adminAuth = verifyToken(event, 'admin');
    if (!adminAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    try {
        const users = await db.collection('users').find({}).toArray();
        let allTransactions = [];

        for (const user of users) {
            if (user.transactions && Array.isArray(user.transactions)) {
                // Map through transactions to add user context and sign S3 images
                const userTxns = await Promise.all(user.transactions.map(async (t) => {
                    let frontUrl = t.frontImage || null;
                    let backUrl = t.backImage || null;

                    // If the transaction has S3 keys, generate signed URLs
                    if (t.frontImageKey) {
                        frontUrl = s3.getSignedUrl('getObject', {
                            Bucket: process.env.E2_BUCKET_NAME.trim(),
                            Key: t.frontImageKey,
                            Expires: 3600 // URL valid for 1 hour
                        });
                    }
                    if (t.backImageKey) {
                        backUrl = s3.getSignedUrl('getObject', {
                            Bucket: process.env.E2_BUCKET_NAME.trim(),
                            Key: t.backImageKey,
                            Expires: 3600
                        });
                    }

                    return {
                        ...t,
                       userId: user._id.toString(), // Add .toString() here!
                     userName: `${user.firstName} ${user.lastName}`,
                     frontImageUrl: frontUrl,
                     backImageUrl: backUrl
                };
                }));
                allTransactions.push(...userTxns);
            }
        }

        // Sort by date newest first
        allTransactions.sort((a, b) => new Date(b.date) - new Date(a.date));

        return { statusCode: 200, headers, body: JSON.stringify({ transactions: allTransactions }) };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ message: "Failed to fetch transactions" }) };
    }
}

case 'submit-mobile-deposit': {
    try {
        const userAuth = verifyToken(event);
        if (!userAuth) return { statusCode: 401, headers, body: JSON.stringify({ message: "Unauthorized" }) };

        const { amount, account, memo, transferPin, frontImage, backImage } = body;

        // 1. Verify PIN
        const user = await db.collection('users').findOne({ _id: new ObjectId(userAuth.id || userAuth.userId) });
        if (!user || String(user.transferPin) !== String(transferPin)) {
            return { statusCode: 403, headers, body: JSON.stringify({ message: "Invalid Transfer PIN" }) };
        }

        // 2. Upload Images to S3 
        const uploadToS3 = async (base64Str, side) => {
            const base64Content = base64Str.split(';base64,').pop();
            const buffer = Buffer.from(base64Content, 'base64');
            const key = `checks/${userAuth.id}/${Date.now()}-${side}.jpg`;
            
            await s3.upload({
                Bucket: process.env.E2_BUCKET_NAME.trim(),
                Key: key,
                Body: buffer,
                ContentType: 'image/jpeg'
            }).promise();
            return key;
        };

        const frontKey = await uploadToS3(frontImage, 'front');
        const backKey = await uploadToS3(backImage, 'back');

        // 3. Create a Pending Transaction
        const newTransaction = {
            id: new ObjectId().toString(), // String ID is easier for frontend mapping
            description: `Mobile Deposit: ${memo || 'Check Deposit'}`,
            amount: parseFloat(amount),
            date: new Date().toISOString(),
            type: 'Mobile Deposit', // Changed to match your frontend filter
            category: 'credit', 
            status: 'Pending Verification',
            accountType: account,
            frontImageKey: frontKey,
            backImageKey: backKey
        };

        await db.collection('users').updateOne(
            { _id: new ObjectId(userAuth.id || userAuth.userId) },
            { $push: { transactions: { $each: [newTransaction], $position: 0 } } } // Add to top of list
        );

        return { statusCode: 200, headers, body: JSON.stringify({ message: "Deposit submitted successfully" }) };
    } catch (err) {
        console.error("Deposit Error:", err);
        return { statusCode: 500, headers, body: JSON.stringify({ message: "Server error during deposit" }) };
    }
}

case 'admin-finalize-deposit': {
    const finalizeAuth = verifyToken(event, 'admin'); 
    if (!finalizeAuth) {
        return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };
    }

    const { userId, txnId, newStatus, amount, accountType, adminNote } = body;
    console.log("DEBUG: Finalizing for User:", userId, "Txn:", txnId);

    // 1. Fetch the user first to check the current transaction status
    const userDoc = await db.collection('users').findOne(
        { _id: new ObjectId(userId) },
        { projection: { transactions: 1, accounts: 1 } }
    );

    if (!userDoc) {
        return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };
    }

    const targetTxn = (userDoc.transactions || []).find(t => (t.id === txnId || t._id?.toString() === txnId));
    if (!targetTxn) {
        return { statusCode: 404, headers, body: JSON.stringify({ message: "Transaction ID not found in user record" }) };
    }

    const wasAlreadyCompleted = targetTxn.status === 'Completed';

    // 2. Update the transaction array including type: 'credit'
    const updateResult = await db.collection('users').updateOne(
        { _id: new ObjectId(userId) },
        { 
            $set: { 
                "transactions.$[elem].status": newStatus,
                "transactions.$[elem].type": "credit", // <--- ENSURES IT COUNTS AS INFLOW
                "transactions.$[elem].adminNote": adminNote || "",
                "transactions.$[elem].updatedAt": new Date()
            } 
        },
        { 
            arrayFilters: [{ "elem.id": txnId }] 
        }
    );

    if (updateResult.matchedCount === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };
    }

    // 3. Handle Balance Increment if Status is 'Completed' AND wasn't already completed
    if (newStatus === 'Completed' && !wasAlreadyCompleted) {
        const validAccount = (accountType || 'checking').toLowerCase();
        const balanceField = `accounts.${validAccount}.balance`;
        
        await db.collection('users').updateOne(
            { _id: new ObjectId(userId) },
            { $inc: { [balanceField]: parseFloat(amount) } }
        );
    }

    return { 
        statusCode: 200, 
        headers, 
        body: JSON.stringify({ message: "Success" }) 
    };
}
            
case 'send-support-message': {
    const userAuth = verifyToken(event, 'user'); 
    const { message } = JSON.parse(event.body);

    const newMessage = {
        text: message.trim(),
        sender: userAuth.email, // "mistycpayne@gmail.com"
        type: 'user-to-admin',
        date: new Date().toISOString(),
        readByAdmin: false
    };

    await db.collection('users').updateOne(
        { email: userAuth.email }, 
        { 
            $push: { supportMessages: newMessage },
            $set: { 
                lastMessageAt: new Date().toISOString(),
                hasUnreadAdminReply: false // Notify Admin of new message
            } 
        }
    );

    return { statusCode: 200, headers, body: JSON.stringify({ message: "Sent via Secure Email Link" }) };
}
case 'admin-reply-support': {
    const adminAuth = verifyToken(event, 'admin');
    if (!adminAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };

    try {
        const { userEmail, replyText } = JSON.parse(event.body);
        if (!replyText || !userEmail) throw new Error("Missing fields");

        const adminReply = {
            text: replyText.trim(),
            sender: adminAuth.email, 
            type: 'admin-to-user',
            recipient: userEmail,
            date: new Date().toISOString()
        };

        await db.collection('users').updateOne(
            { email: userEmail }, 
            { 
                $push: { supportMessages: adminReply },
                $set: { 
                    hasUnreadAdminReply: true, 
                    lastAdminReplyBy: adminAuth.email,
                    lastAdminReplyAt: adminReply.date,
                    // IMPORTANT: Update this so the inbox sorts correctly
                    lastMessageAt: adminReply.date 
                } 
            }
        );

        return { statusCode: 200, headers, body: JSON.stringify({ message: "Reply delivered" }) };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
    }
}

case 'clear-support-unread': {
    const auth = verifyToken(event, 'user');
    if (!auth) return { statusCode: 403, body: JSON.stringify({ message: "Unauthorized" }) };
    
    await db.collection('users').updateOne(
        { email: auth.email },
        { $set: { hasUnreadAdminReply: false } }
    );
    return { statusCode: 200, body: JSON.stringify({ success: true }) };
}

case 'admin-approve-application':
                const approveAuth = verifyToken(event, 'admin');
                if (!approveAuth) return { statusCode: 403, headers, body: JSON.stringify({ message: "Unauthorized" }) };

                const { applicationId, status } = body; 
                const application = await db.collection('applications').findOne({ _id: new ObjectId(applicationId) });
                
                if (!application) {
                    return { statusCode: 404, headers, body: JSON.stringify({ message: "Application not found" }) };
                }

                // 1. Update Application Status
                await db.collection('applications').updateOne(
                    { _id: new ObjectId(applicationId) },
                    { $set: { status: status, processedBy: approveAuth.email, processedAt: new Date() } }
                );

                // 2. If Approved, activate the corresponding User login
                if (status === 'Approved') {
                    // We look for the user associated with this application
                    await db.collection('users').updateOne(
                        { _id: new ObjectId(application.userId) },
                        { $set: { status: 'Active' } }
                    );
                }

                            

                return { statusCode: 200, headers, body: JSON.stringify({ message: `Application ${status} successfully` }) };
            }
            
    } catch (error) {
        console.error("API Error:", error);
        return { statusCode: 500, headers, body: JSON.stringify({ error: "Internal Server Error", details: error.message }) };
    }
};