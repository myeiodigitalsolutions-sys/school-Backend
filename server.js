require('dotenv').config(); // LOAD .env FIRST

const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));

if (!process.env.FIREBASE_KEY) {
  console.error('❌ FIREBASE_KEY not found in .env');
  process.exit(1);
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_KEY);
  serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
} catch (err) {
  console.error('❌ Invalid FIREBASE_KEY JSON');
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const auth = admin.auth();

console.log('Firebase Admin SDK initialized successfully');

/* ===========================
   FIXED ADMIN CONFIG
=========================== */
const ADMIN_EMAIL = 'myeiokln@gmail.com';
const ADMIN_PASSWORD = 'admin123';

/* ===========================
   ENSURE ADMIN EXISTS
=========================== */
async function ensureAdminExists() {
  try {
    let adminUser;

    try {
      // Check if admin exists in Auth
      adminUser = await auth.getUserByEmail(ADMIN_EMAIL);
      console.log('✅ Admin already exists in Auth:', adminUser.uid);
    } catch (err) {
      if (err.code !== 'auth/user-not-found') throw err;

      // Create admin in Auth
      adminUser = await auth.createUser({
        email: ADMIN_EMAIL,
        password: ADMIN_PASSWORD,
      });
      console.log('🆕 Admin created in Auth:', adminUser.uid);
    }

    // Apply custom claim
    const user = await auth.getUser(adminUser.uid);
    if (!user.customClaims || user.customClaims.admin !== true) {
      await auth.setCustomUserClaims(adminUser.uid, { admin: true });
      console.log('🔐 Admin claim applied');
    }

    // Add admin to Firestore "users" collection with ID "ADMIN"
    const adminDocRef = db.collection('users').doc('ADMIN');
    const adminSnap = await adminDocRef.get();

    if (!adminSnap.exists) {
      await adminDocRef.set({
        auth_uid: adminUser.uid,
        created_at: new Date(),
        dob: '01/01/1990',
        email: ADMIN_EMAIL,
        name: 'Admin',
        role: 'admin',
        uid: 'ADMIN'
      });
      console.log('📁 Admin added to Firestore collection "users" with ID "ADMIN"');
    } else {
      console.log('📁 Admin already exists in Firestore collection "users"');
    }

  } catch (err) {
    console.error('❌ Failed to ensure admin:', err);
  }
}


// Call on server start
ensureAdminExists();

/* ===========================
   ADMIN VERIFY (CLAIM ONLY)
=========================== */
async function verifyAdmin(idToken) {
  if (!idToken) throw { code: 401, message: 'Missing idToken' };

  const decoded = await auth.verifyIdToken(idToken);
  if (decoded.admin === true) return decoded;

  throw { code: 403, message: 'Admin access only' };
}

/* ===========================
   CURRENT ACADEMIC YEAR
=========================== */
async function getCurrentAcademicYearId() {
  const snapshot = await db.collection('academic_years')
    .where('isCurrent', '==', true)
    .limit(1)
    .get();

  if (snapshot.empty) {
    throw new Error('No current academic year found (no document with isCurrent: true)');
  }

  return snapshot.docs[0].id;
}

/* ===========================
   CREATE USER
=========================== */
app.post('/create-user', async (req, res) => {
  const { idToken, customUid, email, password, role = 'student', name = '', dob = '' } = req.body || {};

  if (!idToken || !customUid || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    await verifyAdmin(idToken);

    const currentYearId = await getCurrentAcademicYearId();
    const targetRef = db
      .collection('academic_years')
      .doc(currentYearId)
      .collection('users')
      .doc(customUid);

    const existing = await targetRef.get();
    if (existing.exists) {
      return res.status(409).json({ error: 'UID already exists in current year' });
    }

    try {
      await auth.getUserByEmail(email);
      return res.status(409).json({ error: 'Email already in use' });
    } catch (err) {
      if (err.code !== 'auth/user-not-found') throw err;
    }

    const createdAuthUser = await auth.createUser({ email, password });

    await targetRef.set({
      uid: customUid,
      email,
      role: role.toLowerCase(),
      name: name || '',
      dob: dob || '',
      auth_uid: createdAuthUser.uid,
      created_at: new Date(),
      updated_at: new Date(),
    });

    return res.json({
      success: true,
      message: 'User created successfully',
      docId: customUid,
      auth_uid: createdAuthUser.uid
    });
  } catch (err) {
    console.error('CREATE ERROR:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Server error' });
  }
});

/* ===========================
   UPDATE USER
=========================== */
app.post('/update-user', async (req, res) => {
  const { idToken, customUid, email, name, dob } = req.body || {};

  if (!idToken || !customUid) {
    return res.status(400).json({ error: 'Missing idToken or customUid' });
  }

  try {
    await verifyAdmin(idToken);

    const currentYearId = await getCurrentAcademicYearId();
    const userRef = db
      .collection('academic_years')
      .doc(currentYearId)
      .collection('users')
      .doc(customUid);

    const userSnap = await userRef.get();
    if (!userSnap.exists) {
      return res.status(404).json({ error: 'User not found in current year' });
    }

    const userData = userSnap.data();
    const authUid = userData.auth_uid;
    if (!authUid) {
      return res.status(400).json({ error: 'No linked Auth account' });
    }

    const updates = {};
    const authUpdates = {};

    if (email && email !== userData.email) { updates.email = email; authUpdates.email = email; }
    if (name && name !== userData.name) { updates.name = name; }
    if (dob && dob !== userData.dob) {
      updates.dob = dob;
      const [day, month, year] = dob.split('/');
      authUpdates.password = `${day}${month}${year}`;
    }

    if (Object.keys(authUpdates).length > 0) {
      await auth.updateUser(authUid, authUpdates);
    }

    if (Object.keys(updates).length > 0) {
      updates.updated_at = new Date();
      await userRef.update(updates);
    }

    return res.json({ success: true, message: 'User updated successfully' });
  } catch (err) {
    console.error('UPDATE ERROR:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Update failed' });
  }
});

/* ===========================
   DELETE USER
=========================== */
app.post('/delete-user', async (req, res) => {
  const { idToken, customUid } = req.body;

  if (!idToken || !customUid) {
    return res.status(400).json({ error: 'Missing idToken or customUid' });
  }

  try {
    await verifyAdmin(idToken);

    const currentYearId = await getCurrentAcademicYearId();
    const userRef = db
      .collection('academic_years')
      .doc(currentYearId)
      .collection('users')
      .doc(customUid);

    const userSnap = await userRef.get();
    if (!userSnap.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = userSnap.data();

    if (userData.auth_uid) {
      try {
        await auth.deleteUser(userData.auth_uid);
      } catch (err) {
        console.warn('Auth user already deleted:', err.message);
      }
    }

    await userRef.delete();

    return res.json({ success: true, message: 'User deleted permanently' });
  } catch (err) {
    console.error('DELETE ERROR:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Delete failed' });
  }
});

/* ===========================
   SWITCH YEAR
=========================== */
app.post('/switch-year', async (req, res) => {
  const { idToken, newYearId } = req.body;

  if (!idToken || !newYearId) {
    return res.status(400).json({ error: 'Missing idToken or newYearId' });
  }

  try {
    await verifyAdmin(idToken);

    const batch = db.batch();

    const allYearsSnap = await db.collection('academic_years').get();
    allYearsSnap.docs.forEach(doc => {
      batch.update(doc.ref, { isCurrent: false });
    });

    const newYearRef = db.collection('academic_years').doc(newYearId);
    const newYearSnap = await newYearRef.get();
    if (!newYearSnap.exists) {
      return res.status(404).json({ error: 'Academic year not found' });
    }

    batch.update(newYearRef, { isCurrent: true });
    await batch.commit();

    return res.json({ success: true, message: `Current year switched to: ${newYearId}` });
  } catch (err) {
    console.error('SWITCH YEAR ERROR:', err);
    return res.status(500).json({ error: err.message || 'Failed to switch year' });
  }
});

/* ===========================
   HEALTH CHECK
=========================== */
app.get('/', (req, res) => {
  res.send('<h1>ADMIN SERVER RUNNING</h1><p>Endpoints: /create-user | /update-user | /delete-user | /switch-year</p>');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\nADMIN SERVER RUNNING → http://localhost:${PORT}`);
  console.log('Endpoints: /create-user | /update-user | /delete-user | /switch-year\n');
});
