// server.js
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

// Get current academic year ID from document with isCurrent: true
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

/**
 * Verify caller is global admin from top-level /users collection
 */
async function verifyAdmin(idToken) {
  if (!idToken) throw { code: 401, message: 'Missing idToken' };

  const decoded = await auth.verifyIdToken(idToken);
  const callerAuthUid = decoded.uid;

  // Check custom claim first (optional extra layer)
  if (decoded.admin === true) {
    return decoded;
  }

  // Check in global users collection
  let adminDoc = null;

  // Try by auth_uid field
  const q = await db.collection('users')
    .where('auth_uid', '==', callerAuthUid)
    .limit(1)
    .get();

  if (!q.empty) {
    adminDoc = q.docs[0];
  }

  // Fallback: try by document ID = auth_uid
  if (!adminDoc) {
    const fallbackSnap = await db.collection('users').doc(callerAuthUid).get();
    if (fallbackSnap.exists) {
      adminDoc = fallbackSnap;
    }
  }

  if (!adminDoc) {
    throw { code: 403, message: 'Only global admins can perform this action' };
  }

  const data = adminDoc.data();
  const role = (data.role || '').toLowerCase();
  const uidUpper = (data.uid || '').toString().toUpperCase();

  const isAdmin = role.includes('admin') ||
                  ['ADMIN001', 'SUPERADMIN', 'ROOT'].includes(uidUpper) ||
                  uidUpper.startsWith('SUPER');

  if (!isAdmin) {
    throw { code: 403, message: 'Only global admins can perform this action' };
  }

  return decoded;
}

/**
 * POST /create-user
 * Creates regular user ONLY in current academic year
 */
app.post('/create-user', async (req, res) => {
  const { idToken, customUid, email, password, role = 'student', name = '', dob = '' } = req.body || {};

  if (!idToken || !customUid || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    await verifyAdmin(idToken);

    const uidUpper = customUid.toString().trim().toUpperCase();
    if (['ADMIN001', 'SUPERADMIN', 'ROOT'].includes(uidUpper) || uidUpper.startsWith('SUPER')) {
      return res.status(403).json({ error: 'Cannot create reserved UID' });
    }

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

/**
 * POST /update-user
 */
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
    let authUpdates = {};

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

/**
 * POST /delete-user
 */
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
    const uidUpper = (userData.uid || '').toString().toUpperCase();
    if (['ADMIN001', 'SUPERADMIN', 'ROOT'].includes(uidUpper) || uidUpper.startsWith('SUPER')) {
      return res.status(403).json({ error: 'Cannot delete global admin' });
    }

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

/**
 * POST /switch-year
 * Global admin only: switches current academic year by setting isCurrent: true on one document
 */
app.post('/switch-year', async (req, res) => {
  const { idToken, newYearId } = req.body;

  if (!idToken || !newYearId) {
    return res.status(400).json({ error: 'Missing idToken or newYearId' });
  }

  try {
    await verifyAdmin(idToken);

    const batch = db.batch();

    // Clear isCurrent from all years
    const allYearsSnap = await db.collection('academic_years').get();
    allYearsSnap.docs.forEach(doc => {
      batch.update(doc.ref, { isCurrent: false });
    });

    // Set new year as current
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

// Health check
app.get('/', (req, res) => {
  res.send('<h1>ADMIN SERVER RUNNING</h1><p>Endpoints: /create-user | /update-user | /delete-user | /switch-year</p>');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\nADMIN SERVER RUNNING → http://localhost:${PORT}`);
  console.log('Endpoints: /create-user | /update-user | /delete-user | /switch-year\n');
});