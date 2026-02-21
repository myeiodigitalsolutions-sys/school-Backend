const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));

if (!process.env.FIREBASE_KEY) {
  process.exit(1);
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_KEY);
  serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
} catch {
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const auth = admin.auth();

const SUPERADMIN_EMAIL = 'moorthyn007@gmail.com';
const SUPERADMIN_PASSWORD = '23102001';

async function ensureSuperAdmin() {
  try {
    let userRecord;
    try {
      userRecord = await auth.getUserByEmail(SUPERADMIN_EMAIL);
      console.log('Superadmin already exists');
    } catch (err) {
      if (err.code !== 'auth/user-not-found') throw err;
      userRecord = await auth.createUser({
        email: SUPERADMIN_EMAIL,
        password: SUPERADMIN_PASSWORD,
      });
      console.log('Superadmin created');
    }

    const user = await auth.getUser(userRecord.uid);
    if (!user.customClaims || user.customClaims.superadmin !== true) {
      await auth.setCustomUserClaims(userRecord.uid, { superadmin: true });
    }

    const docRef = db.collection('users').doc('SUPERADMIN');
    const snap = await docRef.get();

    if (!snap.exists) {
      await docRef.set({
        uid: 'SUPERADMIN',
        auth_uid: userRecord.uid,
        email: SUPERADMIN_EMAIL,
        name: 'Super Admin',
        role: 'superadmin',
        created_at: new Date(),
      });
    }
  } catch {}
}

ensureSuperAdmin();

async function verifySuperAdmin(idToken) {
  if (!idToken) throw { code: 401, message: 'Missing idToken' };
  const decoded = await auth.verifyIdToken(idToken);
  if (decoded.superadmin === true) return decoded;
  throw { code: 403, message: 'Superadmin access only' };
}

async function verifyAdmin(idToken) {
  if (!idToken) throw { code: 401, message: 'Missing idToken' };
  const decoded = await auth.verifyIdToken(idToken);
  if (decoded.admin === true || decoded.superadmin === true) return decoded;
  throw { code: 403, message: 'Admin access required' };
}

app.post('/create-school', async (req, res) => {
  const { idToken, schoolCode, schoolName, email, password } = req.body || {};

  if (!idToken || !schoolCode || !schoolName || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const decoded = await verifySuperAdmin(idToken);

    try {
      await auth.getUserByEmail(email);
      return res.status(409).json({ error: 'Email already in use' });
    } catch (err) {
      if (err.code !== 'auth/user-not-found') throw err;
    }

    const createdAuthUser = await auth.createUser({ email, password });
    const adminUid = createdAuthUser.uid;

    await auth.setCustomUserClaims(adminUid, {
      admin: true,
      school: schoolCode
    });

    // Save school
    await db.collection('schools').doc(schoolCode).set({
      name: schoolName.trim(),
      schoolCode,
      adminEmail: email.trim(),
      adminUid,
      createdAt: new Date(),
    });

    // ✅ FIX: Use adminUid as document ID
    await db.collection('users').doc(adminUid).set({
      uid: adminUid,
      auth_uid: adminUid,
      email: email.trim(),
      name: schoolName.trim(),
      role: 'admin',
      schoolId: schoolCode,
      created_at: new Date(),
    });

    return res.json({
      success: true,
      message: 'School and admin created successfully',
      schoolCode,
      adminUid,
    });

  } catch (err) {
    return res.status(err.code || 500).json({
      error: err.message || 'Server error'
    });
  }
});

app.post('/update-school', async (req, res) => {
  const { idToken, schoolCode, schoolName, email, password } = req.body || {};

  if (!idToken || !schoolCode || !schoolName || !email) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    await verifySuperAdmin(idToken);

    const schoolRef = db.collection('schools').doc(schoolCode);
    const schoolSnap = await schoolRef.get();

    if (!schoolSnap.exists) {
      return res.status(404).json({ error: 'School not found' });
    }

    const schoolData = schoolSnap.data();
    const adminUid = schoolData.adminUid;

    if (!adminUid) {
      return res.status(500).json({ error: 'Admin UID missing in school document' });
    }

    // Update Firebase Auth
    const authUpdates = { email: email.trim() };
    if (password && password.trim() !== '') {
      authUpdates.password = password.trim();
    }

    await auth.updateUser(adminUid, authUpdates);

    // Update school document
    await schoolRef.update({
      name: schoolName.trim(),
      adminEmail: email.trim(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // ✅ FIX: Update user document using adminUid
    await db.collection('users').doc(adminUid).set({
      name: schoolName.trim(),
      email: email.trim(),
      updated_at: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    return res.json({
      success: true,
      message: 'School updated successfully'
    });

  } catch (err) {
    console.error('update-school error:', {
      schoolCode,
      errCode: err.code,
      message: err.message,
      stack: err.stack ? err.stack.substring(0, 500) : null
    });

    return res.status(500).json({
      error: err.message || 'Update failed'
    });
  }
});

app.post('/delete-school', async (req, res) => {
  const { idToken, schoolCode, schoolName } = req.body || {};

  if (!idToken || !schoolCode || !schoolName) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    await verifySuperAdmin(idToken);

    const schoolRef = db.collection('schools').doc(schoolCode);
    const schoolSnap = await schoolRef.get();

    if (!schoolSnap.exists) {
      return res.status(404).json({ error: 'School not found' });
    }

    const schoolData = schoolSnap.data();
    const adminUid = schoolData.adminUid;

    if (adminUid) {
      try {
        await auth.deleteUser(adminUid);
      } catch (err) {
        console.warn('Firebase Auth user deletion failed:', err.message);
      }
    }

    await schoolRef.delete();

    if (adminUid) {
      try {
        await db.collection('users').doc(adminUid).delete();
      } catch (err) {
        console.warn('Global users document deletion failed:', err.message);
      }
    }

    await db.collection('users').doc(schoolName).delete()
      .catch(err => {
        console.warn('Legacy users doc by name deletion attempt failed (can be ignored):', err.message);
      });

    return res.json({ 
      success: true, 
      message: 'School and admin account deleted successfully' 
    });
  } catch (err) {
    console.error('Delete school failed:', {
      schoolCode,
      error: err.message,
      code: err.code,
      stack: err.stack ? err.stack.substring(0, 400) : null
    });

    return res.status(err.code || 500).json({ 
      error: err.message || 'Delete failed - check server logs'
    });
  }
});

app.post('/create-user', async (req, res) => {
  const { idToken, schoolId, academicYearId, uid, email, name, dob, gender, role, password } = req.body || {};
  if (!idToken || !schoolId || !academicYearId || !uid || !email || !name || !dob || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    await verifyAdmin(idToken);
    const userInYearRef = db.collection('schools').doc(schoolId)
      .collection('academic_years').doc(academicYearId)
      .collection('users').doc(uid);
    const userInYearSnap = await userInYearRef.get();
    if (userInYearSnap.exists) {
      return res.status(409).json({ error: 'User ID already exists in this academic year' });
    }
    try {
      await auth.getUserByEmail(email);
      return res.status(409).json({ error: 'This email is already in use. Please use another email.' });
    } catch (err) {
      if (err.code !== 'auth/user-not-found') throw err;
    }
    const generatedPassword = password || dob.replace(/\//g, '');
    const newAuthUser = await auth.createUser({
      email,
      password: generatedPassword,
    });
    const authUid = newAuthUser.uid;
    const customClaims = { school: schoolId };
    if (role === 'principal' || role === 'admin') {
      customClaims.admin = true;
    }
    await auth.setCustomUserClaims(authUid, customClaims);
    await db.collection('users').doc(authUid).set({
      uid: uid,
      auth_uid: authUid,
      email: email,
      name: name,
      dob: dob,
      gender: gender || null,
      schoolId: schoolId,
      role: role,
      created_at: new Date(),
    }, { merge: true });
    await userInYearRef.set({
      uid: uid,
      auth_uid: authUid,
      email: email,
      name: name,
      dob: dob,
      gender: gender || null,
      role: role,
      created_at: new Date(),
    });
    if (role.toLowerCase() === 'principal') {
      const staffRef = db.collection('schools').doc(schoolId)
        .collection('academic_years').doc(academicYearId)
        .collection('staff').doc(uid);
      await staffRef.set({
        staff_id: uid,
        uid: uid,
        auth_uid: authUid,
        email: email,
        name: name,
        dob: dob,
        gender: gender || '',
        role: 'principal',
        department: '',
        blood_group: '',
        contact: '',
        address: '',
        joining_date: '',
        created_at: new Date(),
      });
    }
    return res.json({
      success: true,
      message: 'User created successfully',
      uid,
      auth_uid: authUid,
    });
  } catch (err) {
    console.error('Error creating user:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Failed to create user' });
  }
});

// app.post('/create-user', async (req, res) => {
//   const { idToken, schoolId, academicYearId, uid, email, name, dob,gender, role, password } = req.body || {};
//   if (!idToken || !schoolId || !academicYearId || !uid || !email || !name || !dob || !role) {
//     return res.status(400).json({ error: 'Missing required fields' });
//   }
//   try {
//     await verifyAdmin(idToken);
//     const userInYearRef = db.collection('schools').doc(schoolId)
//       .collection('academic_years').doc(academicYearId)
//       .collection('users').doc(uid);
//     const userInYearSnap = await userInYearRef.get();
//     if (userInYearSnap.exists) {
//       return res.status(409).json({ error: 'User ID already exists in this academic year' });
//     }
//     try {
//       await auth.getUserByEmail(email);
//       return res.status(409).json({ error: 'This email is already in use. Please use another email.' });
//     } catch (err) {
//       if (err.code !== 'auth/user-not-found') throw err;
//     }
//     const generatedPassword = password || dob.replace(/\//g, '');
//     const newAuthUser = await auth.createUser({
//       email,
//       password: generatedPassword,
//     });
//     const authUid = newAuthUser.uid;
//     const customClaims = { school: schoolId };
//     if (role === 'principal' || role === 'admin') {
//       customClaims.admin = true;
//     }
//     await auth.setCustomUserClaims(authUid, customClaims);
//     await db.collection('users').doc(authUid).set({
//       uid: uid,
//       auth_uid: authUid,
//       email: email,
//       name: name,
//       dob: dob,
//       gender: gender || null,
//       schoolId: schoolId,
//       role: role,
//       created_at: new Date(),
//     }, { merge: true });
//     await userInYearRef.set({
//       uid: uid,
//       auth_uid: authUid,
//       email: email,
//       name: name,
//       dob: dob,
//       gender: gender || null,
//       role: role,
//       created_at: new Date(),
//     });
//     return res.json({
//       success: true,
//       message: 'User created successfully',
//       uid,
//       auth_uid: authUid,
//     });
//   } catch (err) {
//     console.error('Error creating user:', err);
//     return res.status(err.code || 500).json({ error: err.message || 'Failed to create user' });
//   }
// });

app.post('/update-user', async (req, res) => {
  const { idToken, schoolId, academicYearId, uid, email, name, dob,gender, role } = req.body || {};
  if (!idToken || !schoolId || !academicYearId || !uid) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    await verifyAdmin(idToken);
    const userRef = db.collection('schools').doc(schoolId)
      .collection('academic_years').doc(academicYearId)
      .collection('users').doc(uid);
    const userSnap = await userRef.get();
    if (!userSnap.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    const existing = userSnap.data();
    const authUid = existing.auth_uid;
    const updateData = { updated_at: new Date() };
    if (email) updateData.email = email;
    if (name) updateData.name = name;
    if (dob) updateData.dob = dob;
    if (gender) updateData.gender = gender;
    if (role) updateData.role = role;
    await userRef.update(updateData);
    if (authUid && (email || name)) {
      const authUpdates = {};
      if (email) authUpdates.email = email;
      if (Object.keys(authUpdates).length > 0) {
        await auth.updateUser(authUid, authUpdates);
      }
      await db.collection('users').doc(authUid).update(updateData);
    }
    return res.json({
      success: true,
      message: 'User updated successfully',
      uid,
    });
  } catch (err) {
    console.error('Error updating user:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Failed to update user' });
  }
});

app.post('/delete-user', async (req, res) => {
  const { idToken, schoolId, academicYearId, uid } = req.body || {};
  if (!idToken || !schoolId || !academicYearId || !uid) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    await verifyAdmin(idToken);
    const userRef = db.collection('schools').doc(schoolId)
      .collection('academic_years').doc(academicYearId)
      .collection('users').doc(uid);
    const userSnap = await userRef.get();
    if (!userSnap.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    const userData = userSnap.data();
    const authUid = userData.auth_uid;
    await userRef.delete();
    if (authUid) {
      try {
        await auth.deleteUser(authUid);
      } catch (err) {
        console.warn('Auth user delete failed:', err);
      }
      try {
        await db.collection('users').doc(authUid).delete();
      } catch (err) {
        console.warn('Global user delete failed:', err);
      }
    }
    return res.json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    console.error('Error deleting user:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Failed to delete user' });
  }
});

app.post('/create-student', async (req, res) => {
  const {
    idToken, schoolId, academicYearId, student_id, email, name, dob, role,
    className, section, gender, blood_group, contact, address, password, ...otherFields
  } = req.body || {};
  if (!idToken || !schoolId || !academicYearId || !student_id || !email || !name || !dob) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    await verifyAdmin(idToken);
    const studentInYearRef = db.collection('schools').doc(schoolId)
      .collection('academic_years').doc(academicYearId)
      .collection('students').doc(student_id);
    const studentInYearSnap = await studentInYearRef.get();
    if (studentInYearSnap.exists) {
      return res.status(409).json({ error: 'Student ID already exists' });
    }
    try {
      await auth.getUserByEmail(email);
      return res.status(409).json({ error: 'This email is already in use. Please use another email.' });
    } catch (err) {
      if (err.code !== 'auth/user-not-found') throw err;
    }
    const generatedPassword = password || dob.replace(/\//g, '');
    const newAuthUser = await auth.createUser({
      email,
      password: generatedPassword,
    });
    const authUid = newAuthUser.uid;
    const customClaims = { school: schoolId };
    await auth.setCustomUserClaims(authUid, customClaims);
    await db.collection('users').doc(authUid).set({
      uid: student_id,
      auth_uid: authUid,
      email,
      name,
      dob,
      schoolId,
      role: role || 'student',
      created_at: new Date(),
    }, { merge: true });
    const userRef = db.collection('schools').doc(schoolId)
      .collection('academic_years').doc(academicYearId)
      .collection('users').doc(student_id);
    await userRef.set({
      uid: student_id,
      student_id,
      auth_uid: authUid,
      email,
      name,
      dob,
      role: role || 'student',
      created_at: new Date(),
    });
    const studentData = {
      student_id,
      uid: student_id,
      auth_uid: authUid,
      email,
      name,
      dob,
      role: role || 'student',
      class: className || '',
      section: section || '',
      gender: gender || '',
      blood_group: blood_group || '',
      contact: contact || '',
      address: address || '',
      created_at: new Date(),
      ...otherFields,
    };
    await studentInYearRef.set(studentData);
    return res.json({
      success: true,
      message: 'Student created successfully',
      student_id,
      auth_uid: authUid,
    });
  } catch (err) {
    console.error('Error creating student:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Failed to create student' });
  }
});

app.post('/create-staff', async (req, res) => {
  const {
    idToken, schoolId, academicYearId, staff_id, email, name, dob, role,
    department, gender, blood_group, contact, address, joining_date, password, ...otherFields
  } = req.body || {};
  if (!idToken || !schoolId || !academicYearId || !staff_id || !email || !name || !dob) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    await verifyAdmin(idToken);
    const staffInYearRef = db.collection('schools').doc(schoolId)
      .collection('academic_years').doc(academicYearId)
      .collection('staff').doc(staff_id);
    const staffInYearSnap = await staffInYearRef.get();
    if (staffInYearSnap.exists) {
      return res.status(409).json({ error: 'Staff ID already exists' });
    }
    try {
      await auth.getUserByEmail(email);
      return res.status(409).json({ error: 'This email is already in use. Please use another email.' });
    } catch (err) {
      if (err.code !== 'auth/user-not-found') throw err;
    }
    const generatedPassword = password || dob.replace(/\//g, '');
    const newAuthUser = await auth.createUser({
      email,
      password: generatedPassword,
    });
    const authUid = newAuthUser.uid;
    const customClaims = { school: schoolId };
    if (role === 'principal') {
      customClaims.admin = true;
    }
    await auth.setCustomUserClaims(authUid, customClaims);
    await db.collection('users').doc(authUid).set({
      uid: staff_id,
      auth_uid: authUid,
      email,
      name,
      dob,
      schoolId,
      role: role || 'teacher',
      created_at: new Date(),
    }, { merge: true });
    const userRef = db.collection('schools').doc(schoolId)
      .collection('academic_years').doc(academicYearId)
      .collection('users').doc(staff_id);
    await userRef.set({
      uid: staff_id,
      staff_id,
      auth_uid: authUid,
      email,
      name,
      dob,
      gender: gender || '',
      role: role || 'teacher',
      created_at: new Date(),
    });
    const staffData = {
      staff_id,
      uid: staff_id,
      auth_uid: authUid,
      email,
      name,
      dob,
      gender: gender || '',
      role: role || 'teacher',
      department: department || '',
      gender: gender || '',
      blood_group: blood_group || '',
      contact: contact || '',
      address: address || '',
      joining_date: joining_date || '',
      created_at: new Date(),
      ...otherFields,
    };
    await staffInYearRef.set(staffData);
    return res.json({
      success: true,
      message: 'Staff created successfully',
      staff_id,
      auth_uid: authUid,
    });
  } catch (err) {
    console.error('Error creating staff:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Failed to create staff' });
  }
});

app.post('/bulk-create-users', async (req, res) => {
  const { idToken, schoolId, academicYearId, users } = req.body || {};
  if (!idToken || !schoolId || !academicYearId || !users || !Array.isArray(users)) {
    return res.status(400).json({ error: 'Missing required fields or invalid users array' });
  }
  try {
    await verifyAdmin(idToken);
    const results = {
      success: [],
      failed: [],
    };

    // Helper to normalize DOB to "DD/MM/YYYY" format
    const normalizeDOB = (dobStr) => {
      if (!dobStr) return '';
      const cleaned = dobStr.trim().replace(/\s+/g, '');
      const parts = cleaned.split(/[-\/]/);
      if (parts.length !== 3) return cleaned;
      let [d, m, y] = parts.map(p => p.trim());
      if (d.length === 4) [y, m, d] = [d, m, y]; // if year first
      d = d.padStart(2, '0');
      m = m.padStart(2, '0');
      return `${d}/${m}/${y}`;
    };

    for (const user of users) {
      try {
        let { uid, email, name, dob, role, password } = user;
        if (!uid || !email || !name || !dob || !role) {
          results.failed.push({ uid, error: 'Missing required fields' });
          continue;
        }

        // Normalize incoming DOB
        dob = normalizeDOB(dob);

        const userRef = db.collection('schools').doc(schoolId)
          .collection('academic_years').doc(academicYearId)
          .collection('users').doc(uid);

        const userSnap = await userRef.get();
        let authUid;

        if (userSnap.exists) {
          // UPDATE EXISTING USER
          const existing = userSnap.data();
          authUid = existing.auth_uid;

          // Normalize existing DOB for comparison
          const existingDobNorm = normalizeDOB(existing.dob || '');

          const updateData = { updated_at: new Date() };
          if (email && email.trim().toLowerCase() !== (existing.email || '').trim().toLowerCase()) {
            updateData.email = email.trim().toLowerCase();
          }
          if (name && name.trim() !== (existing.name || '').trim()) {
            updateData.name = name.trim();
          }
          if (dob && dob !== existingDobNorm) {
            updateData.dob = dob;
          }
          if (role && role.trim().toLowerCase() !== (existing.role || '').trim().toLowerCase()) {
            updateData.role = role.trim().toLowerCase();
          }

          if (Object.keys(updateData).length > 1) {
            // Update users collection
            await userRef.update(updateData);

            // Update Firebase Auth
            if (authUid) {
              const authUpdates = {};
              if (updateData.email) authUpdates.email = updateData.email;
              if (password) authUpdates.password = password;
              if (Object.keys(authUpdates).length > 0) {
                try {
                  await auth.updateUser(authUid, authUpdates);
                } catch (authErr) {
                  console.warn(`Failed to update auth for ${uid}:`, authErr.message);
                }
              }
            }

            // Update global users collection
            if (authUid) {
              try {
                await db.collection('users').doc(authUid).update(updateData);
              } catch (globalErr) {
                console.warn(`Failed to update global user ${uid}:`, globalErr.message);
              }
            }

            // Update student/staff collection based on role
            const lowerRole = (updateData.role || existing.role || '').toLowerCase();
            if (lowerRole === 'student') {
              const studentRef = db.collection('schools').doc(schoolId)
                .collection('academic_years').doc(academicYearId)
                .collection('students').doc(uid);
              const studentSnap = await studentRef.get();
              if (studentSnap.exists) {
                await studentRef.update(updateData);
              }
            } else if (lowerRole === 'teacher' || lowerRole === 'principal') {
              const staffRef = db.collection('schools').doc(schoolId)
                .collection('academic_years').doc(academicYearId)
                .collection('staff').doc(uid);
              const staffSnap = await staffRef.get();
              if (staffSnap.exists) {
                await staffRef.update(updateData);
              }
            }
          }

          results.success.push({ uid, action: 'updated', auth_uid: authUid });
        } else {
          // CREATE NEW USER
          try {
            await auth.getUserByEmail(email);
            results.failed.push({ uid, error: 'This email is already in use. Please use another email.' });
            continue;
          } catch (err) {
            if (err.code !== 'auth/user-not-found') throw err;
          }

          const generatedPassword = password || dob.replace(/\//g, '');
          const newAuthUser = await auth.createUser({
            email,
            password: generatedPassword,
          });
          authUid = newAuthUser.uid;

          const customClaims = { school: schoolId };
          if (role === 'principal' || role === 'admin') {
            customClaims.admin = true;
          }
          await auth.setCustomUserClaims(authUid, customClaims);

          await db.collection('users').doc(authUid).set({
            uid,
            auth_uid: authUid,
            email,
            name,
            dob,
            gender: gender || '',
            schoolId,
            role,
            created_at: new Date(),
          }, { merge: true });

          await userRef.set({
            uid,
            auth_uid: authUid,
            email,
            name,
            dob,
            gender: gender || '',
            role,
            created_at: new Date(),
          });

          results.success.push({ uid, action: 'created', auth_uid: authUid });
        }
      } catch (err) {
        results.failed.push({ uid: user.uid || 'unknown', error: err.message });
      }
    }

    return res.json({
      success: true,
      message: `Bulk operation completed. Success: ${results.success.length}, Failed: ${results.failed.length}`,
      results,
    });
  } catch (err) {
    console.error('Error in bulk create:', err);
    return res.status(err.code || 500).json({ error: err.message || 'Bulk create failed' });
  }
});

app.get('/', (req, res) => {
  res.send('<h1>SERVER RUNNING</h1>');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`ADMIN SERVER RUNNING → http://localhost:${PORT}`);
});