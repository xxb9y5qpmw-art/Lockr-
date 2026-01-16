# Lockr-
Lockr is a modern, security-first password manager designed to store credentials locally with strong encryption. Built for learning and real-world use, Lockr focuses on privacy, simplicity, and clean architecture.
npx create-react-app vaultkey
cd vaultkey
npm start
npm install crypto-js
import { useState } from "react";
git clone https://github.com/yourusername/vaultkey.git
cd vaultkey
npm start
npm install
const firebaseConfig = {
  apiKey: "...",
  authDomain: "...",
  projectId: "...",
};
npx create-expo-app vaultkey-mobile
expo install expo-local-authentication

function App() {
  const [locked, setLocked] = useState(true);
vaultkey/
├── src/
│   ├── components/
│   ├── storage/
│   │   ├── masterPassword.js
│   │   ├── vault.js
│   │   └── cloudVault.js
│   ├── utils/
│   │   ├── crypto.js
│   │   └── passwordGenerator.js
│   ├── firebase.js
│   └── App.jsx
├── public/
└── README.md

  return (
    <div className="app">
      {locked ? (
        <div>
          <h1>🔐 VaultKey</h1>
          <input type="password" placeholder="Master Password" />
          <button>Unlock</button>
        </div>
      ) : (
        <h2>Vault Unlocked</h2>
      )}
    </div>
  );
}

export default App;
npm install crypto-js
src/utils/crypto.js
import CryptoJS from "crypto-js";

const ITERATIONS = 100000;

// Generate random salt
export function generateSalt() {
  return CryptoJS.lib.WordArray.random(128 / 8).toString();
}

// Derive key from master password
export function deriveKey(password, salt) {
  return CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: ITERATIONS,
  }).toString();
}

// Hash key for verification
export function hashKey(key) {
  return CryptoJS.SHA256(key).toString();
}
src/storage/masterPassword.js
import { generateSalt, deriveKey, hashKey } from "../utils/crypto";

const SALT_KEY = "vault_salt";
const HASH_KEY = "vault_master_hash";

export function isMasterPasswordSet() {
  return localStorage.getItem(HASH_KEY) !== null;
}

export function createMasterPassword(password) {
  const salt = generateSalt();
  const derivedKey = deriveKey(password, salt);
  const hash = hashKey(derivedKey);

  localStorage.setItem(SALT_KEY, salt);
  localStorage.setItem(HASH_KEY, hash);
}

export function verifyMasterPassword(password) {
  const salt = localStorage.getItem(SALT_KEY);
  const storedHash = localStorage.getItem(HASH_KEY);

  if (!salt || !storedHash) return false;

  const derivedKey = deriveKey(password, salt);
  const hash = hashKey(derivedKey);

  return hash === storedHash;
}
import { useState } from "react";
import {
  isMasterPasswordSet,
  createMasterPassword,
  verifyMasterPassword,
} from "./storage/masterPassword";

function App() {
  const [password, setPassword] = useState("");
  const [locked, setLocked] = useState(true);
  const [hasMaster, setHasMaster] = useState(isMasterPasswordSet());
  const [error, setError] = useState("");

  const handleSubmit = () => {
    if (!hasMaster) {
      if (password.length < 8) {
        setError("Password must be at least 8 characters");
        return;
      }
      createMasterPassword(password);
      setHasMaster(true);
      setLocked(false);
    } else {
      const valid = verifyMasterPassword(password);
      if (valid) {
        setLocked(false);
        setError("");
      } else {
        setError("Incorrect master password");
      }
    }
    setPassword("");
  };

  if (!locked) {
    return <h2>🔓 Vault Unlocked</h2>;
  }

  return (
    <div style={{ padding: 40 }}>
      <h1>🔐 VaultKey</h1>
      <p>{hasMaster ? "Enter Master Password" : "Create Master Password"}</p>

      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Master Password"
      />

      <button onClick={handleSubmit}>
        {hasMaster ? "Unlock" : "Create"}
      </button>

      {error && <p style={{ color: "red" }}>{error}</p>}
    </div>
  );
}

export default App;
Master Password
     ↓
PBKDF2 (Step 2)
     ↓
Derived Key (in memory only)
     ↓
AES Encrypt / Decrypt
     ↓
Encrypted Vault in localStorage
src/storage/vault.js
import CryptoJS from "crypto-js";

const VAULT_KEY = "vault_data";

// Encrypt vault with derived key
export function encryptVault(vault, key) {
  return CryptoJS.AES.encrypt(
    JSON.stringify(vault),
    key
  ).toString();
}

// Decrypt vault with derived key
export function decryptVault(ciphertext, key) {
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    return JSON.parse(decrypted);
  } catch {
    return [];
  }
}

// Load vault
export function loadVault(key) {
  const encrypted = localStorage.getItem(VAULT_KEY);
  if (!encrypted) return [];
  return decryptVault(encrypted, key);
}

// Save vault
export function saveVault(vault, key) {
  const encrypted = encryptVault(vault, key);
  localStorage.setItem(VAULT_KEY, encrypted);
}
import { deriveKey } from "./utils/crypto";
import { loadVault, saveVault } from "./storage/vault";
import { useState } from "react";
import {
  isMasterPasswordSet,
  createMasterPassword,
  verifyMasterPassword,
} from "./storage/masterPassword";
import { deriveKey } from "./utils/crypto";
import { loadVault, saveVault } from "./storage/vault";

function App() {
  const [password, setPassword] = useState("");
  const [locked, setLocked] = useState(true);
  const [hasMaster, setHasMaster] = useState(isMasterPasswordSet());
  const [error, setError] = useState("");
  const [key, setKey] = useState(null);
  const [vault, setVault] = useState([]);
  const [site, setSite] = useState("");
  const [username, setUsername] = useState("");
  const [sitePassword, setSitePassword] = useState("");

  const unlock = () => {
    if (!hasMaster) {
      createMasterPassword(password);
    }

    const valid = !hasMaster || verifyMasterPassword(password);
    if (!valid) {
      setError("Incorrect master password");
      return;
    }

    const salt = localStorage.getItem("vault_salt");
    const derivedKey = deriveKey(password, salt);

    const decryptedVault = loadVault(derivedKey);

    setKey(derivedKey);
    setVault(decryptedVault);
    setLocked(false);
    setPassword("");
    setError("");
  };

  const addEntry = () => {
    const updated = [
      ...vault,
      { id: Date.now(), site, username, password: sitePassword },
    ];

    setVault(updated);
    saveVault(updated, key);

    setSite("");
    setUsername("");
    setSitePassword("");
  };

  if (locked) {
    return (
      <div style={{ padding: 40 }}>
        <h1>🔐 VaultKey</h1>
        <p>{hasMaster ? "Enter Master Password" : "Create Master Password"}</p>

        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Master Password"
        />
        <button onClick={unlock}>
          {hasMaster ? "Unlock" : "Create"}
        </button>

        {error && <p style={{ color: "red" }}>{error}</p>}
      </div>
    );
  }

  return (
    <div style={{ padding: 40 }}>
      <h2>🔓 Vault</h2>

      <input
        placeholder="Website"
        value={site}
        onChange={(e) => setSite(e.target.value)}
      />
      <input
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        placeholder="Password"
        value={sitePassword}
        onChange={(e) => setSitePassword(e.target.value)}
      />
      <button onClick={addEntry}>Add</button>

      <ul>
        {vault.map((item) => (
          <li key={item.id}>
            <strong>{item.site}</strong> — {item.username} — {item.password}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default App;
const [search, setSearch] = useState("");
const [visibleId, setVisibleId] = useState(null);
const [editingId, setEditingId] = useState(null);
const deleteEntry = (id) => {
  const updated = vault.filter((item) => item.id !== id);
  setVault(updated);
  saveVault(updated, key);
};

const startEdit = (item) => {
  setEditingId(item.id);
  setSite(item.site);
  setUsername(item.username);
  setSitePassword(item.password);
};

const saveEdit = () => {
  const updated = vault.map((item) =>
    item.id === editingId
      ? { ...item, site, username, password: sitePassword }
      : item
  );

  setVault(updated);
  saveVault(updated, key);

  setEditingId(null);
  setSite("");
  setUsername("");
  setSitePassword("");
};
const filteredVault = vault.filter(
  (item) =>
    item.site.toLowerCase().includes(search.toLowerCase()) ||
    item.username.toLowerCase().includes(search.toLowerCase())
);
return (
  <div style={{ padding: 40, maxWidth: 600 }}>
    <h2>🔓 Vault</h2>

    <input
      placeholder="Search..."
      value={search}
      onChange={(e) => setSearch(e.target.value)}
      style={{ width: "100%", marginBottom: 10 }}
    />

    <input
      placeholder="Website"
      value={site}
      onChange={(e) => setSite(e.target.value)}
    />
    <input
      placeholder="Username"
      value={username}
      onChange={(e) => setUsername(e.target.value)}
    />
    <input
      placeholder="Password"
      type="password"
      value={sitePassword}
      onChange={(e) => setSitePassword(e.target.value)}
    />

    {editingId ? (
      <button onClick={saveEdit}>Save</button>
    ) : (
      <button onClick={addEntry}>Add</button>
    )}

    <ul style={{ marginTop: 20 }}>
      {filteredVault.map((item) => (
        <li key={item.id} style={{ marginBottom: 10 }}>
          <strong>{item.site}</strong>
          <div>{item.username}</div>

          <div>
            {visibleId === item.id ? item.password : "••••••••"}
            <button onClick={() =>
              setVisibleId(visibleId === item.id ? null : item.id)
            }>
              {visibleId === item.id ? "Hide" : "Show"}
            </button>
          </div>

          <button onClick={() => startEdit(item)}>Edit</button>
          <button onClick={() => deleteEntry(item.id)}>Delete</button>
        </li>
      ))}
    </ul>
  </div>
);
import { useEffect } from "react";
const AUTO_LOCK_TIME = 2 * 60 * 1000; // 2 minutes

useEffect(() => {
  if (locked) return;

  let timer = setTimeout(() => {
    lockApp();
  }, AUTO_LOCK_TIME);

  const resetTimer = () => {
    clearTimeout(timer);
    timer = setTimeout(lockApp, AUTO_LOCK_TIME);
  };

  window.addEventListener("mousemove", resetTimer);
  window.addEventListener("keydown", resetTimer);

  return () => {
    clearTimeout(timer);
    window.removeEventListener("mousemove", resetTimer);
    window.removeEventListener("keydown", resetTimer);
  };
}, [locked]);
const lockApp = () => {
  setLocked(true);
  setKey(null);
  setVault([]);
  setVisibleId(null);
};
src/utils/passwordGenerator.js
export function generatePassword(length = 16) {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(
      Math.floor(Math.random() * chars.length)
    );
  }
  return result;
}
import { generatePassword } from "./utils/passwordGenerator";
<button onClick={() => setSitePassword(generatePassword())}>
  Generate
</button>
const getStrength = (password) => {
  let score = 0;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 1) return "Weak";
  if (score === 2) return "Medium";
  return "Strong";
};
{sitePassword && (
  <p>Password Strength: {getStrength(sitePassword)}</p>
)}
Master Password
   ↓
PBKDF2 → Derived Key (local)
   ↓
AES Encrypt Vault (local)
   ↓
Upload ENCRYPTED blob to Firebase
npm install firebase
src/firebase.js
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "YOUR_KEY",
  authDomain: "YOUR_DOMAIN",
  projectId: "YOUR_ID",
  storageBucket: "YOUR_BUCKET",
  messagingSenderId: "YOUR_SENDER_ID",
  appId: "YOUR_APP_ID",
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
import { signInWithEmailAndPassword } from "firebase/auth";
import { auth } from "./firebase";

await signInWithEmailAndPassword(auth, email, password);
src/storage/cloudVault.js
import { doc, setDoc, getDoc } from "firebase/firestore";
import { db } from "../firebase";

export async function uploadVault(userId, encryptedVault) {
  await setDoc(doc(db, "vaults", userId), {
    vault: encryptedVault,
    updated: Date.now(),
  });
}

export async function downloadVault(userId) {
  const snap = await getDoc(doc(db, "vaults", userId));
  return snap.exists() ? snap.data().vault : null;
}
saveVault(updated, key);
uploadVault(auth.currentUser.uid, encryptVault(updated, key));
const encrypted = await downloadVault(uid);
const decrypted = decryptVault(encrypted, key);
setVault(decrypted);
npx create-expo-app vaultkey-mobile
cd vaultkey-mobile
expo install expo-local-authentication
import * as LocalAuthentication from "expo-local-authentication";

export async function authenticateBiometric() {
  const available =
    await LocalAuthentication.hasHardwareAsync();

  if (!available) return false;

  const result =
    await LocalAuthentication.authenticateAsync({
      promptMessage: "Unlock VaultKey",
    });

  return result.success;
}
const success = await authenticateBiometric();
if (success) {
  unlockVault();
}
