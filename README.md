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
{
  "vault": "...encrypted...",
  "version": 5,
  "updatedAt": 1710000000000
}import { doc, setDoc, getDoc } from "firebase/firestore";
import { db } from "../firebase";

export async function uploadVault(userId, encryptedVault, version) {
  await setDoc(doc(db, "vaults", userId), {
    vault: encryptedVault,
    version,
    updatedAt: Date.now(),
  });
}export async function downloadVaultWithMeta(userId) {
  const snap = await getDoc(doc(db, "vaults", userId));

  if (!snap.exists()) return null;

  return snap.data(); // { vault, version, updatedAt }
}const syncVault = async () => {
  const cloudData = await downloadVaultWithMeta(uid);

  if (!cloudData) return;

  if (cloudData.version > localVersion) {
    // Cloud is newer → overwrite local
    const decrypted = decryptVault(cloudData.vault, key);
    setVault(decrypted);
    setLocalVersion(cloudData.version);
  } else if (cloudData.version < localVersion) {
    // Local is newer → upload
    await uploadVault(uid, encryptVault(vault, key), localVersion);
  } else {
    // Same version → do nothing
  }
};export async function downloadVaultWithMeta(userId) {
  const snap = await getDoc(doc(db, "vaults", userId));

  if (!snap.exists()) return null;

  return snap.data(); // { vault, version, updatedAt }
}const syncVault = async () => {
  const cloudData = await downloadVaultWithMeta(uid);

  if (!cloudData) return;

  if (cloudData.version > localVersion) {
    // Cloud is newer → overwrite local
    const decrypted = decryptVault(cloudData.vault, key);
    setVault(decrypted);
    setLocalVersion(cloudData.version);
  } else if (cloudData.version < localVersion) {
    // Local is newer → upload
    await uploadVault(uid, encryptVault(vault, key), localVersion);
  } else {
    // Same version → do nothing
  }
};const newVersion = localVersion + 1;
setLocalVersion(newVersion);

saveVault(updated, key);
uploadVault(uid, encryptVault(updated, key), newVersion);const syncVault = async () => {
  const cloudData = await downloadVaultWithMeta(uid);

  if (!cloudData) return;

  if (cloudData.version > localVersion) {
    // Cloud is newer → overwrite local
    const decrypted = decryptVault(cloudData.vault, key);
    setVault(decrypted);
    setLocalVersion(cloudData.version);
  } else if (cloudData.version < localVersion) {
    // Local is newer → upload
    await uploadVault(uid, encryptVault(vault, key), localVersion);
  } else {
    // Same version → do nothing
  }
};const newVersion = localVersion + 1;
setLocalVersion(newVersion);

saveVault(updated, key);
uploadVault(uid, encryptVault(updated, key), newVersion);const mergeVaults = (local, cloud) => {
  const map = new Map();

  [...local, ...cloud].forEach((item) => {
    map.set(item.id, item); // last write wins
  });

  return Array.from(map.values());
};const merged = mergeVaults(localVault, cloudVault);await setDoc(doc(db, "vault_history", `${userId}_${Date.now()}`), {
  vault: encryptedVault,
  timestamp: Date.now(),
});npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -pexport default {
  content: ["./src/**/*.{js,jsx}"],
  theme: {
    extend: {},
  },
  plugins: [],
};@tailwind base;
@tailwind components;
@tailwind utilities;<div className="min-h-screen bg-gray-900 text-white p-6">
  <div className="max-w-xl mx-auto">

    <h1 className="text-3xl font-bold mb-6">🔐 VaultKey</h1>

    <input
      className="w-full p-2 mb-3 rounded bg-gray-800"
      placeholder="Search..."
      value={search}
      onChange={(e) => setSearch(e.target.value)}
    />

    <div className="bg-gray-800 p-4 rounded mb-4 space-y-2">
      <input
        className="w-full p-2 rounded bg-gray-700"
        placeholder="Website"
        value={site}
        onChange={(e) => setSite(e.target.value)}
      />
      <input
        className="w-full p-2 rounded bg-gray-700"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        className="w-full p-2 rounded bg-gray-700"
        type="password"
        placeholder="Password"
        value={sitePassword}
        onChange={(e) => setSitePassword(e.target.value)}
      />

      <div className="flex gap-2">
        <button
          className="bg-blue-600 px-4 py-2 rounded"
          onClick={editingId ? saveEdit : addEntry}
        >
          {editingId ? "Save" : "Add"}
        </button>

        <button
          className="bg-purple-600 px-4 py-2 rounded"
          onClick={() => setSitePassword(generatePassword())}
        >
          Generate
        </button>
      </div>
    </div><div className="space-y-3">
  {filteredVault.map((item) => (
    <div
      key={item.id}
      className="bg-gray-800 p-3 rounded shadow"
    >
      <div className="font-bold">{item.site}</div>
      <div className="text-sm text-gray-400">
        {item.username}
      </div>

      <div className="flex justify-between items-center mt-2">
        <span>
          {visibleId === item.id
            ? item.password
            : "••••••••"}
        </span>

        <div className="flex gap-2">
          <button onClick={() =>
            setVisibleId(
              visibleId === item.id ? null : item.id
            )
          }>
            👁
          </button>

          <button onClick={() => startEdit(item)}>✏️</button>
          <button onClick={() => deleteEntry(item.id)}>🗑</button>
        </div>
      </div>
    </div>
  ))}
</div>
const copyToClipboard = (text) => {
  navigator.clipboard.writeText(text);

  setTimeout(() => {
    navigator.clipboard.writeText("");
  }, 30000);
};<button onClick={lockApp}>
  🔒 Lock
</button>const reused = vault.filter(
  (item) => item.password === sitePassword
);

if (reused.length > 0) {
  alert("⚠️ This password is already used!");
}useEffect(() => {
  const handleVisibility = () => {
    if (document.hidden) lockApp();
  };

  document.addEventListener("visibilitychange", handleVisibility);
  return () =>
    document.removeEventListener("visibilitychange", handleVisibility);
}, []);new URL("https://google.com").hostnameconst exportVault = () => {
  const blob = new Blob([JSON.stringify(vault)], {
    type: "application/json",
  });

  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "vault.json";
  link.click();
};{
  action: "DELETE",
  site: "gmail.com",
  time: Date.now()
}"short_name": "VaultKey",
"display": "standalone"const [showWarning, setShowWarning] = useState(false);

useEffect(() => {
  if (locked) return;

  const warningTimer = setTimeout(() => {
    setShowWarning(true);
  }, AUTO_LOCK_TIME - 15000); // 15 sec before lock

  const lockTimer = setTimeout(() => {
    lockApp();
  }, AUTO_LOCK_TIME);

  return () => {
    clearTimeout(warningTimer);
    clearTimeout(lockTimer);
  };
}, [locked]);{showWarning && (
  <div className="bg-yellow-600 p-2 rounded mb-2">
    ⚠️ Session expiring soon...
    <button onClick={() => setShowWarning(false)}>
      Stay Logged In
    </button>
  </div>
)}let secureVault = null;

export function setSecureVault(data) {
  secureVault = data;
}

export function getSecureVault() {
  return secureVault;
}

export function clearSecureVault() {
  secureVault = null;
}let attempts = 0;

const handleUnlock = () => {
  if (attempts >= 5) {
    alert("Too many attempts. Try again later.");
    return;
  }

  const valid = verifyMasterPassword(password);

  if (!valid) {
    attempts++;
    return;
  }

  attempts = 0;
};let idleTimer;

const resetIdle = () => {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lockApp, AUTO_LOCK_TIME);
};

["click", "scroll", "keypress"].forEach((event) =>
  window.addEventListener(event, resetIdle)
);const [copiedId, setCopiedId] = useState(null);

const handleCopy = (id, text) => {
  navigator.clipboard.writeText(text);
  setCopiedId(id);

  setTimeout(() => setCopiedId(null), 2000);
};<button onClick={() => handleCopy(item.id, item.password)}>
  {copiedId === item.id ? "✅ Copied" : "Copy"}
</button>import { useEffect, useState } from "react";

const [debouncedSearch, setDebouncedSearch] = useState("");

useEffect(() => {
  const handler = setTimeout(() => {
    setDebouncedSearch(search);
  }, 300);

  return () => clearTimeout(handler);
}, [search]);const getSecurityScore = (vault) => {
  let score = 100;

  const weak = vault.filter(
    (v) => getStrength(v.password) === "Weak"
  ).length;

  const reused = new Set(
    vault.map((v) => v.password)
  ).size !== vault.length;

  score -= weak * 10;
  if (reused) score -= 20;

  return Math.max(score, 0);
};const backupVault = () => {
  const encrypted = encryptVault(vault, key);

  const blob = new Blob([encrypted], {
    type: "text/plain",
  });

  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "vault.backup";
  link.click();
};const [online, setOnline] = useState(navigator.onLine);

useEffect(() => {
  const update = () => setOnline(navigator.onLine);

  window.addEventListener("online", update);
  window.addEventListener("offline", update);

  return () => {
    window.removeEventListener("online", update);
    window.removeEventListener("offline", update);
  };
}, []);<p>{online ? "🟢 Online" : "🔴 Offline"}</p>const [blur, setBlur] = useState(false);

useEffect(() => {
  const handle = () => setBlur(document.hidden);
  document.addEventListener("visibilitychange", handle);
  return () =>
    document.removeEventListener("visibilitychange", handle);
}, []);<div className={blur ? "blur-md" : ""}>User visits website
      ↓
Extension detects domain
      ↓
Fetch encrypted vault (from your app / local)
      ↓
Decrypt (locally)
      ↓
Find matching credentials
      ↓
Autofill login formvaultkey-extension/
├── manifest.json
├── content.js
├── background.js
├── popup.html
├── popup.js
├── styles.css{
  "manifest_version": 3,
  "name": "VaultKey Autofill",
  "version": "1.0",
  "description": "Autofill passwords securely",
  "permissions": ["storage", "activeTab", "scripting"],
  "host_permissions": ["<all_urls>"],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_popup": "popup.html"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"]
    }
  ]
}function findLoginFields() {
  const inputs = document.querySelectorAll("input");

  let username = null;
  let password = null;

  inputs.forEach((input) => {
    if (
      input.type === "email" ||
      input.name.toLowerCase().includes("user")
    ) {
      username = input;
    }

    if (input.type === "password") {
      password = input;
    }
  });

  return { username, password };
}function autofill(credentials) {
  const { username, password } = findLoginFields();

  if (username) username.value = credentials.username;
  if (password) password.value = credentials.password;
}chrome.storage.local.get(["vault"], (result) => {
  const vault = result.vault || [];

  const domain = window.location.hostname;

  const match = vault.find((item) =>
    domain.includes(item.site)
  );

  if (match) {
    autofill(match);
  }
});chrome.runtime.sendMessage(
  { type: "GET_VAULT" },
  (response) => {
    const vault = response.vault;
  }
);chrome.runtime.onMessage.addListener(
  (request, sender, sendResponse) => {
    if (request.type === "GET_VAULT") {
      chrome.storage.local.get(["vault"], (data) => {
        sendResponse({ vault: data.vault || [] });
      });
      return true;
    }
  }
);<!DOCTYPE html>
<html>
  <body>
    <h3>VaultKey</h3>
    <button id="fill">Autofill</button>
    <script src="popup.js"></script>
  </body>
</html>document.getElementById("fill").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    chrome.scripting.executeScript({
      target: { tabId: tabs[0].id },
      func: () => {
        console.log("Trigger autofill");
      },
    });
  });
});const decrypted = decryptVault(encryptedVault, derivedKey);const normalize = (url) =>
  url.replace("www.", "").toLowerCase();

const match = vault.find((item) =>
  normalize(domain).includes(normalize(item.site))
);vaultkey-extension/import CryptoJS from "crypto-js";

export function encryptVault(data, key) {
  return CryptoJS.AES.encrypt(
    JSON.stringify(data),
    key
  ).toString();
}

export function decryptVault(cipher, key) {
  const bytes = CryptoJS.AES.decrypt(cipher, key);
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}import { encryptVault } from "../shared/crypto";

const encrypted = encryptVault(vault, key);

await uploadVault(uid, encrypted, version);import { getDoc, doc } from "firebase/firestore";

async function fetchVault(userId) {
  const snap = await getDoc(doc(db, "vaults", userId));
  return snap.data().vault; // still encrypted
}import { decryptVault } from "./crypto";

const decryptedVault = decryptVault(encryptedVault, derivedKey);import CryptoJS from "crypto-js";

function deriveKey(password, salt) {
  return CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 100000,
  }).toString();
}sendMessage({ vault: encryptedVault })setTimeout(() => {
  decryptedVault = null;
}, 10000);import CryptoJS from "crypto-js";

function signVault(data, key) {
  return CryptoJS.HmacSHA256(data, key).toString();
}{
  "vault": "...",
  "signature": "abc123"
}if (signVault(encryptedVault, key) !== signature) {
  throw new Error("Vault tampered!");
}{
  "vault": "...",
  "version": 5,
  "updatedAt": 1710000000000
}if (cloud.updatedAt < local.updatedAt) {
  ignore();
}src/utils/webcrypto.jsexport async function deriveKey(password, salt) {
  const enc = new TextEncoder();

  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false, // 🔥 non-extractable key
    ["encrypt", "decrypt"]
  );
}export async function encryptVault(data, key) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    enc.encode(JSON.stringify(data))
  );

  return {
    cipher: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: Array.from(iv),
  };
}export async function decryptVault(cipher, iv, key) {
  const dec = new TextDecoder();

  const encryptedBytes = Uint8Array.from(atob(cipher), c =>
    c.charCodeAt(0)
  );

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(iv),
    },
    key,
    encryptedBytes
  );

  return JSON.parse(dec.decode(decrypted));
}"vault": "encryptedstring"{
  "cipher": "...",
  "iv": [12, 34, 56, ...]
}const encrypted = await encryptVault(vault, key);

await uploadVault(uid, encrypted, version);const data = await downloadVault(uid);

const decrypted = await decryptVault(
  data.cipher,
  data.iv,
  key
);

setVault(decrypted);const lockApp = () => {
  setLocked(true);
  setKey(null); // destroys CryptoKey reference
  setVault([]);
};Master Password
     ↓
PBKDF2 → Encryption Key (WebCrypto)
     ↓
Vault Encryption (AES-GCM)

+ Hardware Key (WebAuthn)
     ↓
Used to unlock / verify user
     ↓
Protect access to encryption keyasync function registerHardwareKey() {
  const publicKey = {
    challenge: new Uint8Array(32),
    rp: { name: "VaultKey" },
    user: {
      id: new Uint8Array(16),
      name: "user@vaultkey",
      displayName: "VaultKey User",
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 } // ES256
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required",
    },
    timeout: 60000,
    attestation: "none",
  };

  const credential = await navigator.credentials.create({
    publicKey,
  });

  return credential;
}localStorage.setItem(
  "hardware_public_key",
  JSON.stringify(credential)
);async function authenticateHardwareKey() {
  const publicKey = {
    challenge: new Uint8Array(32),
    allowCredentials: [
      {
        id: new Uint8Array(credentialId),
        type: "public-key",
      },
    ],
    userVerification: "required",
  };

  const assertion = await navigator.credentials.get({
    publicKey,
  });

  return assertion;
}User opens app
   ↓
Hardware auth required
   ↓
Then allow master password entry
   ↓
Derive encryption keyVault Key (AES)
   ↓
Encrypted by KEK
   ↓
KEK unlocked via WebAuthnconst unlockVault = async () => {
  const success = await authenticateHardwareKey();

  if (!success) return;

  // THEN allow decryption
  const key = await deriveKey(password, salt);
};User signs up
   ↓
Device creates keypair (hardware)
   ↓
Public key → stored in Firebase
Private key → stays in device (never leaves)
   ↓
Login = biometric verificationasync function registerPasskey(email) {
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),

    rp: {
      name: "VaultKey",
      id: window.location.hostname,
    },

    user: {
      id: crypto.getRandomValues(new Uint8Array(16)),
      name: email,
      displayName: email,
    },

    pubKeyCredParams: [
      { type: "public-key", alg: -7 } // ES256
    ],

    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required",
      residentKey: "required"
    },

    timeout: 60000,
    attestation: "none",
  };

  const credential = await navigator.credentials.create({
    publicKey,
  });

  return credential;
}{
  "credentialId": "...",
  "publicKey": "...",
  "email": "user@email.com"
}async function loginWithPasskey(credentialId) {
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),

    allowCredentials: [
      {
        id: Uint8Array.from(atob(credentialId), c => c.charCodeAt(0)),
        type: "public-key",
      },
    ],

    userVerification: "required",
  };

  const assertion = await navigator.credentials.get({
    publicKey,
  });

  return assertion;
}Passkey unlock
   ↓
Allow access to encryption key
   ↓
Decrypt vaultconst unlockWithPasskey = async () => {
  const auth = await loginWithPasskey(credentialId);

  if (!auth) return;

  const key = await deriveKeyFromDevice(); // or stored method
  const vault = await decryptVault(cipher, iv, key);

  setVault(vault);
};Passkey → unlock device-bound key → decrypt vaultnpm install firebase-admin firebase-functions @simplewebauthn/server// functions/registerStart.js
const { generateRegistrationOptions } = require("@simplewebauthn/server");

exports.registerStart = async (req, res) => {
  const options = generateRegistrationOptions({
    rpName: "VaultKey",
    rpID: "yourdomain.com",

    userID: req.body.userId,
    userName: req.body.email,

    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
  });

  // Save challenge in DB
  await db.collection("challenges").doc(req.body.userId).set({
    challenge: options.challenge,
  });

  res.json(options);
};const options = await fetch("/registerStart").then(r => r.json());

const credential = await navigator.credentials.create({
  publicKey: options,
});// functions/registerFinish.js
const {
  verifyRegistrationResponse,
} = require("@simplewebauthn/server");

exports.registerFinish = async (req, res) => {
  const expectedChallenge = await getChallenge(req.body.userId);

  const verification = await verifyRegistrationResponse({
    response: req.body,
    expectedChallenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "yourdomain.com",
  });

  if (verification.verified) {
    const { credentialPublicKey, credentialID } =
      verification.registrationInfo;

    await db.collection("users").doc(req.body.userId).set({
      credentialID,
      publicKey: credentialPublicKey,
    });
  }

  res.json({ verified: verification.verified });
};const { generateAuthenticationOptions } =
  require("@simplewebauthn/server");

exports.loginStart = async (req, res) => {
  const user = await getUser(req.body.userId);

  const options = generateAuthenticationOptions({
    allowCredentials: [
      {
        id: user.credentialID,
        type: "public-key",
      },
    ],
    userVerification: "required",
  });

  await saveChallenge(req.body.userId, options.challenge);

  res.json(options);
};const options = await fetch("/loginStart").then(r => r.json());

const assertion = await navigator.credentials.get({
  publicKey: options,
});const {
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

exports.loginFinish = async (req, res) => {
  const user = await getUser(req.body.userId);
  const expectedChallenge = await getChallenge(req.body.userId);

  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "yourdomain.com",
    authenticator: {
      credentialPublicKey: user.publicKey,
      credentialID: user.credentialID,
      counter: 0,
    },
  });

  res.json({ verified: verification.verified });
};{ "verified": true }if (verified) {
  const key = await deriveKey(...);
  const vault = await decryptVault(cipher, iv, key);
  setVault(vault);
}
Frontend (React)
     ↓
Stripe Checkout
     ↓
Webhook (Firebase)
     ↓
Firestore → user.subscription = "premium"
     ↓
App unlocks premium featuresprice_12345
price_family_67890npm install stripeconst functions = require("firebase-functions");
const Stripe = require("stripe");

const stripe = new Stripe(process.env.STRIPE_SECRET);

exports.createCheckout = functions.https.onRequest(async (req, res) => {
  const { priceId, userId } = req.body;

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    mode: "subscription",
    line_items: [
      {
        price: priceId,
        quantity: 1,
      },
    ],
    success_url: "http://localhost:3000/success",
    cancel_url: "http://localhost:3000/cancel",
    metadata: { userId },
  });

  res.json({ url: session.url });
});const subscribe = async (priceId) => {
  const res = await fetch("/createCheckout", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      priceId,
      userId: currentUser.uid,
    }),
  });

  const data = await res.json();
  window.location.href = data.url;
};exports.stripeWebhook = functions.https.onRequest(async (req, res) => {
  const event = req.body;

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const userId = session.metadata.userId;

    await db.collection("users").doc(userId).update({
      subscription: "premium",
    });
  }

  res.sendStatus(200);
});const isPremium = user.subscription === "premium";if (!isPremium) {
  alert("Upgrade to Premium 🔒");
  return;
}export default function Pricing() {
  return (
    <div className="min-h-screen bg-gray-950 text-white py-16 px-6">
      <div className="max-w-5xl mx-auto text-center">

        {/* Header */}
        <h1 className="text-4xl font-bold mb-4">
          Simple, Secure Pricing
        </h1>
        <p className="text-gray-400 mb-12">
          Start free. Upgrade when you need more security and power.
        </p>

        {/* Plans */}
        <div className="grid md:grid-cols-3 gap-6">

          {/* FREE PLAN */}
          <div className="bg-gray-900 p-6 rounded-2xl border border-gray-800">
            <h2 className="text-xl font-semibold mb-2">Free</h2>
            <p className="text-3xl font-bold mb-4">$0</p>

            <ul className="text-gray-400 space-y-2 mb-6">
              <li>✔ Local password storage</li>
              <li>✔ Basic encryption</li>
              <li>✔ Manual entry</li>
            </ul>

            <button className="w-full bg-gray-700 py-2 rounded">
              Get Started
            </button>
          </div>

          {/* PREMIUM PLAN (HIGHLIGHTED) */}
          <div className="bg-gray-900 p-6 rounded-2xl border-2 border-blue-500 relative">

            <span className="absolute top-3 right-3 text-xs bg-blue-500 px-2 py-1 rounded">
              MOST POPULAR
            </span>

            <h2 className="text-xl font-semibold mb-2">Premium</h2>
            <p className="text-3xl font-bold mb-4">$2<span className="text-sm">/mo</span></p>

            <ul className="text-gray-300 space-y-2 mb-6">
              <li>✔ Cloud sync</li>
              <li>✔ Autofill extension</li>
              <li>✔ Security dashboard</li>
              <li>✔ Password generator</li>
              <li>✔ Encrypted backups</li>
            </ul>

            <button
              onClick={() => subscribe("price_premium")}
              className="w-full bg-blue-600 hover:bg-blue-700 py-2 rounded font-semibold"
            >
              Upgrade to Premium
            </button>
          </div>

          {/* FAMILY PLAN */}
          <div className="bg-gray-900 p-6 rounded-2xl border border-gray-800">
            <h2 className="text-xl font-semibold mb-2">Family</h2>
            <p className="text-3xl font-bold mb-4">$7<span className="text-sm">/mo</span></p>

            <ul className="text-gray-400 space-y-2 mb-6">
              <li>✔ Everything in Premium</li>
              <li>✔ Up to 5 users</li>
              <li>✔ Shared vaults</li>
              <li>✔ Admin controls</li>
            </ul>

            <button
              onClick={() => subscribe("price_family")}
              className="w-full bg-purple-600 hover:bg-purple-700 py-2 rounded"
            >
              Start Family Plan
            </button>
          </div>

        </div>

        {/* Footer */}
        <p className="text-gray-500 mt-10 text-sm">
          Cancel anytime. Secure payments powered by Stripe.
        </p>
      </div>
    </div>
  );
}const subscribe = async (priceId) => {
  const res = await fetch("/createCheckout", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      priceId,
      userId: currentUser.uid
    }),
  });

  const data = await res.json();
  window.location.href = data.url;
};<button className="bg-gray-800 px-4 py-2 rounded">
  Monthly
</button>
<button className="bg-gray-700 px-4 py-2 rounded">
  Yearly (Save 20%)
</button>className="hover:scale-105 transition-transform duration-200"className="border-2 border-blue-500 shadow-lg shadow-blue-500/20"export default function Landing() {
  return (
    <div className="bg-gray-950 text-white min-h-screen">

      {/* NAVBAR */}
      <nav className="flex justify-between items-center p-6 max-w-6xl mx-auto">
        <h1 className="text-xl font-bold">🔐 Lockr</h1>
        <div className="space-x-4">
          <button className="text-gray-300">Login</button>
          <button className="bg-blue-600 px-4 py-2 rounded">
            Get Started
          </button>
        </div>
      </nav>

      {/* HERO */}
      <section className="text-center py-20 px-6">
        <h1 className="text-5xl font-bold mb-6">
          The Last Password Manager You’ll Ever Need
        </h1>

        <p className="text-gray-400 max-w-2xl mx-auto mb-8">
          Zero-knowledge encryption. Passkey login. Autofill everywhere.
          Your data is yours—and only yours.
        </p>

        <div className="space-x-4">
          <button className="bg-blue-600 px-6 py-3 rounded text-lg">
            Start Free
          </button>
          <button className="border border-gray-700 px-6 py-3 rounded text-lg">
            View Pricing
          </button>
        </div>
      </section>

      {/* FEATURES */}
      <section className="py-16 px-6 max-w-6xl mx-auto grid md:grid-cols-3 gap-8">

        <div className="bg-gray-900 p-6 rounded-xl">
          <h3 className="text-xl font-semibold mb-2">🔐 Zero-Knowledge</h3>
          <p className="text-gray-400">
            Your vault is encrypted before it leaves your device. We can’t see your data.
          </p>
        </div>

        <div className="bg-gray-900 p-6 rounded-xl">
          <h3 className="text-xl font-semibold mb-2">⚡ Autofill Anywhere</h3>
          <p className="text-gray-400">
            Chrome extension fills your passwords instantly and securely.
          </p>
        </div>

        <div className="bg-gray-900 p-6 rounded-xl">
          <h3 className="text-xl font-semibold mb-2">🔑 Passkey Login</h3>
          <p className="text-gray-400">
            No passwords. Just Face ID, Touch ID, or your device.
          </p>
        </div>

      </section>

      {/* HOW IT WORKS */}
      <section className="py-20 text-center px-6">
        <h2 className="text-3xl font-bold mb-10">How Lockr Works</h2>

        <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
          <div>
            <h3 className="font-semibold mb-2">1. Save</h3>
            <p className="text-gray-400">Store passwords securely in your vault</p>
          </div>
          <div>
            <h3 className="font-semibold mb-2">2. Encrypt</h3>
            <p className="text-gray-400">Encrypted locally using AES-256</p>
          </div>
          <div>
            <h3 className="font-semibold mb-2">3. Access Anywhere</h3>
            <p className="text-gray-400">Sync across devices securely</p>
          </div>
        </div>
      </section>

      {/* SOCIAL PROOF */}
      <section className="py-16 text-center">
        <p className="text-gray-500">
          Built with modern security standards used by top tech companies
        </p>
      </section>

      {/* CTA */}
      <section className="py-20 text-center">
        <h2 className="text-3xl font-bold mb-6">
          Ready to Secure Your Digital Life?
        </h2>

        <button className="bg-blue-600 px-8 py-4 rounded text-lg">
          Get Started for Free
        </button>
      </section>

      {/* FOOTER */}
      <footer className="text-center text-gray-500 py-6">
        © 2026 Lockr. Secure by design.
      </footer>

    </div>
  );
}<img src="/demo.png" className="rounded-xl shadow-lg mx-auto mt-10" /><img src="/demo.png" className="rounded-xl shadow-lg mx-auto mt-10" /><p className="text-sm text-red-400">
  Limited early access pricing 🚀
Sidebar
  ├ Vault
  ├ Security Dashboard
  ├ Shared (Family)
  ├ Settings

Main Area
  ├ Search + Add Password
  ├ Vault List
  ├ Security Scoreexport default function Dashboard({ vault, user }) {
  return (
    <div className="flex h-screen bg-gray-950 text-white">

      {/* SIDEBAR */}
      <aside className="w-64 bg-gray-900 p-6 flex flex-col justify-between">
        <div>
          <h1 className="text-xl font-bold mb-8">🔐 Lockr</h1>

          <nav className="space-y-4 text-gray-300">
            <p className="hover:text-white cursor-pointer">Vault</p>
            <p className="hover:text-white cursor-pointer">Security</p>
            <p className="hover:text-white cursor-pointer">Shared</p>
            <p className="hover:text-white cursor-pointer">Settings</p>
          </nav>
        </div>

        <div className="text-sm text-gray-400">
          {user.email}
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="flex-1 p-6 overflow-y-auto">

        {/* TOP BAR */}
        <div className="flex justify-between items-center mb-6">
          <input
            placeholder="Search passwords..."
            className="bg-gray-800 px-4 py-2 rounded w-1/3"
          />

          <button className="bg-blue-600 px-4 py-2 rounded">
            + Add Password
          </button>
        </div>

        {/* SECURITY CARD */}
        <div className="bg-gray-900 p-6 rounded-xl mb-6">
          <h2 className="text-lg font-semibold mb-2">
            Security Score
          </h2>

          <p className="text-3xl font-bold text-green-400">
            82%
          </p>

          <p className="text-gray-400 mt-2">
            2 weak passwords, 1 reused
          </p>
        </div>

        {/* VAULT LIST */}
        <div className="bg-gray-900 rounded-xl overflow-hidden">
          <table className="w-full text-left">

            <thead className="bg-gray-800 text-gray-400">
              <tr>
                <th className="p-4">Site</th>
                <th className="p-4">Username</th>
                <th className="p-4">Password</th>
                <th className="p-4"></th>
              </tr>
            </thead>

            <tbody>
              {vault.map((item) => (
                <tr key={item.id} className="border-t border-gray-800">

                  <td className="p-4">{item.site}</td>

                  <td className="p-4">{item.username}</td>

                  <td className="p-4">
                    ••••••••
                  </td>

                  <td className="p-4 space-x-2">
                    <button className="text-blue-400">Copy</button>
                    <button className="text-gray-400">Edit</button>
                  </td>

                </tr>
              ))}
            </tbody>

          </table>
        </div>

      </main>
    </div>
  );
}className="hover:bg-gray-800 transition"className="bg-gray-900/80 backdrop-blur-md"className="transition-all duration-200 hover:scale-[1.01]"<div className="grid md:grid-cols-3 gap-4 mb-6">

  <div className="bg-gray-900 p-4 rounded">
    <p className="text-gray-400">Weak Passwords</p>
    <p className="text-xl font-bold text-red-400">2</p>
  </div>

  <div className="bg-gray-900 p-4 rounded">
    <p className="text-gray-400">Reused</p>
    <p className="text-xl font-bold text-yellow-400">1</p>
  </div>

  <div className="bg-gray-900 p-4 rounded">
    <p className="text-gray-400">Strong</p>
    <p className="text-xl font-bold text-green-400">12</p>
  </div>

</div><div className="flex gap-4 mb-6">

  <button className="bg-gray-800 px-4 py-2 rounded">
    Generate Password
  </button>

  <button className="bg-gray-800 px-4 py-2 rounded">
    Import
  </button>

  <button className="bg-gray-800 px-4 py-2 rounded">
    Backup
  </button>

</div>if (!user.isPremium) {
  return (
    <div className="bg-gray-900 p-6 rounded text-center">
      <h2 className="text-xl mb-2">Upgrade to Premium 🔒</h2>
      <p className="text-gray-400 mb-4">
        Unlock autofill, cloud sync, and more.
      </p>
      <button className="bg-blue-600 px-4 py-2 rounded">
        Upgrade
      </button>
    </div>
  );
}
