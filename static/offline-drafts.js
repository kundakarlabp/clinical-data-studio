(function () {
  const DB_NAME = "clinical-data-studio-offline";
  const DB_VERSION = 1;
  const STORE = "entryDrafts";

  function openDb() {
    return new Promise((resolve, reject) => {
      if (!("indexedDB" in window)) {
        reject(new Error("IndexedDB is not available in this browser."));
        return;
      }
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE)) {
          const store = db.createObjectStore(STORE, { keyPath: "key" });
          store.createIndex("studyId", "studyId", { unique: false });
          store.createIndex("updatedAt", "updatedAt", { unique: false });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Could not open offline draft database."));
    });
  }

  function txStore(db, mode) {
    return db.transaction(STORE, mode).objectStore(STORE);
  }

  function requestToPromise(request) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Offline draft operation failed."));
    });
  }

  async function putDraft(draft) {
    const db = await openDb();
    try {
      return await requestToPromise(txStore(db, "readwrite").put({ ...draft, updatedAt: Date.now(), synced: false }));
    } finally {
      db.close();
    }
  }

  async function getDraft(key) {
    const db = await openDb();
    try {
      return await requestToPromise(txStore(db, "readonly").get(key));
    } finally {
      db.close();
    }
  }

  async function deleteDraft(key) {
    const db = await openDb();
    try {
      return await requestToPromise(txStore(db, "readwrite").delete(key));
    } finally {
      db.close();
    }
  }

  async function listDrafts(studyId) {
    const db = await openDb();
    try {
      const drafts = await requestToPromise(txStore(db, "readonly").getAll());
      return drafts.filter((draft) => !studyId || draft.studyId === studyId).sort((a, b) => b.updatedAt - a.updatedAt);
    } finally {
      db.close();
    }
  }

  function entryKey({ studyId, participantId, formId, eventId, repeatInstance }) {
    return [studyId, participantId, formId, eventId || "baseline", repeatInstance || 1].join(":");
  }

  window.CDSOfflineDrafts = { putDraft, getDraft, deleteDraft, listDrafts, entryKey };
})();
