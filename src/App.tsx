import { useEffect, useEffectEvent, useRef } from "react";
import {
  AlertTriangle,
  Check,
  Database,
  Lock,
  Moon,
  Redo2,
  Settings,
  Sun,
  Undo2,
} from "lucide-react";
import { pickImportFile, vaultSave } from "./vaultApi";
import { VAULT_SCHEMA_VERSION, type VaultGraph } from "./vaultDocument";
import { retainedAttachmentIds } from "./history";
import { clearCopiedSecrets } from "./clipboard";
import { APP_NAME_HEAD, APP_NAME_TAIL } from "./brand";
import { useTheme } from "./theme";
import { serviceIconFor } from "./serviceIcons";
import { Logo } from "./components/bits";
import { UpdateDialog } from "./components/UpdateDialog";
import { LockScreen } from "./components/LockScreen";
import { SettingsModal } from "./components/SettingsModal";
import { AccountList } from "./components/AccountList";
import { AccountDetail } from "./components/AccountDetail";
import { useHistory, useUndoRedoShortcuts } from "./hooks/useHistory";
import { useAccounts } from "./hooks/useAccounts";
import { useVaultSession, type DraftFlushResult } from "./hooks/useVaultSession";
import { useUpdater } from "./hooks/useUpdater";
import { useAutoLock } from "./hooks/useAutoLock";
import "./App.css";

function App() {
  const { preference: themePreference, resolved: resolvedTheme, setPreference: setThemePreference } = useTheme();
  const history = useHistory();
  const accounts = useAccounts(history.commit);

  // Saves are strictly serialized: an auto-save, a lock flush and a package
  // export can otherwise overlap and race on the same vault file.
  const saveQueue = useRef<Promise<boolean>>(Promise.resolve(true));
  // The path/generation the in-memory document belongs to, captured when a
  // save is requested. A queued save therefore carries the session it was
  // prepared for and the backend refuses it after a vault switch (KV-04).
  const saveTarget = useRef<{ path: string; generation: number | null }>({
    path: "",
    generation: null,
  });

  const doPersist = useEffectEvent(async (): Promise<boolean> => {
    const revision = accounts.revision;
    const target = saveTarget.current;
    if (target.path === "" || target.generation === null) {
      accounts.markSaveFailed();
      return false;
    }
    const expectedPath = target.path;
    const expectedGeneration = target.generation;
    const document: VaultGraph = {
      ...accounts.extraKeys,
      accounts: accounts.accounts,
      schemaVersion: VAULT_SCHEMA_VERSION,
      presets: accounts.presets,
      attachments: accounts.attachments,
      serviceIcons: accounts.serviceIcons,
    };
    const retained = retainedAttachmentIds(accounts.snapshot(), history.history);
    const run = saveQueue.current.then(async () => {
      try {
        await vaultSave(document, retained, expectedPath, expectedGeneration);
        accounts.markSaved(revision);
        return true;
      } catch (error) {
        const message = typeof error === "string" ? error : "";
        if (message.includes("vault_conflict")) accounts.markSaveConflict();
        else accounts.markSaveFailed();
        return false;
      }
    });
    saveQueue.current = run;
    return run;
  });

  // Central draft flush: every editor saves its focused draft and reports
  // whether it changed anything, so lock/close/export never clear state before
  // the draft is committed to the document. A rejected draft blocks the lock
  // instead of being silently dropped.
  const flushDrafts = useEffectEvent(async (): Promise<DraftFlushResult> => {
    const detail: DraftFlushResult = { changed: false, failed: false };
    window.dispatchEvent(new CustomEvent("keevra:flush-drafts", { detail }));
    if (detail.changed) {
      // Let React commit the flushed drafts before persist() snapshots state.
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    return detail;
  });

  function applyVaultDocument(stored: VaultGraph) {
    accounts.applyVaultDocument(stored);
    history.reset();
  }

  function onLocked() {
    void clearCopiedSecrets();
    accounts.clearDomain();
    history.reset();
  }

  const session = useVaultSession({
    dirty: accounts.dirty,
    persist: doPersist,
    flushDrafts,
    waitForPendingAttachments: accounts.pendingAttachments,
    applyVaultDocument,
    onLocked,
  });
  // Keep the save binding in step with the session state that owns the
  // document currently in `accounts`.
  saveTarget.current = {
    path: session.vaultPath,
    generation: session.vaultGeneration,
  };

  const updater = useUpdater({ beforeRestart: () => session.handleVaultClose() });

  const vaultActive = session.backend === "unlocked";

  function handleUndo() {
    const snapshot = history.undo(accounts.snapshot());
    if (snapshot) accounts.applySnapshot(snapshot);
  }

  function handleRedo() {
    const snapshot = history.redo(accounts.snapshot());
    if (snapshot) accounts.applySnapshot(snapshot);
  }

  useUndoRedoShortcuts(handleUndo, handleRedo);

  // Locking flushes unsaved changes itself and refuses to lock when the flush
  // fails, so memory is never cleared before the data is safely on disk.
  // A refused lock keeps auto-lock armed so the session cannot stay open by
  // accident after one failed save.
  useAutoLock(vaultActive, () => session.handleVaultLock());

  // Stable view of the close handler for the window listener registered once.
  const closeVault = useEffectEvent(() => session.handleVaultClose());

  // Latest session state for the window close handler, read without stale
  // closures. A ref updated in an effect can lag one commit behind a lock, so
  // the lock screen could still take the "save first" branch and (if the
  // destroy permission was unavailable) swallow the close entirely.
  const needsSaveBeforeClose = useEffectEvent(() => session.backend === "unlocked");

  // Guards against a second close request while the save-then-destroy flow is
  // already running (e.g. a double click on the title-bar X).
  const closingRef = useRef(false);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void (async () => {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        const appWindow = getCurrentWindow();
        const stop = await appWindow.onCloseRequested(async (event) => {
          // Locked/boot/demo: never intercept. The native close proceeds even
          // if the explicit destroy below is denied, so the title-bar X always
          // works on the lock screen.
          if (!needsSaveBeforeClose()) {
            try {
              await appWindow.destroy();
            } catch {
              // Native close still proceeds because the event was not prevented.
            }
            return;
          }
          // Unlocked: hold the close until drafts are flushed and the vault is
          // on disk, then destroy. A failed save cancels the close.
          event.preventDefault();
          if (closingRef.current) return;
          closingRef.current = true;
          try {
            // handleVaultClose flushes drafts and persists before locking.
            if (await closeVault()) await appWindow.destroy();
          } catch (error) {
            console.error("Keevra: close request failed", error);
          } finally {
            closingRef.current = false;
          }
        });
        if (disposed) stop();
        else unlisten = stop;
      } catch {
        // Browser/demo mode has no Tauri window to intercept.
      }
    })();
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  // Auto-save: every committed mutation persists ~1s after the last change.
  useEffect(() => {
    if (!vaultActive || !accounts.dirty) return;
    const timer = setTimeout(() => void doPersist(), 1000);
    return () => clearTimeout(timer);
  }, [
    vaultActive,
    accounts.dirty,
    accounts.revision,
    accounts.accounts,
    accounts.presets,
    accounts.attachments,
    accounts.serviceIcons,
  ]);

  // Root-level update announcement: visible on the lock screen as soon as the
  // background check finds a newer release, and hidden behind Settings so the
  // two dialogs never stack.
  const updateDialog =
    updater.updateCheck.phase === "available" &&
    updater.updateDismissedTag !== updater.updateCheck.release?.tag_name &&
    !session.showSettings ? (
      <UpdateDialog
        check={updater.updateCheck}
        busy={updater.updateBusy}
        onDownload={() => void updater.handleUpdateDownload()}
        onLater={updater.dismissUpdate}
        onCopyLink={() => void updater.copyReleaseLink()}
      />
    ) : null;

  if (session.backend === "checking") {
    return (
      <>
        <main className="app">
          <div className="boot">
            <Logo size={52} />
            <p>Decrypting your universe…</p>
          </div>
        </main>
        {updateDialog}
      </>
    );
  }

  if (session.backend === "locked") {
    return (
      <>
        <LockScreen
          vaults={session.vaults}
          defaultPath={session.defaultVaultPath}
          selectedPath={session.vaultPath}
          onSelectPath={session.setVaultPath}
          busy={session.lockBusy}
          error={session.lockError}
          notice={session.lockNotice}
          onCreate={session.handleVaultCreate}
          onOpen={session.handleVaultOpen}
          onRestore={session.handleVaultRestore}
          onForget={session.handleVaultForget}
          onRemember={session.handleVaultRemember}
          onRename={session.handleVaultRename}
          onPickFile={pickImportFile}
          onDeleteVault={session.handleVaultDelete}
        />
        {updateDialog}
      </>
    );
  }

  return (
    <main className="app">
      <header className="topbar">
        <div className="brand">
          <Logo />
          <span className="brand-name">
            {APP_NAME_HEAD}
            <em>{APP_NAME_TAIL}</em>
          </span>
          {session.vaultName !== "" ? (
            <span className="vault-pill" title={session.vaultName}>
              <span className="dot">
                <Database />
              </span>
              <span>{session.vaultName}</span>
            </span>
          ) : null}
          <span className="lock-badge" title={vaultActive ? "Encrypted at rest" : "Demo data, no persistence"}>
            <Lock /> {vaultActive ? "Encrypted" : "Demo"}
          </span>
        </div>
        <div className="topbar-spacer" />
        {vaultActive ? (
          <>
            {accounts.saveConflict ? (
              <span className="save-state save-state--error">
                <AlertTriangle style={{ width: 14, height: 14 }} /> Changed on disk
                <button
                  type="button"
                  className="mini-btn"
                  title="Discard unsaved edits, lock, and load the newest file on unlock"
                  onClick={() => void session.handleVaultReloadExternal()}
                >
                  Discard &amp; reload
                </button>
              </span>
            ) : accounts.saveError ? (
              <span className="save-state save-state--error">
                <AlertTriangle style={{ width: 14, height: 14 }} /> Save failed
                <button type="button" className="mini-btn" onClick={() => void doPersist()}>
                  Retry
                </button>
              </span>
            ) : accounts.dirty ? (
              <span className="save-state">
                <span className="pulse" /> Saving…
              </span>
            ) : (
              <span className="save-state">
                <Check style={{ width: 14, height: 14 }} /> Saved
              </span>
            )}
            <button
              type="button"
              className="icon-btn"
              disabled={history.history.past.length === 0}
              onClick={handleUndo}
              title="Undo (Ctrl+Z)"
              aria-label="Undo"
            >
              <Undo2 />
            </button>
            <button
              type="button"
              className="icon-btn"
              disabled={history.history.future.length === 0}
              onClick={handleRedo}
              title="Redo (Ctrl+Y)"
              aria-label="Redo"
            >
              <Redo2 />
            </button>
            <button
              type="button"
              className="icon-btn"
              onClick={() => setThemePreference(resolvedTheme === "dark" ? "light" : "dark")}
              title={resolvedTheme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              aria-label={resolvedTheme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            >
              {resolvedTheme === "dark" ? <Sun /> : <Moon />}
            </button>
            <button
              type="button"
              className="icon-btn"
              onClick={() => session.setShowSettings(true)}
              title="Settings"
              aria-label="Settings"
            >
              <Settings />
            </button>
            <button
              type="button"
              className="icon-btn icon-btn--primary"
              onClick={() => void session.handleVaultLock()}
              title="Lock vault"
            >
              <Lock /> Lock
            </button>
          </>
        ) : (
          <span className="save-state">Demo mode · fake data only · no persistence</span>
        )}
      </header>

      {vaultActive && accounts.migrationWarnings.length > 0 ? (
        <div className="migration-banner" role="status">
          <AlertTriangle style={{ width: 15, height: 15 }} />
          <span>{accounts.migrationWarnings.join(" ")}</span>
          <button type="button" className="mini-btn" onClick={accounts.dismissMigrationWarnings}>
            Dismiss
          </button>
        </div>
      ) : null}

      {vaultActive && session.showSettings ? (
        <SettingsModal
          vaults={session.vaults}
          defaultPath={session.defaultVaultPath}
          currentPath={session.vaultPath}
          onClose={() => session.setShowSettings(false)}
          onDefaultChange={session.handleDefaultChange}
          onCreateVault={session.handleSettingsCreate}
          onExportPackage={() => void session.handleExportPackage()}
          onImportPackage={() => void session.handleImportPackage()}
          packageMessage={session.packageMessage}
          themePreference={themePreference}
          onThemeChange={setThemePreference}
          updateCheck={updater.updateCheck}
          updateBusy={updater.updateBusy}
          onCheckUpdates={() => void updater.checkForUpdates(true)}
          onDownloadUpdate={() => void updater.handleUpdateDownload()}
        />
      ) : null}

      {updateDialog}

      <div className="workspace">
        <AccountList
          accounts={accounts.visibleAccounts}
          serviceIcons={accounts.serviceIcons}
          selectedId={accounts.selectedAccountId}
          query={accounts.query}
          onQuery={accounts.setQuery}
          onSelect={accounts.setSelectedAccountId}
          onAdd={accounts.addAccount}
          addError={accounts.addError}
        />
        {accounts.selectedAccount !== null ? (
          <AccountDetail
            key={accounts.selectedAccount.id}
            account={accounts.selectedAccount}
            attachments={accounts.selectedAttachments}
            serviceIcon={serviceIconFor(accounts.serviceIcons, accounts.selectedAccount.service)}
            onSetServiceIcon={accounts.setServiceIcon}
            services={accounts.serviceOptions}
            tags={accounts.tagOptions}
            onSaveIdentity={accounts.saveIdentity}
            onAddField={accounts.addField}
            onSaveField={accounts.saveField}
            onRemoveField={accounts.removeField}
            onUploadAttachment={() => void accounts.uploadAttachment()}
            onDownloadAttachment={(meta) => void accounts.downloadAttachment(meta)}
            onDeleteAttachment={accounts.deleteAttachment}
            attachmentBusy={accounts.pickerBusy}
            attachmentError={accounts.attachmentError}
            attachmentNotice={accounts.attachmentNotice}
            confirmingAttachmentId={accounts.confirmingAttId}
            onDelete={accounts.deleteAccount}
          />
        ) : (
          <aside className="details-pane details-pane--empty" aria-label="Account details">
            <div className="empty">
              <p>
                <b>Nothing selected</b>
                Pick an account on the left, or add one.
              </p>
            </div>
          </aside>
        )}
      </div>

      <footer className="app-footer">
        <span>Type a name, pick a service, press Enter. Fields save when you click away.</span>
        <span className="right">
          <span>
            <kbd>Ctrl+Z</kbd> undo
          </span>
          <span className="sep">·</span>
          <span>
            <kbd>Ctrl+Y</kbd> redo
          </span>
          <span className="sep">·</span>
          <span>auto-locks after 5 min idle</span>
        </span>
      </footer>
    </main>
  );
}

export default App;
