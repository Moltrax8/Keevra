import { useEffect, useState } from "react";
import {
  appSettingsGet,
  appSettingsSetDefault,
  pickExportFile,
  pickImportFile,
  vaultCreate,
  vaultDeleteVault,
  vaultExportPackage,
  vaultForget,
  vaultGetDocument,
  vaultImportPackage,
  vaultList,
  vaultLock,
  vaultOpen,
  vaultRemember,
  vaultRename,
  vaultRestoreBackup,
  vaultStatus,
  type VaultEntry,
} from "../vaultApi";
import { APP_NAME } from "../brand";
import { UnsupportedVaultVersionError, type VaultGraph } from "../vaultDocument";

export type BackendState = "checking" | "demo" | "locked" | "unlocked";

export interface DraftFlushResult {
  /** At least one editor committed a draft to the document. */
  changed: boolean;
  /** An editor rejected its draft (e.g. validation), so locking must wait. */
  failed: boolean;
}

export interface VaultSessionOptions {
  dirty: boolean;
  persist: () => Promise<boolean>;
  /** Commits any focused editor drafts, then lets React apply them. */
  flushDrafts: () => Promise<DraftFlushResult>;
  applyVaultDocument: (stored: VaultGraph) => void;
  onLocked: () => void;
}

export interface VaultDeleteOutcome {
  error: string | null;
  notice: string | null;
}

export interface VaultSessionApi {
  backend: BackendState;
  vaultPath: string;
  setVaultPath: (path: string) => void;
  vaultName: string;
  vaults: VaultEntry[];
  defaultVaultPath: string | null;
  showSettings: boolean;
  setShowSettings: (open: boolean) => void;
  packageMessage: string | null;
  setPackageMessage: (message: string | null) => void;
  lockBusy: boolean;
  lockError: string | null;
  lockNotice: string | null;
  handleVaultOpen: (path: string, password: string) => Promise<boolean>;
  handleVaultCreate: (name: string, password: string, hint: string) => Promise<boolean>;
  handleVaultRemember: (name: string, path: string, hint: string) => Promise<boolean>;
  handleVaultDelete: (path: string) => Promise<VaultDeleteOutcome>;
  handleDefaultChange: (path: string | null) => Promise<void>;
  handleSettingsCreate: (name: string, password: string, hint: string) => Promise<string | null>;
  handleVaultForget: (path: string) => Promise<void>;
  handleVaultRename: (path: string, name: string) => Promise<string | null>;
  handleVaultRestore: (path: string, password: string) => Promise<void>;
  handleExportPackage: () => Promise<void>;
  handleImportPackage: () => Promise<void>;
  /** Returns false when unsaved changes could not be written. */
  handleVaultLock: () => Promise<boolean>;
  /** Flush and lock before closing the window; false keeps the window open. */
  handleVaultClose: () => Promise<boolean>;
}

export function useVaultSession({
  dirty,
  persist,
  flushDrafts,
  applyVaultDocument,
  onLocked,
}: VaultSessionOptions): VaultSessionApi {
  const [backend, setBackend] = useState<BackendState>("checking");
  const [vaultPath, setVaultPath] = useState("");
  const [vaultName, setVaultName] = useState("");
  const [vaults, setVaults] = useState<VaultEntry[]>([]);
  const [defaultVaultPath, setDefaultVaultPath] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [packageMessage, setPackageMessage] = useState<string | null>(null);
  const [lockBusy, setLockBusy] = useState(false);
  const [lockError, setLockError] = useState<string | null>(null);
  const [lockNotice, setLockNotice] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await vaultStatus();
        if (cancelled) return;
        const entries = await vaultList().catch((): VaultEntry[] => []);
        if (cancelled) return;
        setVaults(entries);
        const settings = await appSettingsGet().catch(() => null);
        if (cancelled) return;
        setDefaultVaultPath(settings?.defaultVaultPath ?? null);
        const entry = entries.find((item) => item.path === status.path);
        if (status.path) {
          setVaultPath(status.path);
          setVaultName(entry?.name ?? "");
        } else {
          setVaultPath(entries[0]?.path ?? "");
          setVaultName(entries[0]?.name ?? "");
        }
        if (!status.unlocked) {
          setBackend("locked");
          return;
        }
        // Rust still holds an unlocked session (renderer reload). Never show
        // the initial demo document over it: load the real document, or fail
        // closed and lock.
        try {
          applyVaultDocument(await vaultGetDocument());
          if (cancelled) return;
          setBackend("unlocked");
        } catch {
          await vaultLock().catch(() => {});
          if (cancelled) return;
          setLockError("The open vault could not be reloaded. Enter your password to continue.");
          setBackend("locked");
        }
      } catch {
        if (!cancelled) setBackend("demo");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function refreshVaults(): Promise<VaultEntry[]> {
    const entries = await vaultList().catch((): VaultEntry[] => []);
    setVaults(entries);
    return entries;
  }

  /**
   * Commits focused drafts first, then saves if anything actually changed.
   * Auto-lock, lock, export, import and vault switching all go through this so
   * an in-progress field edit can never be dropped by a state clear.
   */
  async function ensureSaved(): Promise<boolean> {
    const { changed, failed } = await flushDrafts();
    if (failed) return false;
    if (!dirty && !changed) return true;
    return persist();
  }

  /** True only when the backend authoritatively reports no open session. */
  async function backendLocked(): Promise<boolean> {
    const status = await vaultStatus().catch(() => null);
    return status !== null && !status.unlocked;
  }

  async function handleVaultOpen(path: string, password: string): Promise<boolean> {
    if (password === "") {
      setLockError("Enter a password.");
      return false;
    }
    setLockBusy(true);
    setLockError(null);
    setLockNotice(null);
    let sessionOpened = false;
    try {
      const graph = await vaultOpen(path, password);
      sessionOpened = true;
      // A document this build cannot parse must not leave an unlocked Rust
      // session behind while the UI shows the lock screen.
      applyVaultDocument(graph);
      setVaultPath(path);
      const entries = await refreshVaults();
      setVaultName(entries.find((item) => item.path === path)?.name ?? "");
      setBackend("unlocked");
      return true;
    } catch (error) {
      if (sessionOpened) {
        await vaultLock().catch(() => {});
      }
      setLockError(
        error instanceof UnsupportedVaultVersionError
          ? `This vault was created by a newer version of ${APP_NAME} (schema ${error.version}). Update the app to open it.`
          : sessionOpened
            ? "The vault opened but its contents could not be read. It was locked again."
            : "Could not open the vault (wrong password or corrupt file).",
      );
      return false;
    } finally {
      setLockBusy(false);
    }
  }

  async function handleVaultCreate(name: string, password: string, hint: string): Promise<boolean> {
    if (password === "") {
      setLockError("Enter a password.");
      return false;
    }
    setLockBusy(true);
    setLockError(null);
    setLockNotice(null);
    try {
      const created = await vaultCreate(name, password, hint === "" ? undefined : hint);
      applyVaultDocument(created.graph);
      setVaultPath(created.path);
      setVaultName(name);
      setVaults(await refreshVaults());
      setBackend("unlocked");
      return true;
    } catch (error) {
      const message = typeof error === "string" ? error : "";
      setLockError(
        message.includes("weak_password")
          ? "Use at least 12 characters for a new vault password."
          : "Could not create the vault.",
      );
      return false;
    } finally {
      setLockBusy(false);
    }
  }

  async function handleVaultRemember(name: string, path: string, hint: string): Promise<boolean> {
    try {
      setVaults(await vaultRemember(name, path, hint === "" ? undefined : hint));
      return true;
    } catch {
      return false;
    }
  }

  async function handleVaultDelete(path: string): Promise<VaultDeleteOutcome> {
    setLockBusy(true);
    try {
      const result = await vaultDeleteVault(path);
      const entries = await refreshVaults();
      if (vaultPath === path) setVaultPath(entries[0]?.path ?? "");
      const settings = await appSettingsGet().catch(() => null);
      if (settings) setDefaultVaultPath(settings.defaultVaultPath);
      return {
        error: null,
        notice: result.filesDeleted
          ? null
          : "Removed from the list. The vault file was left on disk because it is not managed by this app.",
      };
    } catch (error) {
      const message = typeof error === "string" ? error : "";
      if (message.includes("vault_unlocked")) {
        return { error: "Lock the vault before deleting it.", notice: null };
      }
      if (message.includes("not_a_vault")) {
        return { error: "That file is not a Keevra vault. Nothing was deleted.", notice: null };
      }
      if (message.includes("delete_failed")) {
        return {
          error: "The vault could not be fully deleted. Its listing was kept; check file permissions and try again.",
          notice: null,
        };
      }
      return { error: "Could not delete the vault.", notice: null };
    } finally {
      setLockBusy(false);
    }
  }

  async function handleDefaultChange(path: string | null) {
    try {
      const settings = await appSettingsSetDefault(path);
      setDefaultVaultPath(settings.defaultVaultPath);
    } catch {
      // Settings failures leave existing state untouched.
    }
  }

  async function handleSettingsCreate(name: string, password: string, hint: string): Promise<string | null> {
    if (!(await ensureSaved())) {
      return "Could not save the current vault. New vault was not created.";
    }
    setLockBusy(true);
    try {
      const created = await vaultCreate(name, password, hint === "" ? undefined : hint);
      applyVaultDocument(created.graph);
      setVaultPath(created.path);
      setVaultName(name);
      setVaults(await refreshVaults());
      setShowSettings(false);
      return null;
    } catch (error) {
      const message = typeof error === "string" ? error : "";
      return message.includes("weak_password")
        ? "Use at least 12 characters for a new vault password."
        : "Could not create the vault.";
    } finally {
      setLockBusy(false);
    }
  }

  async function handleVaultForget(path: string) {
    try {
      const entries = await vaultForget(path);
      setVaults(entries);
      if (vaultPath === path) {
        setVaultPath(entries[0]?.path ?? "");
      }
    } catch {
      // Listing failures leave existing state untouched.
    }
  }

  async function handleVaultRename(path: string, name: string): Promise<string | null> {
    if (name === "") return "Enter a vault name.";
    try {
      setVaults(await vaultRename(path, name));
      return null;
    } catch (error) {
      const message = typeof error === "string" ? error : "";
      if (message.includes("duplicate_vault_name")) return "You already have a vault with this name.";
      if (message.includes("invalid_vault_name")) return "Enter a vault name.";
      return "Could not rename the vault.";
    }
  }

  async function handleVaultRestore(path: string, password: string) {
    if (password === "") {
      setLockError("Enter the vault password to verify the backup.");
      return;
    }
    setLockBusy(true);
    setLockError(null);
    setLockNotice(null);
    try {
      await vaultRestoreBackup(path, password);
      setLockNotice(
        "Backup verified with your password and restored. The previous vault is kept as a .pre-restore copy. Open the vault again.",
      );
    } catch (error) {
      const message = typeof error === "string" ? error : "";
      if (message.includes("vault_unlocked")) {
        setLockError("Lock the vault before restoring a backup.");
      } else if (message.includes("wrong_password_or_corrupt")) {
        setLockError("The backup is corrupt or the password does not match it. Nothing was changed.");
      } else if (message.includes("vault_not_found")) {
        setLockError("No backup found for that vault.");
      } else {
        setLockError("Could not restore the backup. The vault was not changed.");
      }
    } finally {
      setLockBusy(false);
    }
  }

  async function handleExportPackage() {
    setPackageMessage(null);
    if (!(await ensureSaved())) {
      setPackageMessage("Could not save the vault before export. Nothing was exported.");
      return;
    }
    let dest: string | null = null;
    try {
      dest = await pickExportFile(`${vaultName === "" ? "vault" : vaultName}.vtpkg.json`);
    } catch {
      setPackageMessage("File picker failed.");
      return;
    }
    if (!dest) return;
    try {
      const count = await vaultExportPackage(dest);
      setPackageMessage(
        `Exported encrypted package with ${count} attachment(s). Attachment integrity was verified; no plaintext left the app.`,
      );
    } catch {
      setPackageMessage("Package export failed.");
    }
  }

  async function handleImportPackage() {
    setPackageMessage(null);
    let source: string | null = null;
    try {
      source = await pickImportFile();
    } catch {
      setPackageMessage("File picker failed.");
      return;
    }
    if (!source) return;
    const stem = source.split(/[/\\]/).pop()?.replace(/\.vtpkg\.json$/i, "").trim() ?? "";
    const name = stem === "" ? "Imported vault" : stem;
    if (!(await ensureSaved())) {
      setPackageMessage("Could not save the current vault before import. Nothing was imported.");
      return;
    }
    try {
      const entries = await vaultImportPackage(source, name);
      setVaults(entries);
      setPackageMessage(`Imported “${name}”. Open it from the lock screen with its original password.`);
    } catch {
      setPackageMessage("Package import failed (bad file or name).");
    }
  }

  async function handleVaultLock(): Promise<boolean> {
    if (!(await ensureSaved())) {
      // A backend idle timeout may have closed the session while the renderer
      // was suspended. Never show "unlocked" when the key is already gone.
      if (await backendLocked()) {
        setLockError(null);
        onLocked();
        setBackend("locked");
        return true;
      }
      // Never drop decrypted state while unsaved changes could not be written.
      setLockError("Could not save your changes. The vault stays unlocked so nothing is lost.");
      return false;
    }
    try {
      await vaultLock();
    } catch {
      // Do not clear the UI if Rust still holds the key: that would fake a
      // locked state while decrypted data stays in memory.
      setLockError("Could not lock the vault. Restart the app to clear the session.");
      return false;
    }
    setLockError(null);
    onLocked();
    setBackend("locked");
    return true;
  }

  async function handleVaultClose(): Promise<boolean> {
    // Always flush: the close handler first commits any in-progress drafts.
    if (!(await ensureSaved())) {
      if (await backendLocked()) {
        setLockError(null);
        onLocked();
        setBackend("locked");
        return true;
      }
      setLockError("Could not save your changes. The window stays open so nothing is lost.");
      return false;
    }
    try {
      await vaultLock();
    } catch {
      // Best effort; the window is closing either way.
    }
    setLockError(null);
    onLocked();
    setBackend("locked");
    return true;
  }

  return {
    backend,
    vaultPath,
    setVaultPath,
    vaultName,
    vaults,
    defaultVaultPath,
    showSettings,
    setShowSettings,
    packageMessage,
    setPackageMessage,
    lockBusy,
    lockError,
    lockNotice,
    handleVaultOpen,
    handleVaultCreate,
    handleVaultRemember,
    handleVaultDelete,
    handleDefaultChange,
    handleSettingsCreate,
    handleVaultForget,
    handleVaultRename,
    handleVaultRestore,
    handleExportPackage,
    handleImportPackage,
    handleVaultLock,
    handleVaultClose,
  };
}
