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

export interface VaultSessionOptions {
  dirty: boolean;
  persist: () => Promise<boolean>;
  applyVaultDocument: (stored: VaultGraph) => void;
  onLocked: () => void;
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
  handleVaultDelete: (path: string) => Promise<string | null>;
  handleDefaultChange: (path: string | null) => Promise<void>;
  handleSettingsCreate: (name: string, password: string, hint: string) => Promise<string | null>;
  handleVaultForget: (path: string) => Promise<void>;
  handleVaultRename: (path: string, name: string) => Promise<string | null>;
  handleVaultRestore: (path: string) => Promise<void>;
  handleExportPackage: () => Promise<void>;
  handleImportPackage: () => Promise<void>;
  handleVaultLock: () => Promise<void>;
  /** Flush and lock before closing the window; false keeps the window open. */
  handleVaultClose: () => Promise<boolean>;
}

export function useVaultSession({
  dirty,
  persist,
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
        setBackend(status.unlocked ? "unlocked" : "locked");
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

  async function handleVaultOpen(path: string, password: string): Promise<boolean> {
    if (password === "") {
      setLockError("Enter a password.");
      return false;
    }
    setLockBusy(true);
    setLockError(null);
    setLockNotice(null);
    try {
      applyVaultDocument(await vaultOpen(path, password));
      setVaultPath(path);
      const entries = await refreshVaults();
      setVaultName(entries.find((item) => item.path === path)?.name ?? "");
      setBackend("unlocked");
      return true;
    } catch (error) {
      setLockError(
        error instanceof UnsupportedVaultVersionError
          ? `This vault was created by a newer version of ${APP_NAME} (schema ${error.version}). Update the app to open it.`
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

  async function handleVaultDelete(path: string): Promise<string | null> {
    setLockBusy(true);
    try {
      await vaultDeleteVault(path);
      const entries = await refreshVaults();
      if (vaultPath === path) setVaultPath(entries[0]?.path ?? "");
      const settings = await appSettingsGet().catch(() => null);
      if (settings) setDefaultVaultPath(settings.defaultVaultPath);
      return null;
    } catch {
      return "Could not delete the vault file.";
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
    if (dirty && !(await persist())) {
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

  async function handleVaultRestore(path: string) {
    setLockBusy(true);
    setLockError(null);
    setLockNotice(null);
    try {
      await vaultRestoreBackup(path);
      setLockNotice("Backup restored. Open the vault with your password.");
    } catch {
      setLockError("No backup found for that path.");
    } finally {
      setLockBusy(false);
    }
  }

  async function handleExportPackage() {
    setPackageMessage(null);
    if (dirty && !(await persist())) {
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
      setPackageMessage(`Exported encrypted package with ${count} attachment(s). Nothing was decrypted.`);
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
    if (dirty && !(await persist())) {
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

  async function handleVaultLock() {
    if (dirty && !(await persist())) {
      // Never drop decrypted state while unsaved changes could not be written.
      setLockError("Could not save your changes. The vault stays unlocked so nothing is lost.");
      return;
    }
    try {
      await vaultLock();
    } catch {
      // Session state is best-effort here; always clear the UI below.
    }
    setLockError(null);
    onLocked();
    setBackend("locked");
  }

  async function handleVaultClose(): Promise<boolean> {
    // Always flush: the close handler first commits any in-progress drafts.
    if (!(await persist())) {
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
