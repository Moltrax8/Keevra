/** Settings dialog: default vault plus in-session vault creation. */
import { useState } from "react";
import { Settings } from "lucide-react";
import type { VaultEntry } from "../vaultApi";
import { APP_NAME } from "../brand";
import { parseThemePreference, THEME_OPTIONS, type ThemePreference } from "../theme";
import type { UpdateCheck } from "./UpdateBanner";

export function SettingsModal({
  vaults,
  defaultPath,
  currentPath,
  onClose,
  onDefaultChange,
  onCreateVault,
  onExportPackage,
  onImportPackage,
  packageMessage,
  themePreference,
  onThemeChange,
  updateCheck,
  onCheckUpdates,
  onDownloadUpdate,
}: {
  vaults: VaultEntry[];
  defaultPath: string | null;
  currentPath: string;
  onClose: () => void;
  onDefaultChange: (path: string | null) => void;
  onCreateVault: (name: string, password: string, hint: string) => Promise<string | null>;
  onExportPackage: () => void;
  onImportPackage: () => void;
  packageMessage: string | null;
  themePreference: ThemePreference;
  onThemeChange: (preference: ThemePreference) => void;
  updateCheck: UpdateCheck;
  onCheckUpdates: () => void;
  onDownloadUpdate: () => void;
}) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [hint, setHint] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function create() {
    if (name.trim() === "") {
      setError("Name your vault.");
      return;
    }
    if (password.length < 12) {
      setError("Use at least 12 characters for a new vault password.");
      return;
    }
    setError(null);
    const message = await onCreateVault(name.trim(), password, hint.trim());
    if (message === null) {
      onClose();
    } else {
      setError(message);
    }
  }

  return (
    <div className="modal-overlay" role="dialog" aria-label="Settings" onMouseDown={(e) => {
      if (e.target === e.currentTarget) onClose();
    }}>
      <section className="create-form lock-screen__card modal-card" aria-label="Settings">
        <h2>
          <Settings style={{ width: 18, height: 18 }} /> Settings
        </h2>
        <p className="lock-sub">Defaults and vault management for this machine.</p>
        <h3 className="stack-heading">Appearance</h3>
        <select
          value={themePreference}
          onChange={(event) => onThemeChange(parseThemePreference(event.target.value))}
          aria-label="Theme"
        >
          {THEME_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
        <p className="hint">Dark mode keeps the same warm paper look, lit from one side.</p>
        <h3 className="stack-heading">Default vault</h3>
        <select
          value={defaultPath ?? ""}
          onChange={(event) => onDefaultChange(event.target.value === "" ? null : event.target.value)}
          aria-label="Default vault"
        >
          <option value="">Ask every time</option>
          {vaults.map((vault) => (
            <option key={vault.path} value={vault.path}>{vault.name}</option>
          ))}
        </select>
        <p className="hint">Unlocking starts here; “Change vault” still lists everything.</p>
        <h3 className="stack-heading">Currently open</h3>
        <p className="hint">{vaults.find((vault) => vault.path === currentPath)?.name ?? "Demo mode"}</p>
        <h3 className="stack-heading">New vault</h3>
        <input
          type="text"
          placeholder="Vault name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          aria-label="New vault name"
        />
        <input
          type="password"
          placeholder="Password (12+ characters)"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-label="New vault password"
        />
        <input
          type="text"
          placeholder="Password hint (optional)"
          value={hint}
          onChange={(event) => setHint(event.target.value)}
          aria-label="Password hint"
        />
        {error ? <p className="create-form__error">{error}</p> : null}
        <div className="btn-row">
          <button type="button" className="create-form__submit" onClick={() => void create()}>
            Create and open
          </button>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
        <h3 className="stack-heading">Portable package</h3>
        <p className="hint">
          One encrypted file with the vault plus all encrypted attachments. Nothing is decrypted during
          export or import.
        </p>
        <div className="btn-row">
          <button type="button" className="btn-secondary" onClick={onExportPackage}>
            Export package…
          </button>
          <button type="button" className="btn-secondary" onClick={onImportPackage}>
            Import package…
          </button>
        </div>
        {packageMessage ? <p className="hint">{packageMessage}</p> : null}
        <h3 className="stack-heading">Updates</h3>
        <p className="hint">
          Notify-only. {APP_NAME} checks GitHub releases, never downloads silently. Installer SHA256 is
          verified before save; you run the installer yourself.
        </p>
        <div className="btn-row">
          <button type="button" className="btn-secondary" onClick={onCheckUpdates}>
            {updateCheck.phase === "checking" ? "Checking…" : "Check for updates"}
          </button>
          {updateCheck.phase === "available" ? (
            <button type="button" className="create-form__submit" onClick={onDownloadUpdate}>
              Download…
            </button>
          ) : null}
        </div>
        {updateCheck.phase === "available" && updateCheck.release ? (
          <p className="hint">
            {updateCheck.release.tag_name} available (you have {updateCheck.current}).
          </p>
        ) : null}
        {updateCheck.phase === "up-to-date" && updateCheck.message ? (
          <p className="hint">{updateCheck.message}</p>
        ) : null}
        {updateCheck.phase === "error" && updateCheck.message ? (
          <p className="create-form__error">{updateCheck.message}</p>
        ) : null}
      </section>
    </div>
  );
}
