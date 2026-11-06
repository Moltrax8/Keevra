/** Lock screen: hero pitch plus unlock / create / locate / delete flows. */
import { useEffect, useState } from "react";
import {
  Check,
  Clock,
  Database,
  Eye,
  EyeOff,
  FileUp,
  Fingerprint,
  Lock,
  Plus,
  Sparkles,
} from "lucide-react";
import type { VaultEntry } from "../vaultApi";
import type { VaultDeleteOutcome } from "../hooks/useVaultSession";
import { APP_NAME } from "../brand";
import { shouldShowHint, strengthOf } from "../display";
import { Logo } from "./bits";

export function LockScreen({
  vaults,
  defaultPath,
  selectedPath,
  onSelectPath,
  busy,
  error,
  notice,
  onCreate,
  onOpen,
  onRestore,
  onForget,
  onRemember,
  onRename,
  onPickFile,
  onDeleteVault,
}: {
  vaults: VaultEntry[];
  defaultPath: string | null;
  selectedPath: string;
  onSelectPath: (path: string) => void;
  busy: boolean;
  error: string | null;
  notice: string | null;
  onCreate: (name: string, password: string, hint: string) => Promise<boolean>;
  onOpen: (path: string, password: string) => Promise<boolean>;
  onRestore: (path: string, password: string) => void;
  onForget: (path: string) => void;
  onRemember: (name: string, path: string, hint: string) => Promise<boolean>;
  onRename: (path: string, name: string) => Promise<string | null>;
  onPickFile: () => Promise<string | null>;
  onDeleteVault: (path: string) => Promise<VaultDeleteOutcome>;
}) {
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [mode, setMode] = useState<"default" | "open" | "create" | "locate" | "forgot">("open");
  const [leftDefault, setLeftDefault] = useState(false);
  const [newName, setNewName] = useState("");
  const [newHint, setNewHint] = useState("");
  const [locatePath, setLocatePath] = useState("");
  const [locateName, setLocateName] = useState("");
  const [locateHint, setLocateHint] = useState("");
  const [confirmingForget, setConfirmingForget] = useState<string | null>(null);
  const [renamingPath, setRenamingPath] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState("");
  const [forgotConfirm, setForgotConfirm] = useState("");
  const [failuresByPath, setFailuresByPath] = useState<Record<string, number>>({});
  const [lockoutSeconds, setLockoutSeconds] = useState(0);
  const [localError, setLocalError] = useState<string | null>(null);
  const [localNotice, setLocalNotice] = useState<string | null>(null);

  const defaultEntry = vaults.find((vault) => vault.path === defaultPath) ?? null;
  // Derived, never blank: default mode requires its entry; anything else
  // falls back to the full list so async refresh races can't strand an
  // empty card.
  const resolvedMode = mode === "default" && !defaultEntry ? "open" : mode;
  useEffect(() => {
    if (defaultEntry && !leftDefault && mode === "open") {
      setMode("default");
      onSelectPath(defaultEntry.path);
    }
  }, [defaultEntry, leftDefault, mode, onSelectPath]);

  function leaveDefault() {
    setLeftDefault(true);
    setMode("open");
    setLocalError(null);
  }

  // Throttle: each failed unlock adds a short delay (calm-down, not a
  // forensic defense — offline guessing can't be throttled; the KDF is).
  useEffect(() => {
    if (lockoutSeconds <= 0) return;
    const timer = setTimeout(() => setLockoutSeconds((current) => current - 1), 1000);
    return () => clearTimeout(timer);
  }, [lockoutSeconds]);

  async function attempt(
    kind: "open" | "create",
    path: string,
    attemptPassword: string,
    name: string,
    hint: string,
  ): Promise<boolean> {
    if (lockoutSeconds > 0 || busy) return false;
    if (attemptPassword === "") {
      setLocalError("Enter a password.");
      return false;
    }
    if (kind === "create" && attemptPassword.length < 12) {
      setLocalError("Use at least 12 characters for a new vault password.");
      return false;
    }
    setLocalError(null);
    const failures = failuresByPath[path] ?? 0;
    const delayAfterFailure = Math.min(failures + 1, 5);
    const ok = kind === "open" ? await onOpen(path, attemptPassword) : await onCreate(name, attemptPassword, hint);
    if (!ok) {
      // Parent reports the error text; the delay here only slows repeated
      // manual guessing, it cannot stop offline attacks (see THREAT_MODEL).
      // Hints stay hidden until HINT_FAILURE_THRESHOLD (see display.ts).
      if (kind === "open") {
        setFailuresByPath((current) => ({ ...current, [path]: failures + 1 }));
      }
      setLockoutSeconds(delayAfterFailure);
    } else {
      if (kind === "open") {
        setFailuresByPath((current) => {
          if (!(path in current)) return current;
          const next = { ...current };
          delete next[path];
          return next;
        });
      }
      setPassword("");
    }
    return ok;
  }

  async function attemptOpen() {
    if (selectedPath === "") {
      setLocalError("Select a vault.");
      return;
    }
    await attempt("open", selectedPath, password, "", "");
  }

  async function attemptCreate() {
    if (newName.trim() === "") {
      setLocalError("Name your vault.");
      return;
    }
    await attempt("create", "", password, newName.trim(), newHint.trim());
  }

  async function pickLocateFile() {
    const picked = await onPickFile().catch(() => null);
    if (!picked) return;
    setLocatePath(picked);
    const stem = picked.split(/[/\\]/).pop() ?? "";
    setLocateName(stem.replace(/\.vault$/, ""));
    setMode("locate");
    setLocalError(null);
  }

  async function attemptLocate() {
    if (locatePath.trim() === "") {
      setLocalError("Enter a vault file path.");
      return;
    }
    const opened = await attempt("open", locatePath.trim(), password, "", "");
    if (opened && locateName.trim() !== "") {
      await onRemember(locateName.trim(), locatePath.trim(), locateHint.trim());
    }
  }

  async function attemptForgot() {
    const entry = vaults.find((vault) => vault.path === selectedPath);
    if (!entry || forgotConfirm.trim() !== entry.name) {
      setLocalError(`Type "${entry?.name ?? "…"}" to confirm.`);
      return;
    }
    setLocalError(null);
    const outcome = await onDeleteVault(selectedPath);
    if (outcome.error === null) {
      setForgotConfirm("");
      setPassword("");
      setMode(defaultEntry ? "default" : "open");
      setLocalNotice(outcome.notice);
    } else {
      setLocalError(outcome.error);
    }
  }

  function passwordField(autoAction: () => void, showStrength = false) {
    const strength = strengthOf(password);
    return (
      <div>
        <div className="password-wrap">
          <input
            type={showPassword ? "text" : "password"}
            placeholder="Password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            aria-label="Vault password"
            onKeyDown={(event) => {
              if (event.key === "Enter") void autoAction();
            }}
          />
          <button
            type="button"
            className="btn-secondary"
            onClick={() => setShowPassword((current) => !current)}
            aria-label={showPassword ? "Hide password" : "Show password"}
          >
            {showPassword ? <EyeOff /> : <Eye />}
            {showPassword ? "Hide" : "Show"}
          </button>
        </div>
        {showStrength && password !== "" ? (
          <div className="strength" aria-hidden="true">
            {[1, 2, 3, 4].map((level) => (
              <i key={level} className={strength >= level ? `on-${strength}` : undefined} />
            ))}
          </div>
        ) : null}
      </div>
    );
  }

  function statusLines() {
    return (
      <>
        {localError ? <p className="create-form__error">{localError}</p> : null}
        {localNotice ? <p className="notice-ok">{localNotice}</p> : null}
        {error ? <p className="create-form__error">{error}</p> : null}
        {notice ? <p className="notice-ok">{notice}</p> : null}
        {lockoutSeconds > 0 ? (
          <p className="hint">
            <Clock style={{ width: 12, height: 12, verticalAlign: -1 }} /> Try again in {lockoutSeconds}s.
          </p>
        ) : null}
      </>
    );
  }

  const selectedEntry = vaults.find((vault) => vault.path === selectedPath) ?? null;
  const modeTitle =
    resolvedMode === "create"
      ? "Create a vault"
      : resolvedMode === "locate"
        ? "Locate a vault file"
        : resolvedMode === "forgot"
          ? "Delete a vault"
          : defaultEntry && resolvedMode === "default"
            ? `Unlock ${defaultEntry.name}`
            : "Welcome back";

  return (
    <main className="app lock-screen-page">
      <div className="lock-screen">
        <section className="hero" aria-label={`About ${APP_NAME}`}>
          <span className="hero-badge">
            <Lock /> Local · encrypted · yours
          </span>
          <h1>
            Every account,
            <br />
            <span className="grad">one quiet place.</span>
          </h1>
          <p>
            {APP_NAME} is a personal directory of the services you use — logins, notes and recovery paths,
            sealed on this machine only.
          </p>
          <ul className="hero-feats">
            <li>
              <span className="tick">
                <Check />
              </span>
              <span>
                Grouped by service
                <small>See every account you have for a game, shop or mailbox</small>
              </span>
            </li>
            <li>
              <span className="tick">
                <Check />
              </span>
              <span>
                Nothing to configure
                <small>Add a name, add details with one click, they save themselves</small>
              </span>
            </li>
            <li>
              <span className="tick">
                <Check />
              </span>
              <span>
                Locks itself down
                <small>Auto-lock in 5 min idle · masked secrets · zeroized keys</small>
              </span>
            </li>
          </ul>
        </section>
        <section className="create-form lock-screen__card" aria-label="Unlock vault">
          <h2>
            <Logo size={34} />
            {APP_NAME}
          </h2>
          <p className="lock-sub">{modeTitle} — your master key never leaves this device.</p>
          {resolvedMode === "default" && defaultEntry ? (
            <>
              {defaultEntry.hint && shouldShowHint(failuresByPath[defaultEntry.path] ?? 0) ? (
                <p className="hint">Hint: {defaultEntry.hint}</p>
              ) : null}
              {passwordField(() => void attemptOpen())}
              {statusLines()}
              <div className="btn-row">
                <button
                  type="button"
                  className="create-form__submit"
                  disabled={busy || lockoutSeconds > 0}
                  onClick={() => void attemptOpen()}
                >
                  <Lock /> Open
                </button>
                <button type="button" className="btn-secondary" onClick={leaveDefault}>
                  Change vault
                </button>
              </div>
              <div className="lock-links">
                <button
                  type="button"
                  className="btn-secondary btn-ghost"
                  onClick={() => {
                    setMode("forgot");
                    setForgotConfirm("");
                    setLocalError(null);
                  }}
                >
                  Forgot password?
                </button>
              </div>
            </>
          ) : null}
          {resolvedMode === "open" ? (
            <>
              {vaults.length > 0 ? (
                <ul className="vault-list">
                  {vaults.map((vault) => {
                    const renaming = renamingPath === vault.path;
                    const activeVault = selectedPath === vault.path;
                    return (
                      <li key={vault.path} className={`vault-row${activeVault ? " vault-row--active" : ""}`}>
                        <div className="vault-row__top">
                          <button
                            type="button"
                            className="vault-row__btn"
                            aria-pressed={activeVault}
                            onClick={() => onSelectPath(vault.path)}
                          >
                            <span className="service-avatar" style={{ width: 30, height: 30 }}>
                              <Database style={{ width: 15, height: 15 }} />
                            </span>
                            <span style={{ minWidth: 0 }}>
                              {vault.name}
                              {vault.hint && shouldShowHint(failuresByPath[vault.path] ?? 0) ? (
                                <small>Hint: {vault.hint}</small>
                              ) : (
                                <small>Encrypted vault</small>
                              )}
                            </span>
                          </button>
                        </div>
                        {renaming ? (
                          <div className="field-row__value" style={{ marginTop: 8 }}>
                            <input
                              type="text"
                              value={renameDraft}
                              onChange={(event) => setRenameDraft(event.target.value)}
                              aria-label="New vault name"
                            />
                            <button
                              type="button"
                              className="create-form__submit field-row__reveal"
                              onClick={() => void (async () => {
                                const message = await onRename(vault.path, renameDraft.trim());
                                if (message === null) {
                                  setRenamingPath(null);
                                  setRenameDraft("");
                                } else {
                                  setLocalError(message);
                                }
                              })()}
                            >
                              Save
                            </button>
                          </div>
                        ) : null}
                        <div className="vault-row__mini" style={{ marginTop: 6 }}>
                          <button
                            type="button"
                            className="mini-btn"
                            onClick={() => {
                              setRenamingPath(renaming ? null : vault.path);
                              setRenameDraft(vault.name);
                              setLocalError(null);
                            }}
                          >
                            {renaming ? "Cancel" : "Rename"}
                          </button>
                          <button
                            type="button"
                            className="mini-btn"
                            onClick={() =>
                              setConfirmingForget((current) => (current === vault.path ? null : vault.path))
                            }
                          >
                            {confirmingForget === vault.path ? "Keep it" : "Forget"}
                          </button>
                          {confirmingForget === vault.path ? (
                            <button
                              type="button"
                              className="mini-btn"
                              style={{ color: "#fda4af" }}
                              onClick={() => {
                                setConfirmingForget(null);
                                onForget(vault.path);
                              }}
                            >
                              Remove listing
                            </button>
                          ) : null}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <div className="empty">
                  <Database />
                  <p>
                    <b>No vaults yet</b>
                    Create your first encrypted vault below.
                  </p>
                </div>
              )}
              {passwordField(() => void attemptOpen())}
              {statusLines()}
              <div className="btn-row">
                <button
                  type="button"
                  className="create-form__submit"
                  disabled={busy || lockoutSeconds > 0 || selectedPath === ""}
                  onClick={() => void attemptOpen()}
                >
                  <Lock /> Open
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={busy || selectedPath === ""}
                  onClick={() => onRestore(selectedPath, password)}
                >
                  Restore backup
                </button>
              </div>
              <div className="btn-row">
                <button type="button" className="btn-secondary" onClick={() => setMode("create")}>
                  <Plus /> New vault
                </button>
                <button type="button" className="btn-secondary" onClick={() => setMode("locate")}>
                  <FileUp /> Locate file
                </button>
              </div>
              <div className="lock-links">
                <button
                  type="button"
                  className="btn-secondary btn-ghost"
                  onClick={() => {
                    setMode("forgot");
                    setForgotConfirm("");
                    setLocalError(null);
                  }}
                >
                  Forgot password?
                </button>
              </div>
            </>
          ) : null}
          {resolvedMode === "create" ? (
            <>
              <input
                type="text"
                placeholder="Vault name (e.g. Personal)"
                value={newName}
                onChange={(event) => setNewName(event.target.value)}
                aria-label="New vault name"
              />
              {passwordField(() => void attemptCreate(), true)}
              <input
                type="text"
                placeholder="Password hint (optional, shown on login)"
                value={newHint}
                onChange={(event) => setNewHint(event.target.value)}
                aria-label="Password hint"
              />
              <p className="hint">The hint is visible to anyone using this computer. 12+ characters required.</p>
              {statusLines()}
              <div className="btn-row">
                <button
                  type="button"
                  className="create-form__submit"
                  disabled={busy || lockoutSeconds > 0}
                  onClick={() => void attemptCreate()}
                >
                  <Sparkles /> Create vault
                </button>
                <button type="button" className="btn-secondary" onClick={() => setMode("open")}>
                  Back
                </button>
              </div>
              <p className="hint">
                The file gets a random name; only you see “{newName.trim() === "" ? "…" : newName.trim()}”.
              </p>
            </>
          ) : null}
          {resolvedMode === "locate" ? (
            <>
              <input
                type="text"
                placeholder="Vault file path"
                value={locatePath}
                onChange={(event) => setLocatePath(event.target.value)}
                aria-label="Vault file path"
              />
              <div className="btn-row">
                <button type="button" className="btn-secondary" onClick={() => void pickLocateFile()}>
                  <FileUp /> Choose file…
                </button>
              </div>
              <input
                type="text"
                placeholder="Display name (optional)"
                value={locateName}
                onChange={(event) => setLocateName(event.target.value)}
                aria-label="Display name"
              />
              <input
                type="text"
                placeholder="Password hint (optional)"
                value={locateHint}
                onChange={(event) => setLocateHint(event.target.value)}
                aria-label="Password hint"
              />
              {passwordField(() => void attemptLocate())}
              {statusLines()}
              <div className="btn-row">
                <button
                  type="button"
                  className="create-form__submit"
                  disabled={busy || lockoutSeconds > 0}
                  onClick={() => void attemptLocate()}
                >
                  Open and remember
                </button>
                <button type="button" className="btn-secondary" onClick={() => setMode("open")}>
                  Back
                </button>
              </div>
            </>
          ) : null}
          {resolvedMode === "forgot" ? (
            <>
              <p className="hint">
                A forgotten password cannot be recovered — encryption has no backdoor. Deleting “
                {selectedEntry?.name ?? "this vault"}” erases its file, backup, attachments, and listing permanently.
                Type the vault name to confirm.
              </p>
              <input
                type="text"
                placeholder="Vault name to confirm"
                value={forgotConfirm}
                onChange={(event) => setForgotConfirm(event.target.value)}
                aria-label="Confirm vault name"
              />
              {statusLines()}
              <div className="btn-row">
                <button
                  type="button"
                  className="btn-danger-strong"
                  disabled={busy || selectedPath === ""}
                  onClick={() => void attemptForgot()}
                >
                  Delete vault forever
                </button>
                <button type="button" className="btn-secondary" onClick={() => setMode("open")}>
                  Back
                </button>
              </div>
            </>
          ) : null}
          <p className="lock-foot">
            <Fingerprint /> Argon2id + XChaCha20-Poly1305 · keys zeroized after use
          </p>
        </section>
      </div>
    </main>
  );
}
