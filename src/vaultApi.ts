import { invoke } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import type { AttachmentMeta } from "./domain";
import type { VaultGraph } from "./vaultDocument";

export type { VaultGraph };

export interface VaultStatus {
  unlocked: boolean;
  path: string | null;
}

export async function vaultStatus(): Promise<VaultStatus> {
  return invoke<VaultStatus>("vault_status");
}

export interface VaultEntry {
  name: string;
  path: string;
  hint: string | null;
  modifiedMs: number | null;
  sizeBytes: number | null;
}

export interface CreatedVault {
  graph: VaultGraph;
  path: string;
}

export interface AppSettings {
  defaultVaultPath: string | null;
}

export async function vaultList(): Promise<VaultEntry[]> {
  return invoke<VaultEntry[]>("vault_list");
}

/** Reports genuine user activity to the backend inactivity backstop (K-14). */
export async function vaultTouch(): Promise<void> {
  return invoke<void>("vault_touch");
}

export async function vaultCreate(name: string, password: string, hint?: string): Promise<CreatedVault> {
  return invoke<CreatedVault>("vault_create", { name, password, hint: hint ?? null });
}

export async function vaultRemember(name: string, path: string, hint?: string): Promise<VaultEntry[]> {
  return invoke<VaultEntry[]>("vault_remember", { name, path, hint: hint ?? null });
}

export async function vaultForget(path: string): Promise<VaultEntry[]> {
  return invoke<VaultEntry[]>("vault_forget", { path });
}

export async function vaultRename(path: string, name: string): Promise<VaultEntry[]> {
  return invoke<VaultEntry[]>("vault_rename", { path, name });
}

export async function appSettingsGet(): Promise<AppSettings> {
  return invoke<AppSettings>("app_settings_get");
}

export async function appSettingsSetDefault(path: string | null): Promise<AppSettings> {
  return invoke<AppSettings>("app_settings_set_default", { path });
}

export async function vaultDeleteVault(path: string): Promise<VaultDeleteResult> {
  return invoke<VaultDeleteResult>("vault_delete_vault", { path });
}

export interface VaultDeleteResult {
  /** True only when the file, backup and blobs were actually removed. */
  filesDeleted: boolean;
  listingRemoved: boolean;
}

export async function vaultOpen(path: string, password: string): Promise<VaultGraph> {
  return invoke<VaultGraph>("vault_open", { path, password });
}

/** Document of the session that is already unlocked in Rust (reload recovery). */
export async function vaultGetDocument(): Promise<VaultGraph> {
  return invoke<VaultGraph>("vault_get_document");
}

export async function vaultSave(graph: VaultGraph, retainAttachmentIds: string[] = []): Promise<void> {
  return invoke<void>("vault_save", { graph, retainAttachmentIds });
}

export async function vaultLock(): Promise<void> {
  return invoke<void>("vault_lock");
}

export async function vaultRestoreBackup(path: string, password: string): Promise<void> {
  return invoke<void>("vault_restore_backup", { path, password });
}

export async function attachmentImport(
  attachmentId: string,
  nodeId: string,
  sourcePath: string,
): Promise<AttachmentMeta> {
  return invoke<AttachmentMeta>("attachment_import", {
    attachmentId,
    nodeId,
    sourcePath,
  });
}

export async function attachmentExport(
  attachmentId: string,
  expectedSha256: string,
  destPath: string,
): Promise<number> {
  return invoke<number>("attachment_export", { attachmentId, expectedSha256, destPath });
}

export interface AttachmentPreview {
  bytesB64: string;
  sha256Hex: string;
  sizeBytes: number;
}

/** Decrypts a blob in memory for preview. Never writes to disk. */
export async function attachmentRead(
  attachmentId: string,
  expectedSha256: string,
): Promise<AttachmentPreview> {
  return invoke<AttachmentPreview>("attachment_read", { attachmentId, expectedSha256 });
}

export async function vaultExportPackage(destPath: string): Promise<number> {
  return invoke<number>("vault_export_package", { destPath });
}

export async function vaultImportPackage(sourcePath: string, name: string) {
  return invoke<VaultEntry[]>("vault_import_package", { sourcePath, name });
}

export interface VerifiedManifest {
  version: string;
  assetNames: string[];
}

export async function updateVerifyManifest(manifestJson: string, manifestSig: string): Promise<VerifiedManifest> {
  return invoke<VerifiedManifest>("update_verify_manifest", { manifestJson, manifestSig });
}

export interface ManifestDownload {
  bytes: number;
  version: string;
}

/** Manifest-gated download: signature + newer-version + manifest SHA enforced in Rust. */
export async function updateDownloadManifestAsset(
  installerUrl: string,
  manifestJson: string,
  manifestSig: string,
  currentVersion: string,
  destPath: string,
): Promise<ManifestDownload> {
  return invoke<ManifestDownload>("update_download_manifest_asset", {
    installerUrl,
    manifestJson,
    manifestSig,
    currentVersion,
    destPath,
  });
}

/** Native file picker for imports. Returns null when cancelled. */
export async function pickImportFile(): Promise<string | null> {
  return openDialog({ multiple: false, directory: false });
}

/** Native save picker for exports. Returns null when cancelled. */
export async function pickExportFile(defaultName: string): Promise<string | null> {
  return saveDialog({ defaultPath: defaultName });
}
