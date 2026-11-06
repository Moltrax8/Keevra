import { afterEach, describe, expect, it, vi } from "vitest";
import { clearCopiedSecrets, copySecretWithAutoClear } from "./clipboard";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function stubClipboard(initial = "") {
  let value = initial;
  const writeText = vi.fn(async (text: string) => {
    value = text;
  });
  const readText = vi.fn(async () => value);
  vi.stubGlobal("navigator", { clipboard: { writeText, readText } });
  return { writeText, readText, current: () => value };
}

describe("clipboard", () => {
  it("clears a copied secret after the delay", async () => {
    vi.useFakeTimers();
    const clipboard = stubClipboard();
    await copySecretWithAutoClear("secret", 1000);
    expect(clipboard.current()).toBe("secret");
    await vi.advanceTimersByTimeAsync(1000);
    expect(clipboard.current()).toBe("");
  });

  it("does not overwrite content copied afterwards", async () => {
    vi.useFakeTimers();
    const clipboard = stubClipboard();
    await copySecretWithAutoClear("secret", 1000);
    await navigator.clipboard.writeText("newer");
    await vi.advanceTimersByTimeAsync(1000);
    expect(clipboard.current()).toBe("newer");
  });

  it("wipes pending secrets on lock", async () => {
    vi.useFakeTimers();
    const clipboard = stubClipboard();
    await copySecretWithAutoClear("secret", 60_000);
    await clearCopiedSecrets();
    expect(clipboard.current()).toBe("");
    vi.clearAllTimers();
  });
});
