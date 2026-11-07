// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { GitHubRelease } from "../updates";
import { UpdateDialog, type UpdateCheck } from "./UpdateDialog";

function release(): GitHubRelease {
  return {
    tag_name: "v0.2.1",
    html_url: "https://github.com/Moltrax8/Keevra/releases/tag/v0.2.1",
    body: "### Fixed\n\n- Update dialog shows the release notes before downloading.",
    assets: [],
  };
}

function available(): UpdateCheck {
  return { phase: "available", current: "0.2.0", release: release(), message: null };
}

describe("UpdateDialog", () => {
  afterEach(cleanup);

  it("shows the release notes and both decisions", () => {
    render(
      <UpdateDialog
        check={available()}
        busy={false}
        onDownload={vi.fn()}
        onLater={vi.fn()}
        onCopyLink={vi.fn()}
      />,
    );

    expect(screen.getByRole("dialog", { name: "Update available" })).toBeTruthy();
    expect(screen.getByText(/v0\.2\.1 is available/)).toBeTruthy();
    expect(screen.getByText(/You have 0\.2\.0/)).toBeTruthy();
    expect(screen.getByLabelText("Release notes").textContent).toContain(
      "Update dialog shows the release notes",
    );
    expect(screen.getByRole("button", { name: /Download update/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Not now" })).toBeTruthy();
  });

  it("wires download, later and copy actions", () => {
    const onDownload = vi.fn();
    const onLater = vi.fn();
    const onCopyLink = vi.fn();
    render(
      <UpdateDialog
        check={available()}
        busy={false}
        onDownload={onDownload}
        onLater={onLater}
        onCopyLink={onCopyLink}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /Download update/ }));
    fireEvent.click(screen.getByRole("button", { name: "Not now" }));
    fireEvent.click(screen.getByRole("button", { name: /Copy release link/ }));

    expect(onDownload).toHaveBeenCalledTimes(1);
    expect(onLater).toHaveBeenCalledTimes(1);
    expect(onCopyLink).toHaveBeenCalledTimes(1);
  });

  it("disables the decisions while a download is in progress", () => {
    render(
      <UpdateDialog
        check={available()}
        busy
        onDownload={vi.fn()}
        onLater={vi.fn()}
        onCopyLink={vi.fn()}
      />,
    );

    expect((screen.getByRole("button", { name: /Working/ }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Not now" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("stays hidden when no update is available", () => {
    const { container } = render(
      <UpdateDialog
        check={{ phase: "up-to-date", current: "0.2.1", release: null, message: null }}
        busy={false}
        onDownload={vi.fn()}
        onLater={vi.fn()}
        onCopyLink={vi.fn()}
      />,
    );
    expect(container.firstChild).toBeNull();
  });
});
