import { describe, expect, it } from "vitest";
import {
  isServiceIconDataUrl,
  moveServiceIcon,
  normalizeServiceIcons,
  serviceIconFor,
} from "./serviceIcons";

const PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==";

describe("isServiceIconDataUrl", () => {
  it("accepts small raster data URLs", () => {
    expect(isServiceIconDataUrl(PNG)).toBe(true);
  });

  it("rejects scripts, remote URLs, SVG and non-strings", () => {
    expect(isServiceIconDataUrl("https://example.com/icon.png")).toBe(false);
    expect(isServiceIconDataUrl("data:image/svg+xml;base64,PHN2Zz4=")).toBe(false);
    expect(isServiceIconDataUrl("data:text/html;base64,PGI+")).toBe(false);
    expect(isServiceIconDataUrl(null)).toBe(false);
    expect(isServiceIconDataUrl(42)).toBe(false);
  });
});

describe("normalizeServiceIcons", () => {
  it("keeps valid entries and drops blank or malformed ones", () => {
    expect(
      normalizeServiceIcons({
        " Riot Games ": PNG,
        Discord: PNG,
        "": PNG,
        Steam: "not-an-icon",
        Instagram: 7,
      }),
    ).toEqual({ "Riot Games": PNG, Discord: PNG });
  });

  it("returns an empty map for non-objects", () => {
    expect(normalizeServiceIcons(null)).toEqual({});
    expect(normalizeServiceIcons([])).toEqual({});
    expect(normalizeServiceIcons("x")).toEqual({});
  });
});

describe("serviceIconFor", () => {
  const icons = { Riot: PNG };

  it("finds the picture by exact service label", () => {
    expect(serviceIconFor(icons, "Riot")).toBe(PNG);
  });

  it("has no picture for Other or an unknown service", () => {
    expect(serviceIconFor(icons, "")).toBeNull();
    expect(serviceIconFor(icons, "Steam")).toBeNull();
  });
});

describe("moveServiceIcon", () => {
  it("moves a picture to the renamed service label", () => {
    expect(moveServiceIcon({ Riot: PNG }, " Riot ", "Riot Games")).toEqual({ "Riot Games": PNG });
  });

  it("keeps an existing picture for the destination and drops the old key", () => {
    const other = "data:image/png;base64,AAAA";
    expect(moveServiceIcon({ Riot: PNG, Steam: other }, "Riot", "Steam")).toEqual({ Steam: other });
  });

  it("leaves the map untouched for blank or identical labels", () => {
    expect(moveServiceIcon({ Riot: PNG }, "", "Steam")).toEqual({ Riot: PNG });
    expect(moveServiceIcon({ Riot: PNG }, "Riot", " Riot ")).toEqual({ Riot: PNG });
    expect(moveServiceIcon({}, "Riot", "Steam")).toEqual({});
  });
});
