import { describe, expect, it } from "vitest";
import {
  emptyVaultGraph,
  migrateVaultGraph,
  migrateVaultGraphReport,
  UnsupportedVaultVersionError,
  VAULT_SCHEMA_VERSION,
} from "./vaultDocument";

describe("migrateVaultGraph", () => {
  it("converts a graph document into accounts and inherits the service from contains", () => {
    const stored = {
      schemaVersion: 2,
      nodes: [
        { id: "riot", name: "Riot", type: "Service", fields: [] },
        {
          id: "main",
          name: "Main",
          type: "Account",
          fields: [{ id: "f-1", label: "Password", type: "Password", value: "x" }],
        },
        { id: "loose", name: "Loose", type: "Account", fields: [] },
      ],
      relationships: [
        {
          id: "r-1",
          sourceNodeId: "riot",
          targetNodeId: "main",
          category: "Organizational",
          type: "contains",
        },
      ],
      layout: { main: { x: 1, y: 2 } },
    };

    expect(migrateVaultGraph(stored)).toEqual({
      schemaVersion: VAULT_SCHEMA_VERSION,
      accounts: [
        {
          id: "main",
          name: "Main",
          service: "Riot",
          tags: [],
          fields: [{ id: "f-1", label: "Password", type: "Password", value: "x" }],
        },
        { id: "loose", name: "Loose", service: "", tags: [], fields: [] },
      ],
      presets: [],
      attachments: [],
      serviceIcons: {},
      // Legacy graph sections have no v3 equivalent and are kept verbatim so
      // relationship/layout data is never silently discarded (K-11).
      extraKeys: {
        legacyGraph: {
          nodes: stored.nodes,
          relationships: stored.relationships,
          layout: stored.layout,
        },
      },
    });
  });

  it("converts templates into presets", () => {
    const stored = {
      schemaVersion: 2,
      nodes: [],
      relationships: [],
      layout: {},
      templates: [
        {
          id: "t-1",
          name: "Riot account",
          nodeType: "Account",
          fields: [{ label: "Username", type: "Username", value: "" }],
        },
      ],
    };
    expect(migrateVaultGraph(stored).presets).toEqual([
      {
        id: "t-1",
        name: "Riot account",
        service: "",
        tags: [],
        fields: [{ label: "Username", type: "Username", value: "" }],
      },
    ]);
  });

  it("passes an already-current document through", () => {
    const stored = {
      schemaVersion: 3,
      accounts: [
        { id: "a", name: "A", service: "Discord", tags: ["Owner"], fields: [] },
      ],
      presets: [],
      attachments: [],
      serviceIcons: {},
    };
    expect(migrateVaultGraph(stored)).toEqual(stored);
  });

  it("keeps valid attachments and drops malformed ones", () => {
    const attachment = {
      id: "att-1",
      nodeId: "a",
      fileName: "a.png",
      mimeType: "image/png",
      sizeBytes: 3,
      sha256Hex: "ab".repeat(32),
      createdAtMs: 1,
    };
    expect(migrateVaultGraph({ accounts: [], attachments: [attachment, { id: "bad" }] }).attachments).toEqual([
      attachment,
    ]);
  });

  it("keeps valid service pictures and drops malformed ones", () => {
    const icon = "data:image/png;base64,iVBORw0KGgo=";
    const migrated = migrateVaultGraph({
      accounts: [],
      serviceIcons: { " Riot ": icon, "": icon, Bad: "nope", Instagram: 7 },
    });
    expect(migrated.serviceIcons).toEqual({ Riot: icon });
  });

  it("repairs malformed shapes into an empty current document", () => {
    expect(migrateVaultGraph(null)).toEqual(emptyVaultGraph());
    expect(migrateVaultGraph({ accounts: "nope", nodes: null, presets: [] })).toEqual(emptyVaultGraph());
    expect(migrateVaultGraph({ accounts: [{ name: "no id" }] })).toEqual(emptyVaultGraph());
  });

  it("rejects documents from a newer schema instead of rewriting them", () => {
    expect(() => migrateVaultGraph({ schemaVersion: VAULT_SCHEMA_VERSION + 1, accounts: [] })).toThrow(
      UnsupportedVaultVersionError,
    );
    try {
      migrateVaultGraph({ schemaVersion: 99, accounts: [] });
    } catch (error) {
      expect(error).toBeInstanceOf(UnsupportedVaultVersionError);
      expect((error as UnsupportedVaultVersionError).version).toBe(99);
    }
  });

  it("preserves unknown top-level keys for the next save", () => {
    const migrated = migrateVaultGraph({
      schemaVersion: 3,
      accounts: [],
      futureMetadata: { theme: "amber" },
      customFlag: true,
    });
    expect(migrated.extraKeys).toEqual({ futureMetadata: { theme: "amber" }, customFlag: true });
  });

  it("preserves unknown nested keys for the next save", () => {
    const migrated = migrateVaultGraph({
      schemaVersion: 3,
      accounts: [
        {
          id: "a",
          name: "A",
          service: "",
          tags: [],
          futureAccountFlag: 1,
          fields: [
            { id: "f", label: "L", type: "Text", value: "v", futureFieldFlag: "x" },
          ],
        },
      ],
      presets: [
        {
          id: "p",
          name: "P",
          service: "",
          tags: [],
          futurePresetFlag: true,
          fields: [{ label: "U", type: "Username", futureBlueprintFlag: [1, 2] }],
        },
      ],
    });
    expect(migrated.accounts[0].extraKeys).toEqual({ futureAccountFlag: 1 });
    expect(migrated.accounts[0].fields[0].extraKeys).toEqual({ futureFieldFlag: "x" });
    expect(migrated.presets[0].extraKeys).toEqual({ futurePresetFlag: true });
    expect(migrated.presets[0].fields[0].extraKeys).toEqual({ futureBlueprintFlag: [1, 2] });
  });

  it("keeps the legacy snapshot across repeated loads without duplicating it", () => {
    const stored = {
      schemaVersion: 2,
      nodes: [{ id: "n", name: "N", type: "Account", fields: [] }],
      relationships: [{ id: "r", sourceNodeId: "a", targetNodeId: "n" }],
      layout: { n: { x: 0, y: 1 } },
    };
    const first = migrateVaultGraphReport(stored);
    expect(first.warnings).toHaveLength(1);
    const second = migrateVaultGraphReport(first.graph);
    expect(second.graph.extraKeys).toEqual(first.graph.extraKeys);
    expect(second.warnings).toEqual([]);
  });

  it("reports skipped records instead of dropping them silently", () => {
    const report = migrateVaultGraphReport({
      schemaVersion: 3,
      accounts: [
        { id: "a", name: "A", service: "", tags: [], fields: [{ id: "f", label: "L", type: "Text", value: "v" }, { id: "bad" }] },
        { name: "no id" },
      ],
      presets: [{ id: "p", name: "P", fields: [{ label: "x", type: "Text" }, { type: "Text" }] }],
      attachments: [{ id: "bad" }],
    });
    expect(report.graph.accounts).toHaveLength(1);
    expect(report.warnings).toEqual([
      "Skipped unreadable 1 account record(s), 1 field record(s), 1 preset field record(s), 1 attachment record(s) while opening this vault.",
    ]);
  });
});
