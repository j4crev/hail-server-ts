import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

const validEnvironment = {
  NODE_ENV: "test",
  PORT: "3000",
  PROVIDER_ID: "app",
  PUBLIC_ORIGIN: "https://hailproto.app",
  HAIL_SERVICE_BASE: "https://hailproto.app/hail",
  PLC_DIRECTORY_URL: "http://localhost:2582",
  DATABASE_URL: "postgresql://hail:secret@localhost:5432/hail_app",
  KEY_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};

describe("loadConfig", () => {
  it("loads a valid provider configuration", () => {
    expect(loadConfig(validEnvironment)).toMatchObject({
      nodeEnv: "test",
      port: 3000,
      providerId: "app",
      publicOrigin: "https://hailproto.app",
      hailServiceBase: "https://hailproto.app/hail",
      plcDirectoryUrl: "http://localhost:2582",
    });
  });

  it("requires the Hail service base to belong to the public origin", () => {
    expect(() =>
      loadConfig({
        ...validEnvironment,
        HAIL_SERVICE_BASE: "https://hailproto.dev/hail",
      }),
    ).toThrow("HAIL_SERVICE_BASE must equal PUBLIC_ORIGIN followed by /hail");
  });

  it("rejects a non-HTTPS public origin", () => {
    expect(() =>
      loadConfig({
        ...validEnvironment,
        PUBLIC_ORIGIN: "http://hailproto.app",
      }),
    ).toThrow("PUBLIC_ORIGIN must use https:");
  });

  it("rejects placeholder encryption material", () => {
    expect(() =>
      loadConfig({
        ...validEnvironment,
        KEY_ENCRYPTION_KEY: "replace-me",
      }),
    ).toThrow("KEY_ENCRYPTION_KEY must be a 32-byte unpadded base64url value");
  });

  it("rejects a noncanonical base64url encryption key", () => {
    expect(() =>
      loadConfig({
        ...validEnvironment,
        KEY_ENCRYPTION_KEY: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      }),
    ).toThrow("KEY_ENCRYPTION_KEY must be a canonical 32-byte unpadded base64url value");
  });

  it("rejects credentials in the PLC directory URL", () => {
    expect(() =>
      loadConfig({
        ...validEnvironment,
        PLC_DIRECTORY_URL: "http://user:secret@localhost:2582",
      }),
    ).toThrow("PLC_DIRECTORY_URL must not contain credentials");
  });
});
