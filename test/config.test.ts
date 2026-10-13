import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
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
  const publicEnvironment={...validEnvironment,PLC_DIRECTORY_URL:"https://plc.directory",PLC_AUTHORITY_PROFILE:"strict-public-v1",
    PLC_PUBLIC_READERS:JSON.stringify([{origin:"https://reader-one.example.com",operator:"reader-one"},{origin:"https://reader-two.example.com",operator:"reader-two"}]),
    PLC_PROVIDER_OPERATORS:JSON.stringify(["provider-operator"])};
  it("selects strict public authority explicitly and preserves the default POC configuration",()=>{
    expect(loadConfig(publicEnvironment).publicPlcAuthority).toMatchObject({profile:"strict-public-v1",providerOperators:["provider-operator"]});
    expect(loadConfig(validEnvironment).publicPlcAuthority).toBeUndefined();
  });
  it("refuses private registry, orphaned declarations and non-independent public readers",()=>{
    for(const environment of [
      {...publicEnvironment,PLC_DIRECTORY_URL:"http://plc.fixture:2582"},
      {...publicEnvironment,PLC_AUTHORITY_PROFILE:"unknown"},
      {...publicEnvironment,PLC_AUTHORITY_PROFILE:"poc"},
      {...publicEnvironment,PLC_PROVIDER_OPERATORS:"[]"},
      {...publicEnvironment,PLC_PUBLIC_READERS:JSON.stringify([{origin:"https://reader-one.example.com",operator:"reader-one"},{origin:"https://reader-one.example.com:8443",operator:"reader-two"}])},
      {...publicEnvironment,PLC_PUBLIC_READERS:JSON.stringify([{origin:"https://reader-one.example.com",operator:"reader-one"},{origin:"https://reader-two.example.com",operator:"provider-operator"}])},
      {...publicEnvironment,PLC_PUBLIC_READERS:JSON.stringify([{origin:"https://reader-one.example.com",operator:"reader-one"},{origin:validEnvironment.PUBLIC_ORIGIN,operator:"reader-two"}])},
      {...publicEnvironment,PLC_PUBLIC_READERS:'[{"origin":"https://reader-one.example.com","origin":"https://reader-two.example.com","operator":"x"}]'},
    ])expect(()=>loadConfig(environment)).toThrow();
  });
  it("does not allow prototype onboarding/activation to stand in for a strict public ceremony",()=>{
    for(const script of ["onboard.ts","activate-public.ts","activate-local.ts"]){
      const result=spawnSync("bun",[`src/cli/${script}`,"owner@hailproto.app"],{cwd:new URL("../",import.meta.url).pathname,
        env:{...process.env,...publicEnvironment,NODE_ENV:"production",DATABASE_URL:"postgresql://not-a-database.invalid/unreachable"},encoding:"utf8",timeout:5000});
      expect(result.status).toBe(1);expect(result.stdout).toBe("");expect(result.stderr).toMatch(/ceremony|Local prototype/);
    }
  });
  it("loads a valid provider configuration", () => {
    expect(loadConfig(validEnvironment)).toMatchObject({
      nodeEnv: "test",
      port: 3000,
      providerId: "app",
      publicOrigin: "https://hailproto.app",
      hailServiceBase: "https://hailproto.app/hail",
      plcDirectoryUrl: "http://localhost:2582",
      pocManagedTransfer:false,
    });
  });

  it("enables private managed transfer only with its existing private gates",()=>{
    const enabled={...validEnvironment,POC_MANAGED_TRANSFER:"true",POC_ACCOUNT_ACCESS:"true",
      POC_SELF_SERVICE_TRANSFER:"true",POC_SELF_SERVICE_RETURN:"true"};
    expect(loadConfig(enabled).pocManagedTransfer).toBe(true);
    expect(()=>loadConfig({...enabled,POC_SELF_SERVICE_RETURN:"false"})).toThrow(/requires account access/);
    expect(()=>loadConfig({...publicEnvironment,POC_MANAGED_TRANSFER:"true",POC_ACCOUNT_ACCESS:"true",
      POC_SELF_SERVICE_TRANSFER:"true",POC_SELF_SERVICE_RETURN:"true"})).toThrow(/non-public PLC/);
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
