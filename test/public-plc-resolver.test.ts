import { expect,it,vi } from "vitest";
import type { SQL } from "bun";
import { VerifiedPublicPlcResolver } from "../src/plc/public-resolver.js";
import { publicPlcFixture,publicPlcReaders } from "./public-plc-fixture.js";

it("refuses reader outage, contradictory state/audit and hung reads before persistence or authority",async()=>{
  const fixture=await publicPlcFixture(),readers=publicPlcReaders([fixture]),begin=vi.fn();
  const sql={begin} as unknown as SQL;
  for(const bad of [
    {...readers[1],async audit(){throw new Error("Reader outage");}},
    {...readers[1],async health(){return {lastCommittedOpTime:"2000-01-01T00:00:00.000Z"};}},
    {...readers[1],async health(){return {}; }},
    {...readers[1],async audit(did:string){return (await readers[1].audit(did)).map(entry=>({...entry,createdAt:"2000-01-01T00:00:00.000Z"}));}},
    {...readers[1],resolver:{async resolve(did:string){const resolved=await readers[1].resolver.resolve(did);return {...resolved,messagingDidKey:resolved.identityDidKey};}}},
  ])await expect(new VerifiedPublicPlcResolver(sql,[readers[0],bad],["provider"],["https://local.example.com"])
    .resolve(fixture.did)).rejects.toThrow();
  const stalled={...readers[1],audit:()=>new Promise<never>(()=>{})};
  await expect(new VerifiedPublicPlcResolver(sql,[readers[0],stalled],["provider"],["https://local.example.com"],undefined,20)
    .resolve(fixture.did)).rejects.toMatchObject({name:"TimeoutError"});
  expect(begin).not.toHaveBeenCalled();
});

it("rejects backward/expired local verification clocks and malformed subjects",async()=>{
  const fixture=await publicPlcFixture(),baseReaders=publicPlcReaders([fixture]),
    readers=baseReaders.map(reader=>({...reader,async health(){return {lastCommittedOpTime:new Date(1_800_000_000_000).toISOString()};}})) as typeof baseReaders,
    begin=vi.fn(),sql={begin} as unknown as SQL;
  for(const elapsed of [-1,16_000]){
    let calls=0;const clock=()=>new Date(1_800_000_000_000+(calls++?elapsed:0));
    await expect(new VerifiedPublicPlcResolver(sql,readers,["provider"],["https://local.example.com"],clock).resolve(fixture.did)).rejects.toThrow("clock/deadline");
  }
  await expect(new VerifiedPublicPlcResolver(sql,readers,["provider"],["https://local.example.com"]).resolve("untrusted-message-content")).rejects.toThrow("canonical");
  expect(begin).not.toHaveBeenCalled();
});
