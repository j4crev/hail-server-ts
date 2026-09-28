import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { Readable } from "node:stream";
import ipaddr from "ipaddr.js";
import type { DiscoveryFetch, NetworkTargetValidator } from "./verifier.js";

export interface DnsResolver {
  lookup(hostname: string): Promise<readonly { address: string; family: number }[]>;
}

const systemResolver: DnsResolver = {
  lookup(hostname) {
    return dnsLookup(hostname, { all: true, verbatim: true });
  },
};

export function isPublicAddress(address: string): boolean {
  let parsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    parsed = ipaddr.parse(address);
  } catch {
    return false;
  }
  if (parsed.kind() === "ipv6") {
    const ipv6 = parsed as ipaddr.IPv6;
    if (ipv6.isIPv4MappedAddress()) parsed = ipv6.toIPv4Address();
    else if (!ipv6.match(ipaddr.parse("2000::"), 3)) return false;
  }
  return parsed.range() === "unicast";
}

export class SafeHttpsTransport {
  readonly validateTarget: NetworkTargetValidator;

  constructor(
    private readonly resolver: DnsResolver = systemResolver,
    private readonly connectionTimeoutMs = 5_000,
  ) {
    this.validateTarget = (url) => this.validateUrl(url);
  }

  readonly fetch: DiscoveryFetch = async (request) => {
    if (request.method !== "GET") throw new Error("Safe discovery transport only permits GET");
    const url = new URL(request.url);
    this.validateUrl(url);
    for (const name of ["authorization", "cookie", "referer"]) {
      if (request.headers.has(name)) throw new Error(`Discovery request must not send ${name}`);
    }

    const addresses = await this.resolve(url.hostname, request.signal);
    if (
      addresses.length === 0 ||
      addresses.some(
        (entry) =>
          !isPublicAddress(entry.address) ||
          (entry.family !== 4 && entry.family !== 6) ||
          isIP(entry.address) !== entry.family,
      )
    ) {
      throw new Error("Discovery hostname did not resolve exclusively to public addresses");
    }
    const selected = addresses[0]!;

    return new Promise<Response>((resolve, reject) => {
      const outgoing = httpsRequest(
        {
          protocol: "https:",
          hostname: url.hostname,
          port: url.port ? Number(url.port) : 443,
          path: `${url.pathname}${url.search}`,
          method: "GET",
          headers: Object.fromEntries(request.headers),
          agent: false,
          family: selected.family,
          servername: url.hostname,
          lookup: (_hostname, _options, callback) => {
            callback(null, selected.address, selected.family);
          },
        },
        (incoming) => {
          const headers = new Headers();
          for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
            const name = incoming.rawHeaders[index];
            const value = incoming.rawHeaders[index + 1];
            if (name !== undefined && value !== undefined) headers.append(name, value);
          }
          const body = Readable.toWeb(incoming) as unknown as ReadableStream<Uint8Array>;
          resolve(
            new Response(body, {
              status: incoming.statusCode ?? 500,
              statusText: incoming.statusMessage ?? "",
              headers,
            }),
          );
        },
      );

      const connectionTimer = setTimeout(() => {
        outgoing.destroy(new Error("Discovery connection timed out"));
      }, this.connectionTimeoutMs);
      outgoing.once("socket", (socket) => {
        socket.once("secureConnect", () => clearTimeout(connectionTimer));
      });
      outgoing.once("error", (error) => {
        clearTimeout(connectionTimer);
        reject(error);
      });
      if (request.signal.aborted) {
        clearTimeout(connectionTimer);
        outgoing.destroy(request.signal.reason);
      } else {
        request.signal.addEventListener(
          "abort",
          () => {
            clearTimeout(connectionTimer);
            outgoing.destroy(request.signal.reason);
          },
          { once: true },
        );
      }
      outgoing.end();
    });
  };

  private resolve(
    hostname: string,
    signal: AbortSignal,
  ): Promise<readonly { address: string; family: number }[]> {
    signal.throwIfAborted();
    return new Promise((resolve, reject) => {
      const aborted = () => reject(signal.reason);
      signal.addEventListener("abort", aborted, { once: true });
      this.resolver.lookup(hostname).then(resolve, reject).finally(() => {
        signal.removeEventListener("abort", aborted);
      });
    });
  }

  private validateUrl(url: URL): void {
    const asciiHostname = domainToASCII(url.hostname);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.hash ||
      !asciiHostname ||
      asciiHostname !== url.hostname ||
      url.hostname.endsWith(".") ||
      isIP(url.hostname) !== 0
    ) {
      throw new Error("Discovery target is not a canonical HTTPS DNS URL");
    }
  }
}
