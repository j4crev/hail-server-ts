import {
  Client,
  PlcClientError,
  type CompatibleOpOrTombstone,
  type DidDocument,
  type DocumentData,
  type ExportedOp,
  type Operation,
} from "@did-plc/lib";

export interface PlcDirectoryClient {
  health(): Promise<unknown>;
  getDocument(did: string): Promise<DidDocument>;
  getDocumentData(did: string): Promise<DocumentData>;
  getOperationLog(did: string): Promise<CompatibleOpOrTombstone[]>;
  getAuditableLog(did: string): Promise<ExportedOp[]>;
  sendOperation(did: string, operation: Operation): Promise<void>;
}

export function createPlcDirectoryClient(baseUrl: string): PlcDirectoryClient {
  return new Client(baseUrl);
}

export function isPlcNotFound(error: unknown): boolean {
  return error instanceof PlcClientError && error.status === 404;
}
