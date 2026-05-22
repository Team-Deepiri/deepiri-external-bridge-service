export interface PlakyListItem {
  id: number;
  title: string;
}

export interface PlakySyncClient {
  findItemIdByExternalKey(
    externalFieldKey: string,
    externalKey: string,
    maxPages: number,
    pageSize: number
  ): Promise<number | null>;
  createItem(title: string, fields: Record<string, unknown>): Promise<number>;
  patchItemField(itemId: number, itemFieldKey: string, value: unknown): Promise<void>;
  listItems?(maxPages: number, pageSize: number): Promise<PlakyListItem[]>;
}

export interface BoardmanSyncResult {
  skipped: boolean;
  reason?: string;
  created?: boolean;
  plakyItemId?: number;
  externalKey?: string;
  action?: string;
  linkedIssueKeys?: string[];
}
