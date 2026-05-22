import axios, { AxiosInstance } from 'axios';
import { createLogger } from '@team-deepiri/shared-utils';

const logger = createLogger('boardman-plaky-client');

interface PlakyFieldResponse {
  key?: string;
  title?: string;
  value?: unknown;
}

interface PlakyItemResponse {
  id: number;
  title: string;
  fields?: PlakyFieldResponse[];
}

interface PlakyPagedResponse<T> {
  data: T[];
  hasMore: boolean;
}

export interface PlakyClientConfig {
  apiKey: string;
  baseUrl: string;
  spaceId: number;
  boardId: number;
  groupId: number;
}

export class PlakyClient {
  private readonly http: AxiosInstance;
  private readonly itemBasePath: string;
  private readonly groupId: number;

  constructor(config: PlakyClientConfig) {
    const trimmedBaseUrl = config.baseUrl.replace(/\/+$/, '');
    this.http = axios.create({
      baseURL: trimmedBaseUrl,
      headers: {
        'X-API-Key': config.apiKey,
        'Content-Type': 'application/json'
      },
      timeout: 15000
    });
    this.itemBasePath = `/v1/public/spaces/${config.spaceId}/boards/${config.boardId}/items`;
    this.groupId = config.groupId;
  }

  async findItemIdByExternalKey(
    externalFieldKey: string,
    externalKey: string,
    maxPages: number = 20,
    pageSize: number = 100
  ): Promise<number | null> {
    for (let page = 1; page <= maxPages; page++) {
      const response = await this.http.get<PlakyPagedResponse<PlakyItemResponse>>(this.itemBasePath, {
        params: {
          page,
          pageSize,
          expand: 'fields'
        }
      });

      const items = Array.isArray(response.data?.data) ? response.data.data : [];
      for (const item of items) {
        const currentExternalKey = this.getFieldStringValue(item, externalFieldKey);
        if (currentExternalKey === externalKey) {
          return item.id;
        }
      }

      if (!response.data?.hasMore) {
        return null;
      }
    }

    logger.warn('Plaky scan reached max page limit while searching item by external key', {
      externalFieldKey,
      maxPages
    });
    return null;
  }

  async createItem(title: string, fields: Record<string, unknown>): Promise<number> {
    const response = await this.http.post<PlakyItemResponse>(this.itemBasePath, {
      title,
      groupId: this.groupId,
      fields
    });

    if (!response.data?.id) {
      throw new Error('Plaky create item response missing item id');
    }

    return response.data.id;
  }

  async patchItemField(itemId: number, itemFieldKey: string, value: unknown): Promise<void> {
    await this.http.patch(
      `${this.itemBasePath}/${itemId}/fields/${encodeURIComponent(itemFieldKey)}`,
      { value }
    );
  }

  async listBoards(spaceId: number): Promise<Array<{ id: number; name: string }>> {
    const response = await this.http.get<{ data?: Array<{ id: number; name: string }> }>(
      `/v1/public/spaces/${spaceId}/boards`
    );
    return Array.isArray(response.data?.data) ? response.data.data : [];
  }

  async listItems(maxPages: number = 20, pageSize: number = 100): Promise<PlakyItemResponse[]> {
    const collected: PlakyItemResponse[] = [];

    for (let page = 1; page <= maxPages; page++) {
      const response = await this.http.get<PlakyPagedResponse<PlakyItemResponse>>(this.itemBasePath, {
        params: { page, pageSize }
      });
      const items = Array.isArray(response.data?.data) ? response.data.data : [];
      collected.push(...items);
      if (!response.data?.hasMore) break;
    }

    return collected;
  }

  private getFieldStringValue(item: PlakyItemResponse, fieldKey: string): string | null {
    const fields = Array.isArray(item.fields) ? item.fields : [];
    const field = fields.find((candidate) => candidate?.key === fieldKey);
    if (!field) return null;
    return PlakyClient.stringifyFieldValue(field.value);
  }

  private static stringifyFieldValue(value: unknown): string | null {
    if (value === null || value === undefined) return null;
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    try {
      return JSON.stringify(value);
    } catch {
      return null;
    }
  }
}
