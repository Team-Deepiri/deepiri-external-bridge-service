import {
  resetBoardmanSyncCachesForTests,
  syncGithubIssueToPlaky,
  PlakySyncClient
} from './githubIssueSync';
import {
  InMemoryBoardmanMappingStore,
  setBoardmanMappingStoreForTests
} from './boardmanMappingStore';

function setBoardmanEnv(): void {
  process.env.PLAKY_FIELD_EXTERNAL_KEY_ID = 'string-1';
  process.env.PLAKY_FIELD_GITHUB_URL_ID = 'link-1';
  process.env.PLAKY_FIELD_REPO_ID = 'string-2';
  process.env.PLAKY_FIELD_STATUS_ID = 'status-1';
  process.env.PLAKY_FIELD_PR_URL_ID = 'link-2';
  process.env.PLAKY_FIELD_MERGE_STATE_ID = 'status-2';
  process.env.PLAKY_STATUS_OPEN_VALUE = 'To do';
  process.env.PLAKY_STATUS_CLOSED_VALUE = 'Done';
  process.env.PLAKY_MERGE_STATE_OPEN_VALUE = 'PR Open';
  process.env.PLAKY_MERGE_STATE_MERGED_VALUE = 'PR Merged';
  process.env.PLAKY_MERGE_STATE_CLOSED_VALUE = 'PR Closed';
  process.env.PLAKY_MERGE_STATE_DRAFT_VALUE = 'PR Draft';
  process.env.PLAKY_WORKSPACE_ID = '1';
  process.env.PLAKY_BOARD_ID = '100';
  process.env.PLAKY_ITEM_GROUP_ID = '200';
  process.env.PLAKY_API_KEY = 'test-key';
  process.env.PLAKY_BASE_URL = 'https://api.plaky.com';
}

function makeIssueEvent(action: string, state: string): Record<string, any> {
  return {
    provider_event_type: 'issues',
    payload: {
      action,
      repository: { full_name: 'Team-Deepiri/boardman' },
      issue: {
        number: 42,
        title: 'Fix webhook dedupe',
        body: 'Body',
        state,
        html_url: 'https://github.com/Team-Deepiri/boardman/issues/42'
      }
    }
  };
}

describe('githubIssueSync', () => {
  let mappingStore: InMemoryBoardmanMappingStore;

  beforeEach(() => {
    setBoardmanEnv();
    resetBoardmanSyncCachesForTests();
    mappingStore = new InMemoryBoardmanMappingStore();
    setBoardmanMappingStoreForTests(mappingStore);
  });

  afterEach(() => {
    setBoardmanMappingStoreForTests(null);
  });

  it('skips non-issue github events', async () => {
    const result = await syncGithubIssueToPlaky({ provider_event_type: 'pull_request' });
    expect(result.skipped).toBe(true);
    expect(result.reason).toContain('unsupported_github_event_type');
  });

  it('creates item when external key is not found', async () => {
    const mockClient: PlakySyncClient = {
      findItemIdByExternalKey: jest.fn(async () => null),
      createItem: jest.fn(async () => 999),
      patchItemField: jest.fn(async () => undefined)
    };

    const result = await syncGithubIssueToPlaky(makeIssueEvent('opened', 'open'), {
      clientOverride: mockClient,
      mappingStore
    });

    expect(result.skipped).toBe(false);
    expect(result.created).toBe(true);
    expect(result.plakyItemId).toBe(999);
    expect(mockClient.createItem).toHaveBeenCalledTimes(1);
    expect(mockClient.patchItemField).toHaveBeenCalledTimes(0);
  });

  it('updates existing item and closed status on replayed issue', async () => {
    const mockClient: PlakySyncClient = {
      findItemIdByExternalKey: jest.fn(async () => 321),
      createItem: jest.fn(async () => 999),
      patchItemField: jest.fn(async () => undefined)
    };

    const result = await syncGithubIssueToPlaky(makeIssueEvent('closed', 'closed'), {
      clientOverride: mockClient,
      mappingStore
    });

    expect(result.skipped).toBe(false);
    expect(result.created).toBe(false);
    expect(result.plakyItemId).toBe(321);
    expect(mockClient.createItem).toHaveBeenCalledTimes(0);
    expect(mockClient.patchItemField).toHaveBeenCalledTimes(3);
    expect(mockClient.patchItemField).toHaveBeenCalledWith(321, 'status-1', 'Done');
  });

  it('skips unsupported issue actions', async () => {
    const mockClient: PlakySyncClient = {
      findItemIdByExternalKey: jest.fn(async () => null),
      createItem: jest.fn(async () => 999),
      patchItemField: jest.fn(async () => undefined)
    };

    const result = await syncGithubIssueToPlaky(makeIssueEvent('labeled', 'open'), {
      clientOverride: mockClient,
      mappingStore
    });

    expect(result.skipped).toBe(true);
    expect(result.reason).toContain('unsupported_issue_action');
    expect(mockClient.createItem).not.toHaveBeenCalled();
    expect(mockClient.patchItemField).not.toHaveBeenCalled();
  });
});
