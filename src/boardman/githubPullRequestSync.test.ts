import {
  resetGithubPullRequestSyncCachesForTests,
  syncGithubPullRequestToPlaky
} from './githubPullRequestSync';
import {
  InMemoryBoardmanMappingStore,
  setBoardmanMappingStoreForTests
} from './boardmanMappingStore';
import { resetBoardmanConfigCacheForTests } from './boardmanConfig';
import { PlakySyncClient } from './plakySyncTypes';

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

function makePullRequestEvent(action: string, merged = false): Record<string, any> {
  return {
    provider_event_type: 'pull_request',
    payload: {
      action,
      repository: { full_name: 'Team-Deepiri/boardman' },
      pull_request: {
        number: 7,
        title: 'Link issue #42',
        body: 'Closes #42',
        state: merged ? 'closed' : 'open',
        merged,
        html_url: 'https://github.com/Team-Deepiri/boardman/pull/7'
      }
    }
  };
}

describe('githubPullRequestSync', () => {
  let mappingStore: InMemoryBoardmanMappingStore;

  beforeEach(() => {
    setBoardmanEnv();
    resetBoardmanConfigCacheForTests();
    resetGithubPullRequestSyncCachesForTests();
    mappingStore = new InMemoryBoardmanMappingStore();
    setBoardmanMappingStoreForTests(mappingStore);
  });

  afterEach(() => {
    setBoardmanMappingStoreForTests(null);
  });

  it('updates linked issue item with PR URL and merge state', async () => {
    const mockClient: PlakySyncClient = {
      findItemIdByExternalKey: jest.fn(async (_field, externalKey) =>
        externalKey === 'github:issue:Team-Deepiri/boardman#42' ? 500 : null
      ),
      createItem: jest.fn(async () => 999),
      patchItemField: jest.fn(async () => undefined),
      listItems: jest.fn(async () => [])
    };

    const result = await syncGithubPullRequestToPlaky(makePullRequestEvent('opened'), {
      clientOverride: mockClient,
      mappingStore
    });

    expect(result.skipped).toBe(false);
    expect(result.linkedIssueKeys).toEqual(['closing_keyword:500']);
    expect(mockClient.createItem).not.toHaveBeenCalled();
    expect(mockClient.patchItemField).toHaveBeenCalledWith(
      500,
      'link-2',
      'https://github.com/Team-Deepiri/boardman/pull/7'
    );
    expect(mockClient.patchItemField).toHaveBeenCalledWith(500, 'status-2', 'PR Open');
  });

  it('skips when no linked issues are referenced', async () => {
    const mockClient: PlakySyncClient = {
      findItemIdByExternalKey: jest.fn(async () => null),
      createItem: jest.fn(async () => 999),
      patchItemField: jest.fn(async () => undefined)
    };

    const event = makePullRequestEvent('opened');
    event.payload.pull_request.body = 'No issue references here';
    event.payload.pull_request.title = 'Standalone PR';

    const result = await syncGithubPullRequestToPlaky(event, {
      clientOverride: mockClient,
      mappingStore
    });
    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('no_pr_task_link');
  });
});
