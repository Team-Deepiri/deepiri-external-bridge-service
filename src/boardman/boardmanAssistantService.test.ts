import { BoardmanAssistantService } from './boardmanAssistantService';
import { InMemoryAssistantProposalStore } from './assistantProposalStore';
import { resetBoardmanConfigCacheForTests } from './boardmanConfig';
import { applyDirectionTasksToPlaky, resetDirectionTaskSyncCachesForTests } from './directionTaskSync';
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
}

describe('BoardmanAssistantService', () => {
  let store: InMemoryAssistantProposalStore;

  beforeEach(() => {
    setBoardmanEnv();
    resetBoardmanConfigCacheForTests();
    resetDirectionTaskSyncCachesForTests();
    store = new InMemoryAssistantProposalStore();
  });

  it('synthesize → approve → apply is non-duplicative', async () => {
    const mockClient: PlakySyncClient = {
      findItemIdByExternalKey: jest
        .fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValue(111),
      createItem: jest.fn(async () => 111),
      patchItemField: jest.fn(async () => undefined)
    };

    const service = new BoardmanAssistantService(store, {} as never, mockClient);
    const markdown = '## Sprint\n- [ ] Ship PR linkage\n- [ ] Add assistant routes';

    const proposal = await service.synthesize({
      repoFullName: 'Team-Deepiri/boardman',
      directionMarkdown: markdown
    });
    expect(proposal.tasks).toHaveLength(2);

    await service.approve(proposal.proposalId);

    const firstApply = await service.apply(proposal.proposalId);
    expect(firstApply.applied).toHaveLength(2);
    expect(firstApply.applied.every((entry) => entry.created)).toBe(true);

    await expect(service.apply(proposal.proposalId)).rejects.toThrow('Proposal has already been applied');

    const replayApply = await applyDirectionTasksToPlaky(
      'Team-Deepiri/boardman',
      proposal.tasks,
      {
        findItemIdByExternalKey: jest.fn(async () => 111),
        createItem: jest.fn(async () => 999),
        patchItemField: jest.fn(async () => undefined)
      }
    );
    expect(replayApply.every((entry) => entry.created === false)).toBe(true);
  });

  it('rejects apply before approve', async () => {
    const service = new BoardmanAssistantService(store, {} as never);
    const proposal = await service.synthesize({
      repoFullName: 'Team-Deepiri/boardman',
      directionMarkdown: '## Sprint\n- [ ] One task'
    });

    await expect(service.apply(proposal.proposalId)).rejects.toThrow(
      'Proposal must be approved before apply'
    );
  });
});
