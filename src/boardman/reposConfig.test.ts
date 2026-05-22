import path from 'path';
import { getRepoRouting, listConfiguredRepos, resetReposConfigCacheForTests } from './reposConfig';

describe('reposConfig', () => {
  beforeEach(() => {
    resetReposConfigCacheForTests();
    process.env.BOARDMAN_CONFIG_DIR = path.join(__dirname, '__fixtures__');
    process.env.PLAKY_BOARD_ID = '999';
    process.env.PLAKY_ITEM_GROUP_ID = '888';
  });

  it('routes known repos from repos.yml', () => {
    const routing = getRepoRouting('Team-Deepiri/boardman');
    expect(routing.plakyBoardId).toBe(101);
    expect(routing.plakyGroupId).toBe(201);
    expect(routing.tier).toBe(1);
  });

  it('falls back to defaults for unknown repos', () => {
    const routing = getRepoRouting('Team-Deepiri/unknown-repo');
    expect(routing.plakyBoardId).toBe(100);
    expect(routing.plakyGroupId).toBe(200);
  });

  it('lists configured repos', () => {
    expect(listConfiguredRepos()).toContain('Team-Deepiri/boardman');
  });
});
