import {
  buildDirectionExternalKey,
  filterActionableDirectionTasks,
  parseDirectionMarkdown
} from './directionParser';

describe('directionParser', () => {
  it('parses unchecked DIRECTION tasks with stable external keys', () => {
    const markdown = [
      '# Direction',
      '## Sprint',
      '- [ ] Ship PR linkage',
      '- [x] Already done'
    ].join('\n');

    const parsed = parseDirectionMarkdown('Team-Deepiri/boardman', markdown);
    const actionable = filterActionableDirectionTasks(parsed);

    expect(actionable).toHaveLength(1);
    expect(actionable[0].title).toBe('Ship PR linkage');
    expect(actionable[0].externalKey).toBe(
      buildDirectionExternalKey('Team-Deepiri/boardman', 'Sprint', 3, 'Ship PR linkage')
    );
  });

  it('dedupes by external key across replays', () => {
    const markdown = '## Sprint\n- [ ] Ship PR linkage';
    const first = parseDirectionMarkdown('Team-Deepiri/boardman', markdown);
    const second = parseDirectionMarkdown('Team-Deepiri/boardman', markdown);
    expect(first[0].externalKey).toBe(second[0].externalKey);
  });
});
