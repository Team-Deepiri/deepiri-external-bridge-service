import { extractClosingIssueNumbers } from './prTaskLinking';

describe('prTaskLinking', () => {
  it('extracts closing keywords', () => {
    const issues = extractClosingIssueNumbers('Fix webhook', 'Closes #42 and fixes #43', 7);
    expect(issues).toEqual([42, 43]);
  });
});
