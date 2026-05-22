import crypto from 'crypto';

export interface DirectionTaskProposal {
  externalKey: string;
  title: string;
  section: string;
  lineNumber: number;
  completed: boolean;
}

const CHECKBOX_PATTERN = /^-\s+\[( |x|X)\]\s+(.+)$/;

export function slugifySection(section: string): string {
  const normalized = section
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || 'root';
}

export function buildDirectionExternalKey(
  repoFullName: string,
  section: string,
  lineNumber: number,
  title: string
): string {
  const digest = crypto
    .createHash('sha256')
    .update(`${section}\n${lineNumber}\n${title}`)
    .digest('hex')
    .slice(0, 16);
  return `github:direction:${repoFullName}#${digest}`;
}

export function parseDirectionMarkdown(
  repoFullName: string,
  markdown: string
): DirectionTaskProposal[] {
  const lines = markdown.split(/\r?\n/);
  let currentSection = 'root';
  const proposals: DirectionTaskProposal[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const line = lines[index].trimEnd();
    const headingMatch = line.match(/^##\s+(.+)$/);
    if (headingMatch) {
      currentSection = headingMatch[1].trim() || 'root';
      continue;
    }

    const checkboxMatch = line.match(CHECKBOX_PATTERN);
    if (!checkboxMatch) continue;

    const completed = checkboxMatch[1].toLowerCase() === 'x';
    const title = checkboxMatch[2].trim();
    if (!title) continue;

    proposals.push({
      externalKey: buildDirectionExternalKey(repoFullName, currentSection, lineNumber, title),
      title,
      section: currentSection,
      lineNumber,
      completed
    });
  }

  return proposals;
}

export function filterActionableDirectionTasks(
  proposals: DirectionTaskProposal[]
): DirectionTaskProposal[] {
  return proposals.filter((proposal) => !proposal.completed);
}
