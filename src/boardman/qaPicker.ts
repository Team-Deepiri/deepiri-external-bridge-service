import { loadTeamAssignments, QaAssignee } from './teamAssignmentsConfig';

export function pickQaAssignee(tier: number): QaAssignee | null {
  const roster = loadTeamAssignments().qa_assignees || [];
  const eligible = roster.filter((candidate) => {
    if (!candidate.plaky_user_id || candidate.weight <= 0) return false;
    if (!candidate.tiers || candidate.tiers.length === 0) return true;
    return candidate.tiers.includes(tier);
  });

  if (eligible.length === 0) return null;

  const totalWeight = eligible.reduce((sum, candidate) => sum + candidate.weight, 0);
  let roll = Math.random() * totalWeight;

  for (const candidate of eligible) {
    roll -= candidate.weight;
    if (roll <= 0) return candidate;
  }

  return eligible[eligible.length - 1];
}
