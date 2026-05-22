import express, { Request, Response, Router } from 'express';
import { createLogger } from '@team-deepiri/shared-utils';
import { requireRouteSecret } from '../middleware/routeSecret';
import { BoardmanAssistantService } from './boardmanAssistantService';
import { BoardmanAgentService } from './boardmanAgentService';
import { BoardmanScanService } from './scanService';
import { getRepoRouting, listConfiguredRepos } from './reposConfig';
import { fuzzyMatchBest } from './plakyNameMatch';
import { PlakyClient } from './plakyClient';
import { parsePositiveIntEnv, requiredEnv } from './boardmanConfig';

const logger = createLogger('boardman-api-routes');
const router: Router = express.Router();
const assistantService = new BoardmanAssistantService();
const agentService = new BoardmanAgentService();
const scanService = new BoardmanScanService();

router.use(requireRouteSecret);

router.get('/repos', (_req: Request, res: Response) => {
  const repos = listConfiguredRepos();
  res.json({
    repos: repos.map((repoFullName) => ({
      repoFullName,
      routing: getRepoRouting(repoFullName)
    }))
  });
});

router.get('/plaky/boards/match', async (req: Request, res: Response) => {
  try {
    const query = typeof req.query.q === 'string' ? req.query.q : '';
    if (!query) {
      return void res.status(400).json({ error: 'q is required' });
    }

    const spaceId = parsePositiveIntEnv('PLAKY_WORKSPACE_ID');
    const client = new PlakyClient({
      apiKey: requiredEnv('PLAKY_API_KEY'),
      baseUrl: requiredEnv('PLAKY_BASE_URL'),
      spaceId,
      boardId: parsePositiveIntEnv('PLAKY_BOARD_ID'),
      groupId: parsePositiveIntEnv('PLAKY_ITEM_GROUP_ID')
    });

    const boards = await client.listBoards(spaceId);
    const match = fuzzyMatchBest(query, boards, (board) => board.name);
    res.json({ query, match });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : 'match failed' });
  }
});

router.post('/agent/chat', async (req: Request, res: Response) => {
  try {
    const message = typeof req.body?.message === 'string' ? req.body.message : '';
    if (!message) {
      return void res.status(400).json({ error: 'message is required' });
    }

    const result = await agentService.chat({
      message,
      repoFullName: typeof req.body?.repoFullName === 'string' ? req.body.repoFullName : undefined,
      allowWrites: Boolean(req.body?.allowWrites)
    });

    res.status(200).json(result);
  } catch (error) {
    logger.error('Agent chat failed', { error: error instanceof Error ? error.message : String(error) });
    res.status(400).json({ error: error instanceof Error ? error.message : 'agent chat failed' });
  }
});

router.post('/agent/scan', async (req: Request, res: Response) => {
  try {
    const repoFullName = typeof req.body?.repoFullName === 'string' ? req.body.repoFullName : '';
    if (!repoFullName) {
      return void res.status(400).json({ error: 'repoFullName is required' });
    }

    const result = await scanService.scanRepository({
      repoFullName,
      allowWrites: Boolean(req.body?.allowWrites),
      directionPath: typeof req.body?.directionPath === 'string' ? req.body.directionPath : undefined
    });

    res.status(200).json(result);
  } catch (error) {
    logger.error('Scan failed', { error: error instanceof Error ? error.message : String(error) });
    res.status(400).json({ error: error instanceof Error ? error.message : 'scan failed' });
  }
});

router.post('/assistant/synthesize', async (req: Request, res: Response) => {
  try {
    const repoFullName = typeof req.body?.repoFullName === 'string' ? req.body.repoFullName : '';
    if (!repoFullName) {
      return void res.status(400).json({ error: 'repoFullName is required' });
    }

    const proposal = await assistantService.synthesize({
      repoFullName,
      directionMarkdown:
        typeof req.body?.directionMarkdown === 'string' ? req.body.directionMarkdown : undefined,
      directionPath:
        typeof req.body?.directionPath === 'string' ? req.body.directionPath : undefined,
      ref: typeof req.body?.ref === 'string' ? req.body.ref : undefined
    });

    res.status(201).json({
      proposalId: proposal.proposalId,
      status: proposal.status,
      repoFullName: proposal.repoFullName,
      taskCount: proposal.tasks.length,
      tasks: proposal.tasks
    });
  } catch (error) {
    res.status(400).json({
      error: error instanceof Error ? error.message : 'Failed to synthesize DIRECTION tasks'
    });
  }
});

router.post('/assistant/approve', async (req: Request, res: Response) => {
  try {
    const proposalId = typeof req.body?.proposalId === 'string' ? req.body.proposalId : '';
    if (!proposalId) {
      return void res.status(400).json({ error: 'proposalId is required' });
    }

    const proposal = await assistantService.approve(proposalId);
    res.status(200).json({
      proposalId: proposal.proposalId,
      status: proposal.status,
      approvedAt: proposal.approvedAt
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to approve proposal';
    const statusCode = message === 'Proposal not found' ? 404 : 400;
    res.status(statusCode).json({ error: message });
  }
});

router.post('/assistant/apply', async (req: Request, res: Response) => {
  try {
    const proposalId = typeof req.body?.proposalId === 'string' ? req.body.proposalId : '';
    if (!proposalId) {
      return void res.status(400).json({ error: 'proposalId is required' });
    }

    const result = await assistantService.apply(proposalId);
    res.status(200).json({
      proposalId: result.proposal.proposalId,
      status: result.proposal.status,
      appliedAt: result.proposal.appliedAt,
      results: result.applied
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to apply proposal';
    let statusCode = 400;
    if (message === 'Proposal not found') statusCode = 404;
    if (message === 'Proposal must be approved before apply') statusCode = 409;
    res.status(statusCode).json({ error: message });
  }
});

export default router;
