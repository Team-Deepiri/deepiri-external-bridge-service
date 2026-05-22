import express, { Request, Response, Router } from 'express';
import { createLogger } from '@team-deepiri/shared-utils';
import { requireRouteSecret } from '../middleware/routeSecret';
import { BoardmanAssistantService } from './boardmanAssistantService';

const logger = createLogger('boardman-assistant-routes');
const router: Router = express.Router();
const assistantService = new BoardmanAssistantService();

router.use(requireRouteSecret);

router.post('/synthesize', async (req: Request, res: Response) => {
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
    logger.error('Failed to synthesize DIRECTION tasks', {
      error: error instanceof Error ? error.message : String(error)
    });
    res.status(400).json({
      error: error instanceof Error ? error.message : 'Failed to synthesize DIRECTION tasks'
    });
  }
});

router.post('/approve', async (req: Request, res: Response) => {
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

router.post('/apply', async (req: Request, res: Response) => {
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
