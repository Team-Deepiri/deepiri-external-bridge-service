import { buildDedupeKey, resolveEventDedupeIdentity } from './consumer';

describe('kafka consumer dedupe identity', () => {
  it('prefers provider_event_id when present', () => {
    const identity = resolveEventDedupeIdentity(
      { provider: 'GitHub', provider_event_id: 'd6e7cdd0-1234' },
      'fallback-id'
    );

    expect(identity).toBe('provider:github:d6e7cdd0-1234');
  });

  it('supports numeric provider_event_id', () => {
    const identity = resolveEventDedupeIdentity(
      { provider: 'jira', provider_event_id: 12345 },
      'fallback-id'
    );

    expect(identity).toBe('provider:jira:12345');
  });

  it('falls back to event.event_id when provider_event_id is missing', () => {
    const identity = resolveEventDedupeIdentity(
      { provider: 'github', event_id: 'evt-42' },
      'fallback-id'
    );

    expect(identity).toBe('internal:evt-42');
  });

  it('falls back to message header event_id when event payload id is missing', () => {
    const identity = resolveEventDedupeIdentity(
      { provider: 'github' },
      'header-event-id'
    );

    expect(identity).toBe('internal:header-event-id');
  });

  it('builds full redis key with topic prefix', () => {
    const key = buildDedupeKey(
      'integration.webhook.received',
      { provider: 'github', provider_event_id: 'gh-delivery-1' },
      'fallback-id'
    );

    expect(key).toBe(
      'dedupe:integration.webhook.received:provider:github:gh-delivery-1'
    );
  });
});
