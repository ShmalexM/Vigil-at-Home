import { beforeEach, describe, expect, it, vi } from 'vitest';

const sayToLead = vi.fn();
vi.mock('./api', () => ({ vigil: { sayToLead: (...a: unknown[]) => sayToLead(...a) } }));
const { STARTERS, contextStarter, leadChat, leadChatState, resetLeadChat } =
  await import('./lead-chat');
const snapshot = async () => leadChatState();

describe('the Lead dog chat box', () => {
  beforeEach(() => {
    resetLeadChat();
    sayToLead.mockReset();
  });

  it('sends with where the person is, and empties the box', async () => {
    sayToLead.mockResolvedValue({ ok: true });
    leadChat.setDraft('what is this?');
    const ok = await leadChat.send('what is this?', {
      noAi: false,
      context: { page: 'alerts', selected: 'a1' },
    });
    expect(ok).toBe(true);
    expect(sayToLead).toHaveBeenCalledWith('what is this?', { page: 'alerts', selected: 'a1' });
    expect(await snapshot()).toMatchObject({ draft: '', sending: false, error: null });
  });

  it('puts the words back and says why when the send fails', async () => {
    sayToLead.mockResolvedValue({ ok: false, error: 'The Lead dog is still answering' });
    leadChat.setDraft('hello');
    expect(await leadChat.send('hello', { noAi: false })).toBe(false);
    expect(await snapshot()).toMatchObject({
      draft: 'hello',
      error: 'Not sent: The Lead dog is still answering',
    });

    sayToLead.mockRejectedValue(new Error('IPC closed'));
    expect(await leadChat.send('hello', { noAi: false })).toBe(false);
    expect(await snapshot()).toMatchObject({ draft: 'hello', error: 'Not sent: IPC closed' });
  });

  it('sends nothing when no AI is set up, and keeps the draft', async () => {
    leadChat.setDraft('hello');
    expect(await leadChat.send('hello', { noAi: true })).toBe(false);
    expect(sayToLead).not.toHaveBeenCalled();
    expect((await snapshot()).draft).toBe('hello');
  });

  it('keeps the draft and open state across pages (outside React)', async () => {
    leadChat.open();
    leadChat.setDraft('half written');
    expect(await snapshot()).toMatchObject({ open: true, draft: 'half written' });
    leadChat.close();
    expect((await snapshot()).open).toBe(false);
  });
});

describe('the starter questions', () => {
  it('asks about what is open, and never calls an Activity filter an event', () => {
    expect(contextStarter({ page: 'alerts', selected: 'a1' })).toBe('What’s this alert?');
    expect(contextStarter({ page: 'rules', selected: 'r1' })).toBe('What’s this rule?');
    expect(contextStarter({ page: 'agents', selected: 'claude-code' })).toBe(
      'What has this agent done?',
    );
    expect(contextStarter({ page: 'agents', selected: 'claude-code_0123456789abcdef' })).toBe(
      'What happened in this session?',
    );
    expect(contextStarter({ page: 'activity', selected: 'agent-codex' })).toBe(
      'What has this agent done?',
    );
    expect(contextStarter({ page: 'activity', selected: 'session-0123456789abcdef' })).toBe(
      'What happened in this session?',
    );
    expect(contextStarter({ page: 'activity', selected: 'e1' })).toBeUndefined();
    expect(contextStarter({ page: 'home' })).toBeUndefined();
    expect(STARTERS[0]).toBe('Is my Mac OK right now?');
  });
});
