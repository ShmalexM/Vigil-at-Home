import { beforeEach, describe, expect, it, vi } from 'vitest';

const sayToLead = vi.fn();
vi.mock('./api', () => ({ vigil: { sayToLead: (...a: unknown[]) => sayToLead(...a) } }));
const { leadChat, leadChatState, resetLeadChat } = await import('./lead-chat');
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
