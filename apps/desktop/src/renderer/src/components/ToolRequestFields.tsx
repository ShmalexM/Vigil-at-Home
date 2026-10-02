import type { AgentToolRequestEvent } from '@vigil/core';
import { Bot } from 'lucide-react';
import type { ReactNode } from 'react';
import { toolRequestRows } from '../evidence';
import { agentRoute, VIGIL_CONNECTOR, VIGIL_SELF } from '../views/agents-format';
import type { AgentLinks } from '../views/Activity';
import { Chip } from './ui';

/** Which agent an event ran under, with a link to its session when there is a page for it. */
export function AgentField({
  id,
  session,
  links,
}: {
  id: string;
  session?: string | undefined;
  links: AgentLinks;
}) {
  const own = id === VIGIL_SELF;
  // Pack connectors have no page on Agents; the Pack page lists them.
  const linked = !own && id !== VIGIL_CONNECTOR;
  return (
    <span className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
      <Chip tone={own ? 'ai' : 'accent'}>
        <Bot size={12} />
        {links.nameOf(id)}
      </Chip>
      {session && linked && links.go && (
        <button
          type="button"
          className="more-link"
          onClick={() => links.go?.(agentRoute(id, session))}
        >
          Open this session
        </button>
      )}
    </span>
  );
}

/** A tool request's details as label and value pairs, for Activity's fields and an alert's evidence. */
export function toolRequestFields(
  e: AgentToolRequestEvent,
  links: AgentLinks,
): [string, ReactNode][] {
  return toolRequestRows(e).map((r) => [
    r.label,
    'code' in r ? (
      <code key={r.label}>{r.code}</code>
    ) : 'agent' in r ? (
      <AgentField key={r.label} id={r.agent.id} session={r.agent.session} links={links} />
    ) : (
      r.text
    ),
  ]);
}
