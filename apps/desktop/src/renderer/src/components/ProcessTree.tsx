import { Bot, CornerDownRight } from 'lucide-react';
import type { CSSProperties } from 'react';
import type { TreeNode } from '../../../shared/agents';
import { timeOfDay } from '../format';
import { treeRows } from '../views/agents-format';
import { Chip } from './ui';

/** Main sends at most this many processes of one session. */
const MAX_NODES = 200;

/**
 * What one agent session started: the agent first, then each program under
 * the one that launched it, indented by how far down the tree it ran.
 * Programs one of whose events matched a rule are marked.
 */
export function ProcessTree({ nodes }: { nodes: readonly TreeNode[] }) {
  const rows = treeRows(nodes);
  if (rows.length === 0) return <span className="t-small">No programs recorded yet.</span>;
  return (
    <div className="col" style={{ gap: 6 }}>
      <ol className="ptree" aria-label="Programs this session started">
        {rows.map(({ node: n, parent }, i) => (
          <li
            key={`${n.pid}-${n.ts}-${i}`}
            className={`ptree-row ${n.matched ? 'matched' : ''}`}
            style={{ '--depth': Math.min(n.depth, 12) } as CSSProperties}
          >
            <span className="ptree-glyph" aria-hidden>
              {n.depth === 0 ? <Bot size={14} /> : <CornerDownRight size={13} />}
            </span>
            {/* The indent shows who started what; this says it. */}
            <span className="sr-only">
              {parent ? `Started by ${parent.name}: ` : 'The agent: '}
            </span>
            <span className="ptree-name mono" title={n.path}>
              {n.name}
            </span>
            <span className="t-small ellipsis grow ptree-path" title={n.path}>
              {n.path}
            </span>
            {n.matched && <Chip tone="fair">Matched a rule</Chip>}
            <span className="t-small nowrap ptree-meta">
              {n.pid > 0 ? `pid ${n.pid} · ` : ''}
              {timeOfDay(n.ts)}
            </span>
          </li>
        ))}
      </ol>
      {nodes.length >= MAX_NODES && (
        <span className="t-small">
          Showing the first {MAX_NODES} programs this session started. Its newest events are listed
          below.
        </span>
      )}
    </div>
  );
}
