import { Gauge, Info, RefreshCw, TrendingDown, TrendingUp } from 'lucide-react';
import { Fragment, useEffect, useState, type ReactNode } from 'react';
import {
  PROVIDER_LABEL,
  PURPOSE_LABEL,
  type KeyCapView,
  type LimitWindowView,
  type PeriodTotals,
  type UsageDays,
  type UsageLimitsView,
  type UsageProvider,
  type UsageReport,
} from '../../../shared/usage';
import { useLive, vigil } from '../api';
import { IconButton, Segmented } from '../components/ui';
import '../styles/usage.css';
import { PageHead } from './AppShell';
import { UsageChart } from './UsageChart';
import {
  PROVIDER_COLOR,
  formatCount,
  formatDateTime,
  formatDay,
  formatHour,
  formatPercent,
  formatResetsIn,
  formatTokens,
  formatUsd,
  paceOf,
  elapsedShare,
  remainingPercent,
  type LimitPace,
} from './usage-format';

type Metric = 'cost' | 'tokens' | 'limits';
type Breakdown = 'model' | 'time' | 'task';

const METRICS: { value: Metric; label: string }[] = [
  { value: 'cost', label: 'Cost' },
  { value: 'tokens', label: 'Tokens' },
  { value: 'limits', label: 'Limits' },
];
const PERIODS: { value: `${UsageDays}`; label: string }[] = [
  { value: '1', label: 'Past 24h' },
  { value: '7', label: '7 days' },
  { value: '30', label: '30 days' },
  { value: '90', label: '90 days' },
];

const PREFS_KEY = 'vigil:usage-page:v1';
interface Prefs {
  metric: Metric;
  days: UsageDays;
}
// Limits is what most people open the page for (how much of the plan is left,
// and when it resets), so it is the first-visit default; the last pick sticks.
const DEFAULT_PREFS: Prefs = { metric: 'limits', days: 30 };

function readPrefs(): Prefs {
  try {
    const p = JSON.parse(localStorage.getItem(PREFS_KEY) ?? 'null') as Partial<Prefs> | null;
    if (
      p &&
      METRICS.some((m) => m.value === p.metric) &&
      PERIODS.some((d) => d.value === String(p.days))
    )
      return { metric: p.metric!, days: p.days! };
  } catch {
    // Fall through to the defaults.
  }
  return DEFAULT_PREFS;
}

export function UsageView() {
  const [prefs, setPrefs] = useState(readPrefs);
  const [breakdown, setBreakdown] = useState<Breakdown>('model');
  const [refreshing, setRefreshing] = useState(false);
  const { metric, days } = prefs;
  const showingLimits = metric === 'limits';
  const [report, reloadReport] = useLive(() => vigil.getUsage(days), days);
  const [limits, setLimits] = useState<UsageLimitsView>();
  // The page advances "now" on refresh rather than ticking: a live clock would
  // repaint the page for no decision-changing gain.
  const [now, setNow] = useState(() => Date.now());

  const update = (next: Prefs) => {
    setPrefs(next);
    try {
      localStorage.setItem(PREFS_KEY, JSON.stringify(next));
    } catch {
      // Preferences are a convenience.
    }
  };
  const loadLimits = async (fresh: boolean) => {
    const view = await vigil.getUsageLimits(fresh);
    setLimits(view);
    setNow(Date.now());
  };
  useEffect(() => {
    if (showingLimits) void loadLimits(false).catch((err: unknown) => console.error(err));
  }, [showingLimits]);

  const refresh = () => {
    if (refreshing) return;
    setRefreshing(true);
    const done = () => setRefreshing(false);
    if (showingLimits) void loadLimits(true).finally(done);
    else {
      reloadReport();
      setTimeout(done, 300);
    }
  };

  return (
    <div className="page usage">
      <PageHead
        title="Usage"
        purpose="What Vigil's AI work costs, and how much of your plans it leaves. Only Vigil's own runs count; your other chats are never read."
      />
      <div className="row usage-toolbar">
        <Segmented
          label="Usage metric"
          value={metric}
          options={METRICS}
          onChange={(m) => update({ metric: m, days })}
        />
        {/* The period does not apply to Limits, so it stays in place but disabled. */}
        <Segmented
          label="Usage period"
          value={`${days}`}
          options={PERIODS}
          disabled={showingLimits}
          onChange={(d) => update({ metric, days: Number(d) as UsageDays })}
        />
        <IconButton
          label={showingLimits ? 'Refresh limits' : 'Refresh usage'}
          onClick={refresh}
          disabled={refreshing}
        >
          <RefreshCw size={15} className={refreshing ? 'spin' : undefined} />
        </IconButton>
        {!showingLimits && report && (
          <span className="t-small usage-window">
            {report.resolution === 'hour'
              ? `${formatDateTime(report.since)} to ${formatDateTime(report.until)}`
              : `${formatDay(report.since)} to ${formatDay(report.until)}`}
          </span>
        )}
      </div>
      {showingLimits ? (
        limits ? (
          <LimitsSection limits={limits} now={now} />
        ) : (
          <div className="usage-skeleton" style={{ height: 180 }} />
        )
      ) : report ? (
        <CostSection
          report={report}
          metric={metric}
          breakdown={breakdown}
          setBreakdown={setBreakdown}
        />
      ) : (
        <div className="usage-skeleton" style={{ height: 320 }} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- cost and tokens

/**
 * A provider whose price is only Claude Code's estimate at API prices: priced,
 * but none of it charged to a key (the plan covers it). Local models are free,
 * not estimated.
 */
const planEstimate = (p: { costUsd: number; billedUsd: number }) =>
  p.costUsd > 0 && p.billedUsd === 0;

function CostSection({
  report,
  metric,
  breakdown,
  setBreakdown,
}: {
  report: UsageReport;
  metric: 'cost' | 'tokens';
  breakdown: Breakdown;
  setBreakdown: (b: Breakdown) => void;
}) {
  const { totals } = report;
  const hourly = report.resolution === 'hour';
  const active = report.providers.map((p) => p.provider);
  const usesBilled = totals.billedUsd > 0;

  return (
    <>
      <section className="usage-top">
        <div className="col" style={{ gap: 18 }}>
          <div className="col" style={{ gap: 4 }}>
            <span className="usage-headline num">
              {metric === 'cost' ? formatUsd(totals.costUsd) : formatTokens(totals.totalTokens)}
            </span>
            <span className="t-small row" style={{ gap: 4 }}>
              {formatCount(totals.runs)} {totals.runs === 1 ? 'run' : 'runs'}
              {metric === 'cost' && (
                <>
                  {usesBilled
                    ? ` · ${formatUsd(totals.billedUsd)} billed to your keys, the rest at API prices`
                    : ' · at API prices, nothing billed'}
                  <span
                    className="usage-info"
                    tabIndex={0}
                    title={[
                      'Claude Code reports what each run would cost at API prices; your plan is not charged per run.',
                      ...(usesBilled
                        ? [
                            'Jev, cloud API keys and Codex on an OpenAI key show what you were billed.',
                          ]
                        : []),
                      'Models on this Mac are free.',
                      ...(totals.unpricedRuns > 0
                        ? [
                            `Leaves out ${formatPercent(totals.unpricedShare)} of runs with no price (Codex on a ChatGPT plan).`,
                          ]
                        : []),
                    ].join(' ')}
                  >
                    <Info size={12} aria-label="About this estimate" />
                  </span>
                </>
              )}
            </span>
          </div>
          {report.providers.map((p) => {
            const shareOf = metric === 'cost' ? p.costShare : p.tokenShare;
            return (
              <div key={p.provider} className="col" style={{ gap: 2 }}>
                <div className="row spread" style={{ alignItems: 'baseline' }}>
                  <span className="row" style={{ gap: 8 }}>
                    <span
                      className="usage-dot"
                      style={{ background: PROVIDER_COLOR[p.provider] }}
                    />
                    <span className="usage-provider">{PROVIDER_LABEL[p.provider]}</span>
                    <span className="usage-subtle num">
                      {formatCount(p.runs)} {p.runs === 1 ? 'run' : 'runs'}
                    </span>
                  </span>
                  <span className="usage-provider-value num">
                    {metric === 'cost'
                      ? p.unpricedRuns === p.runs
                        ? 'Unpriced'
                        : p.provider === 'ollama'
                          ? 'Free'
                          : formatUsd(p.costUsd)
                      : formatTokens(p.totalTokens)}
                  </span>
                </div>
                <span className="t-small">
                  {metric === 'cost'
                    ? `${p.unpricedRuns === p.runs ? 'Unpriced' : `${formatPercent(shareOf)} of cost`} · ${formatTokens(p.totalTokens)} tokens`
                    : `${formatPercent(shareOf)} of tokens · ${p.unpricedRuns === p.runs ? 'unpriced' : formatUsd(p.costUsd)}`}
                  {metric === 'cost' && planEstimate(p) && ' · at API prices, not charged'}
                  {p.failed > 0 && (
                    <span
                      className="usage-failed"
                      title="Runs that timed out or failed. They used no tokens that Vigil saw. A local model too big for this Mac often times out."
                    >
                      {' · '}
                      {formatCount(p.failed)} failed
                    </span>
                  )}
                </span>
              </div>
            );
          })}
          {report.providers.length === 0 && (
            <span className="t-small">Vigil hasn’t asked an AI anything in this window.</span>
          )}
        </div>
        <div className="col" style={{ gap: 10 }}>
          <h2 className="t-h3">
            {hourly ? 'Hourly' : 'Daily'} {metric === 'tokens' ? 'processed tokens' : 'cost'}
          </h2>
          <UsageChart
            providers={active}
            periods={report.periods}
            metric={metric}
            resolution={report.resolution}
          />
        </div>
      </section>

      <section className="col" style={{ gap: 6 }}>
        <h2 className="t-h3">Totals</h2>
        <div className="usage-totals">
          <Metric label="Processed tokens" value={formatTokens(totals.totalTokens)} />
          <Metric label="Cached input" value={formatTokens(totals.cachedInputTokens)} />
          <Metric label="Uncached input" value={formatTokens(totals.inputTokens)} />
          <Metric label="Output" value={formatTokens(totals.outputTokens)} />
          <Metric label="Billed to your keys" value={formatUsd(totals.billedUsd)} />
        </div>
      </section>

      <section className="col" style={{ gap: 8 }}>
        <div className="row spread">
          <h2 className="t-h3">Breakdown</h2>
          <Segmented
            label="Usage breakdown"
            value={breakdown}
            options={[
              { value: 'model', label: 'Model' },
              { value: 'task', label: 'Task' },
              { value: 'time', label: hourly ? 'Hour' : 'Day' },
            ]}
            onChange={setBreakdown}
          />
        </div>
        {breakdown === 'time' ? (
          <TimeTable report={report} />
        ) : (
          <table className="usage-table">
            <colgroup>
              <col style={{ width: '40%' }} />
              <col style={{ width: '20%' }} />
              <col style={{ width: '20%' }} />
              <col style={{ width: '20%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>{breakdown === 'model' ? 'Model' : 'Task'}</th>
                <th>Cost</th>
                <th>Share</th>
                <th>Tokens</th>
              </tr>
            </thead>
            <tbody>
              {(breakdown === 'model'
                ? (metric === 'tokens'
                    ? [...report.models].sort((a, b) => b.totalTokens - a.totalTokens)
                    : report.models
                  ).map((m) => ({
                    key: `${m.provider}:${m.model}`,
                    label: (
                      <span className="row" style={{ gap: 8 }}>
                        <span
                          className="usage-dot"
                          style={{ background: PROVIDER_COLOR[m.provider] }}
                        />
                        {m.model || PROVIDER_LABEL[m.provider]}
                      </span>
                    ),
                    priced: m.priced,
                    costUsd: m.costUsd,
                    costShare: m.costShare,
                    tokens: m.totalTokens,
                  }))
                : report.purposes.map((p) => ({
                    key: p.purpose,
                    label: <>{PURPOSE_LABEL[p.purpose]}</>,
                    priced: p.unpricedRuns < p.runs,
                    costUsd: p.costUsd,
                    costShare: p.costShare,
                    tokens: p.totalTokens,
                  }))
              ).map((row) => (
                <tr key={row.key}>
                  <td>{row.label}</td>
                  <td className="num">
                    {row.priced ? formatUsd(row.costUsd) : <span className="muted">Unpriced</span>}
                  </td>
                  <td className="num muted">{row.priced ? formatPercent(row.costShare) : '—'}</td>
                  <td className="num muted">{formatTokens(row.tokens)}</td>
                </tr>
              ))}
              {report.models.length === 0 && <EmptyRow span={4} />}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}

function TimeTable({ report }: { report: UsageReport }) {
  const hourly = report.resolution === 'hour';
  const providers = report.providers.map((p) => p.provider);
  // Newest first: the window can run 90 periods, so the interesting end belongs at the top.
  const rows = report.periods.filter((p) => p.totalTokens > 0 || p.costUsd > 0).reverse();
  const width = `${60 / (providers.length + 2)}%`;
  const label = (p: PeriodTotals) => (hourly ? formatHour(p.start) : formatDay(p.start));
  return (
    <table className="usage-table">
      <colgroup>
        <col style={{ width: '40%' }} />
        {[...providers, 'total', 'tokens'].map((k) => (
          <col key={k} style={{ width }} />
        ))}
      </colgroup>
      <thead>
        <tr>
          <th>{hourly ? 'Hour' : 'Day'}</th>
          {providers.map((p) => (
            <th key={p}>{PROVIDER_LABEL[p]}</th>
          ))}
          <th>Total</th>
          <th>Tokens</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((p) => (
          <tr key={p.start}>
            <td>{label(p)}</td>
            {providers.map((provider) => (
              <td key={provider} className="num muted">
                {formatUsd(p.byProvider[provider]?.costUsd ?? 0)}
              </td>
            ))}
            <td className="num">{formatUsd(p.costUsd)}</td>
            <td className="num muted">{formatTokens(p.totalTokens)}</td>
          </tr>
        ))}
        {rows.length === 0 && <EmptyRow span={providers.length + 3} />}
      </tbody>
    </table>
  );
}

function EmptyRow({ span }: { span: number }) {
  return (
    <tr>
      <td colSpan={span} className="usage-empty">
        No activity in this window.
      </td>
    </tr>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="col" style={{ gap: 2 }}>
      <span className="t-small">{label}</span>
      <span className="usage-metric num">{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------- limits

const PACE: Record<LimitPace, { label: string; icon: ReactNode }> = {
  ahead: {
    label: 'Ahead of pace: spending faster than the window elapses',
    icon: <TrendingUp size={14} />,
  },
  on: { label: 'On pace with the window', icon: <Gauge size={14} /> },
  under: {
    label: 'Under pace: headroom left for the rest of the window',
    icon: <TrendingDown size={14} />,
  },
};

function LimitsSection({ limits, now }: { limits: UsageLimitsView; now: number }) {
  if (limits.plans.length === 0 && limits.keys.length === 0) {
    return (
      <p className="t-small">
        No plan limits to show yet. They appear once Vigil runs on Claude Code or Codex, and
        spending on Jev or a cloud API key shows here once Vigil uses it.
      </p>
    );
  }
  return (
    <div className="col" style={{ gap: 24 }}>
      {limits.plans.map((plan) => (
        <section key={plan.provider} className="col" style={{ gap: 10 }}>
          <h2 className="t-h3 row" style={{ gap: 8 }}>
            <span className="usage-dot" style={{ background: PROVIDER_COLOR[plan.provider] }} />
            {PROVIDER_LABEL[plan.provider]}
            {plan.plan && <span className="usage-plan">{plan.plan}</span>}
          </h2>
          <div className="usage-limit-grid">
            {plan.windows.map((w) => (
              <LimitRow key={w.id} window={w} color={PROVIDER_COLOR[plan.provider]} now={now} />
            ))}
          </div>
        </section>
      ))}
      {limits.backgroundSharePercent !== undefined && limits.plans.length > 0 && (
        <p className="t-small" style={{ margin: 0 }}>
          Background work stops at {limits.backgroundSharePercent}% of each window, so Vigil leaves
          the rest for you. Explaining a block never waits.
        </p>
      )}
      {(limits.keys.length > 0 || limits.cap) && (
        <section className="col" style={{ gap: 10 }}>
          <h2 className="t-h3">API keys this month</h2>
          <div className="usage-limit-grid">
            {limits.cap && <KeyCapRow cap={limits.cap} />}
            {limits.keys.map((k) => (
              <Fragment key={k.provider}>
                <span className="row spread usage-limit-label">
                  <span className="row" style={{ gap: 8 }}>
                    <span
                      className="usage-dot"
                      style={{ background: PROVIDER_COLOR[k.provider] }}
                    />
                    <span className="muted">
                      {KEY_LABEL[k.provider] ?? PROVIDER_LABEL[k.provider]}
                    </span>
                  </span>
                  <span className="num">{formatUsd(k.spentUsd)}</span>
                </span>
                <span className="t-small num usage-limit-side">
                  {`${formatCount(k.runs)} ${k.runs === 1 ? 'run' : 'runs'}`}
                </span>
              </Fragment>
            ))}
            {!limits.cap && <span className="t-small">No monthly cap</span>}
          </div>
        </section>
      )}
      <span className="t-small">Checked {formatDateTime(limits.checkedAt)}</span>
    </div>
  );
}

const KEY_LABEL: Partial<Record<UsageProvider, string>> = {
  claude: 'Claude (Anthropic key)',
  codex: 'Codex (OpenAI key)',
};

/** The one monthly cap, shared by every key, as a bar of what's left. */
function KeyCapRow({ cap }: { cap: KeyCapView }) {
  const used = cap.capUsd > 0 ? Math.min(100, (cap.spentUsd / cap.capUsd) * 100) : 100;
  return (
    <>
      <span className="row spread usage-limit-label">
        <span className="muted">All keys together</span>
        <span className="num">{`${formatUsd(Math.max(0, cap.capUsd - cap.spentUsd))} left`}</span>
      </span>
      <div
        className="usage-bar"
        role="img"
        aria-label={`${formatUsd(cap.spentUsd)} of ${formatUsd(cap.capUsd)} this month`}
        title={`${formatUsd(cap.spentUsd)} of your ${formatUsd(cap.capUsd)} monthly cap`}
      >
        <div className="usage-bar-track" />
        <div
          className="usage-bar-fill"
          style={{ width: `${100 - used}%`, background: 'var(--ac)' }}
        />
      </div>
      <span className="t-small num usage-limit-side">
        {`${formatUsd(cap.spentUsd)} of ${formatUsd(cap.capUsd)}`}
      </span>
    </>
  );
}

/**
 * One window as a full-width bar. The fill is the quota left; the hairline is
 * the time left in the window, which is where even spending would put the fill.
 */
function LimitRow({
  window: w,
  color,
  now,
}: {
  window: LimitWindowView;
  color: string;
  now: number;
}) {
  const remaining = remainingPercent(w);
  const elapsed = elapsedShare(w, now);
  const timeLeft = elapsed === null ? null : Math.round((1 - elapsed) * 100);
  const pace = paceOf(w, now);
  const resetsIn = formatResetsIn(w, now);
  const vigil = Math.round(w.vigilPercent);
  const summary = [
    `${remaining}% left`,
    ...(timeLeft !== null ? [`${timeLeft}% of the window left`] : []),
    `Vigil used ${vigil}% of it`,
    ...(w.resetsAt !== undefined ? [`resets ${formatDateTime(w.resetsAt)}`] : []),
  ].join(' · ');
  return (
    <>
      <span className="row spread usage-limit-label">
        <span className="muted">{w.label}</span>
        <span className="num">{remaining}% left</span>
      </span>
      <div className="usage-bar" role="img" aria-label={`${w.label}: ${summary}`} title={summary}>
        <div className="usage-bar-track" />
        {remaining > 0 && (
          <div className="usage-bar-fill" style={{ width: `${remaining}%`, background: color }} />
        )}
        {timeLeft !== null && <span className="usage-bar-pace" style={{ left: `${timeLeft}%` }} />}
      </div>
      <span className="row usage-limit-side t-small num">
        {pace && (
          <span
            className="usage-pace"
            role="img"
            aria-label={PACE[pace].label}
            title={PACE[pace].label}
          >
            {PACE[pace].icon}
          </span>
        )}
        <span className="usage-vigil" title="The part Vigil used, as far as Vigil has seen">
          Vigil {vigil}%
        </span>
        <span className="grow" />
        <span>{resetsIn ?? ''}</span>
      </span>
    </>
  );
}
