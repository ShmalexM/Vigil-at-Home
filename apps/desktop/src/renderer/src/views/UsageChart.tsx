import { useMemo, useRef, useState } from 'react';
import {
  PROVIDER_LABEL,
  USAGE_PROVIDERS,
  type PeriodTotals,
  type UsageProvider,
} from '../../../shared/usage';
import {
  PROVIDER_COLOR,
  formatDay,
  formatHour,
  formatTokens,
  formatUsd,
  niceScale,
} from './usage-format';

const VIEW_WIDTH = 960;
const VIEW_HEIGHT = 260;
const TICK_COUNT = 4;
const PLOT_TOP = 8;

export type ChartMetric = 'cost' | 'tokens';

interface Point {
  x: number;
  y: number;
}

/** Shape-preserving cubic tangents that cannot overshoot spiky usage data. */
function monotoneTangents(points: readonly Point[]): number[] {
  const count = points.length;
  if (count < 2) return [0];
  const slopes: number[] = [];
  for (let i = 0; i < count - 1; i++) {
    const dx = points[i + 1]!.x - points[i]!.x;
    const dy = points[i + 1]!.y - points[i]!.y;
    slopes.push(dx === 0 ? 0 : dy / dx);
  }
  const t: number[] = Array.from({ length: count }, () => 0);
  t[0] = slopes[0]!;
  t[count - 1] = slopes[count - 2]!;
  for (let i = 1; i < count - 1; i++) {
    const prev = slopes[i - 1]!;
    const next = slopes[i]!;
    t[i] = prev * next <= 0 ? 0 : (prev + next) / 2;
  }
  for (let i = 0; i < count - 1; i++) {
    const slope = slopes[i]!;
    if (slope === 0) {
      t[i] = 0;
      t[i + 1] = 0;
      continue;
    }
    const a = t[i]! / slope;
    const b = t[i + 1]! / slope;
    const magnitude = a * a + b * b;
    if (magnitude > 9) {
      const scale = 3 / Math.sqrt(magnitude);
      t[i] = scale * a * slope;
      t[i + 1] = scale * b * slope;
    }
  }
  return t;
}

function curvePath(points: readonly Point[]): string {
  if (points.length < 2) return '';
  const t = monotoneTangents(points);
  const f = (n: number) => n.toFixed(2);
  let path = `M${f(points[0]!.x)},${f(points[0]!.y)}`;
  for (let i = 0; i < points.length - 1; i++) {
    const from = points[i]!;
    const to = points[i + 1]!;
    const dx = to.x - from.x;
    path += ` C${f(from.x + dx / 3)},${f(from.y + (t[i]! * dx) / 3)} ${f(to.x - dx / 3)},${f(to.y - (t[i + 1]! * dx) / 3)} ${f(to.x)},${f(to.y)}`;
  }
  return path;
}

const valueOf = (p: PeriodTotals, provider: UsageProvider, metric: ChartMetric) => {
  const slot = p.byProvider[provider];
  return slot ? (metric === 'cost' ? slot.costUsd : slot.totalTokens) : 0;
};

/**
 * One line per provider over the window, each measured from zero, with a
 * hover readout. Mirrors T3 Code's usage chart.
 */
export function UsageChart({
  providers,
  periods,
  metric,
  resolution,
}: {
  providers: readonly UsageProvider[];
  periods: readonly PeriodTotals[];
  metric: ChartMetric;
  resolution: 'day' | 'hour';
}) {
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null);
  const plotRef = useRef<HTMLDivElement>(null);
  const format = metric === 'tokens' ? formatTokens : formatUsd;
  const formatPeriod = resolution === 'hour' ? formatHour : formatDay;

  const { paths, ticks, stepX, toY } = useMemo(() => {
    // The scale tops out at the largest single provider-period, not the sum:
    // the lines each start at zero, so a combined peak would leave the plot half empty.
    const peak = Math.max(
      0,
      ...periods.flatMap((p) => providers.map((provider) => valueOf(p, provider, metric))),
    );
    const { max, ticks } = niceScale(peak, TICK_COUNT);
    const step = periods.length <= 1 ? 0 : VIEW_WIDTH / (periods.length - 1);
    const toY = (v: number) =>
      max === 0 ? VIEW_HEIGHT : VIEW_HEIGHT - (v / max) * (VIEW_HEIGHT - PLOT_TOP);
    const built = providers.map((provider) => {
      const values = periods.map((p) => valueOf(p, provider, metric));
      const line = curvePath(values.map((v, i) => ({ x: i * step, y: toY(v) })));
      return {
        provider,
        total: values.reduce((a, b) => a + b, 0),
        line,
        area: line && `${line} L${VIEW_WIDTH},${VIEW_HEIGHT} L0,${VIEW_HEIGHT} Z`,
      };
    });
    // Heavier series first, so the lighter one is not buried.
    return { paths: built.sort((a, b) => b.total - a.total), ticks, stepX: step, toY };
  }, [metric, periods, providers]);

  const hovered = hover ? periods[hover.index] : undefined;
  const mid = periods[Math.floor(periods.length / 2)];
  const first = periods[0];
  const last = periods[periods.length - 1];

  return (
    <div className="col usage-chart" style={{ gap: 4 }}>
      <div className="row" style={{ gap: 8, alignItems: 'stretch' }}>
        <div className="usage-chart-axis">
          {ticks.map((tick) => (
            <span key={tick} style={{ top: `${(toY(tick) / VIEW_HEIGHT) * 100}%` }}>
              {tick === 0 ? '0' : format(tick)}
            </span>
          ))}
        </div>
        <div
          ref={plotRef}
          className="usage-chart-plot"
          onMouseMove={(e) => {
            const b = plotRef.current?.getBoundingClientRect();
            if (!b || b.width === 0 || periods.length === 0) return;
            const x = Math.min(b.width, Math.max(0, e.clientX - b.left));
            const y = Math.min(b.height, Math.max(0, e.clientY - b.top));
            const index = Math.round((x / b.width) * (periods.length - 1));
            setHover({ index: Math.min(periods.length - 1, Math.max(0, index)), x, y });
          }}
          onMouseLeave={() => setHover(null)}
        >
          <svg
            viewBox={`0 0 ${VIEW_WIDTH} ${VIEW_HEIGHT}`}
            preserveAspectRatio="none"
            role="img"
            aria-label={`${resolution === 'hour' ? 'Hourly' : 'Daily'} ${metric === 'tokens' ? 'processed tokens' : 'cost'} by provider`}
          >
            {ticks.map((tick) => (
              <line
                key={tick}
                x1={0}
                x2={VIEW_WIDTH}
                y1={toY(tick)}
                y2={toY(tick)}
                stroke="var(--ln1)"
                strokeWidth={1}
                vectorEffect="non-scaling-stroke"
              />
            ))}
            {/* Fills first, then every stroke, so no series covers another's line. */}
            {paths.map(({ provider, area }) => (
              <path key={provider} d={area} fill={PROVIDER_COLOR[provider]} fillOpacity={0.12} />
            ))}
            {paths.map(({ provider, line }) => (
              <path
                key={provider}
                d={line}
                fill="none"
                stroke={PROVIDER_COLOR[provider]}
                strokeWidth={2}
                vectorEffect="non-scaling-stroke"
              />
            ))}
            {hover && (
              <line
                x1={hover.index * stepX}
                x2={hover.index * stepX}
                y1={PLOT_TOP}
                y2={VIEW_HEIGHT}
                stroke="var(--tx3)"
                strokeWidth={1}
                vectorEffect="non-scaling-stroke"
              />
            )}
          </svg>
          {hover && hovered && (
            <div
              className="usage-tooltip"
              style={
                hover.x > (plotRef.current?.clientWidth ?? 0) / 2
                  ? { right: `calc(100% - ${hover.x - 12}px)`, top: hover.y }
                  : { left: hover.x + 12, top: hover.y }
              }
            >
              <div className="muted">{formatPeriod(hovered.start)}</div>
              {USAGE_PROVIDERS.filter((p) => providers.includes(p)).map((provider) => (
                <div key={provider} className="row spread">
                  <span className="row" style={{ gap: 6 }}>
                    <span className="usage-dot" style={{ background: PROVIDER_COLOR[provider] }} />
                    <span className="muted">{PROVIDER_LABEL[provider]}</span>
                  </span>
                  <span className="num">{format(valueOf(hovered, provider, metric))}</span>
                </div>
              ))}
              <div className="row spread usage-tooltip-total">
                <span className="muted">Total</span>
                <span className="num">
                  {format(metric === 'cost' ? hovered.costUsd : hovered.totalTokens)}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
      <div className="row spread usage-chart-x">
        <span>{first ? formatPeriod(first.start) : ''}</span>
        <span>{mid ? formatPeriod(mid.start) : ''}</span>
        <span>{last ? formatPeriod(last.start) : ''}</span>
      </div>
    </div>
  );
}
