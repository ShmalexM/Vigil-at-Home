// The pack's dogs, drawn from simple shapes so every breed is original art
// (Apache-2.0 like the rest of the app; no third-party images). One side-on
// drawing is shaped per breed by a handful of numbers: leg length, body
// length, ear and tail style, coat and markings. Moods move parts of it with
// CSS transforms only (styles/pack.css), and nothing moves when the system
// asks for reduced motion.

import { useId, type CSSProperties } from 'react';
import type { Breed, DogMood } from '../../../shared/pack';

type Ear = 'pointy' | 'big' | 'floppy' | 'long';
type Tail = 'saber' | 'curl' | 'stub' | 'plume' | 'whip' | 'fluff';

interface Look {
  coat: string;
  /** Far legs and shading. */
  shade: string;
  /** Chest, belly, paws and muzzle where the breed has them. */
  light?: string;
  /** A darker patch over the back (shepherd, beagle). */
  saddle?: string;
  muzzle?: string;
  /** Head colour when it differs from the coat (beagle). */
  head?: string;
  /** Tan points: brows, muzzle, chest and lower legs (doberman). */
  points?: string;
  /** Husky: pale lower face under a coat-coloured cap. */
  mask?: boolean;
  ear: Ear;
  earColor?: string;
  tail: Tail;
  tailTip?: string;
  eye?: string;
  legH: number;
  bodyW: number;
  bodyH: number;
  headR: number;
  snout: number;
  eyeR?: number;
}

const LOOKS: Record<Breed, Look> = {
  shepherd: {
    coat: '#c98a45',
    shade: '#9a6430',
    saddle: '#2a2320',
    muzzle: '#2a2320',
    earColor: '#2a2320',
    ear: 'pointy',
    tail: 'saber',
    legH: 22,
    bodyW: 50,
    bodyH: 24,
    headR: 12.5,
    snout: 11,
  },
  doberman: {
    coat: '#2b2427',
    shade: '#1a1517',
    points: '#b8672e',
    ear: 'pointy',
    tail: 'stub',
    legH: 27,
    bodyW: 46,
    bodyH: 20,
    headR: 11.5,
    snout: 13,
  },
  husky: {
    // Black and white with blue eyes, like the logo's Scout.
    coat: '#26252a',
    shade: '#18171b',
    light: '#f6f5f1',
    mask: true,
    ear: 'pointy',
    tail: 'curl',
    tailTip: '#f6f5f1',
    eye: '#8ed1f7',
    legH: 22,
    bodyW: 48,
    bodyH: 24,
    headR: 13,
    snout: 10,
  },
  dachshund: {
    coat: '#94512a',
    shade: '#6c3a1d',
    muzzle: '#7f4321',
    earColor: '#6c3a1d',
    ear: 'long',
    tail: 'whip',
    legH: 9,
    bodyW: 64,
    bodyH: 20,
    headR: 11,
    snout: 14,
  },
  chihuahua: {
    coat: '#ebc690',
    shade: '#c99c62',
    light: '#f8e8cf',
    ear: 'big',
    earColor: '#ebc690',
    tail: 'curl',
    legH: 13,
    bodyW: 28,
    bodyH: 17,
    headR: 13,
    snout: 5,
    eyeR: 3.1,
  },
  corgi: {
    coat: '#db8430',
    shade: '#b0631c',
    light: '#fbf4ea',
    ear: 'pointy',
    tail: 'fluff',
    legH: 9,
    bodyW: 52,
    bodyH: 23,
    headR: 13,
    snout: 9,
  },
  golden: {
    coat: '#e2ad5f',
    shade: '#bd8740',
    earColor: '#c98f45',
    ear: 'floppy',
    tail: 'plume',
    legH: 22,
    bodyW: 50,
    bodyH: 25,
    headR: 13,
    snout: 11,
  },
  beagle: {
    coat: '#f5f0e7',
    shade: '#d8d0c2',
    saddle: '#2c2422',
    head: '#a65d2c',
    muzzle: '#f5f0e7',
    earColor: '#7d4120',
    ear: 'long',
    tail: 'whip',
    tailTip: '#f5f0e7',
    legH: 16,
    bodyW: 44,
    bodyH: 21,
    headR: 12,
    snout: 10,
  },
};

export const BREEDS: readonly { id: Breed; name: string; blurb: string }[] = [
  { id: 'husky', name: 'Husky', blurb: 'Tireless and watchful, leads well' },
  { id: 'shepherd', name: 'German Shepherd', blurb: 'Steady, loyal, guards the yard' },
  { id: 'doberman', name: 'Doberman', blurb: 'Alert guard, quick to spot trouble' },
  { id: 'golden', name: 'Golden Retriever', blurb: 'Fetches anything you ask for' },
  { id: 'beagle', name: 'Beagle', blurb: 'Follows a scent through the logs' },
  { id: 'corgi', name: 'Corgi', blurb: 'Small legs, big opinions' },
  { id: 'dachshund', name: 'Dachshund', blurb: 'Digs into the details' },
  { id: 'chihuahua', name: 'Chihuahua', blurb: 'Tiny, loud, misses nothing' },
];

export const breedName = (b: Breed) => BREEDS.find((x) => x.id === b)?.name ?? b;

const GROUND = 96;
const W = 128;
const NOSE = '#1c1716';

/** Moods that walk: the legs trot and the body bobs. */
const TROTS: readonly DogMood[] = ['sniffing', 'fetching'];

export function Dog({
  breed,
  mood = 'idle',
  size = 96,
  title,
  className = '',
}: {
  breed: Breed;
  mood?: DogMood;
  size?: number;
  /** Spoken name, for a dog shown on its own. Without one the dog is hidden from screen readers. */
  title?: string;
  className?: string;
}) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, '');
  const L = LOOKS[breed];
  const { legH, bodyW, bodyH, headR: r, snout } = L;

  // Lay the dog out, then shift it so it sits in the middle of the box.
  const bodyTop = GROUND - legH - bodyH;
  const raw0 = 0;
  const hx0 = raw0 + bodyW - 3;
  const left = raw0 - (L.tail === 'saber' || L.tail === 'plume' ? 20 : 14);
  const right = hx0 + r + snout + 3;
  const bx = (W - (right - left)) / 2 - left;
  const hx = bx + bodyW - 3;
  const hy = bodyTop - r * 0.32 - (legH > 20 ? 4 : 0);
  const lw = Math.max(5, Math.min(8, bodyH * 0.32));
  const legTop = bodyTop + bodyH * 0.5;
  const backX = bx + bodyH * 0.32;
  const frontX = bx + bodyW - bodyH * 0.32 - lw;
  const snoutTop = hy - r * 0.05;
  const snoutH = r * 0.78;
  const tipX = hx + r * 0.55 + snout;
  const eyeX = hx + r * 0.32;
  const eyeY = hy - r * 0.3;
  const eyeR = L.eyeR ?? 2.2;
  const tailX = bx + 3;
  const tailY = bodyTop + bodyH * 0.28;
  const headFill = L.head ?? L.coat;
  const sit = Math.max(4, legH * 0.72);

  const leg = (x: number, near: boolean, cls: string) => (
    <g className={`dog-leg ${cls}`} style={{ transformOrigin: `${x + lw / 2}px ${legTop + 2}px` }}>
      <rect
        x={x}
        y={legTop}
        width={lw}
        height={GROUND - legTop}
        rx={lw / 2}
        fill={near ? L.coat : L.shade}
      />
      {(L.points || L.light) && (
        <rect
          x={x}
          y={GROUND - Math.min(7, legH * 0.45)}
          width={lw}
          height={Math.min(7, legH * 0.45)}
          rx={lw / 2}
          fill={near ? (L.points ?? L.light) : shadeOf(L.points ?? L.light!)}
        />
      )}
      <ellipse
        cx={x + lw / 2 + 1}
        cy={GROUND - 1}
        rx={lw / 2 + 1.4}
        ry={2}
        fill={near ? (L.points ?? L.light ?? L.coat) : shadeOf(L.points ?? L.light ?? L.coat)}
      />
    </g>
  );

  const style = {
    width: size,
    height: (size * 104) / W,
    '--sit': `${sit}px`,
  } as CSSProperties;

  return (
    <svg
      viewBox={`0 0 ${W} 104`}
      className={`dog mood-${mood} ${TROTS.includes(mood) ? 'trots' : ''} ${className}`}
      style={style}
      // Decorative unless titled: a name or label always sits beside it.
      {...(title ? { role: 'img', 'aria-label': title } : { 'aria-hidden': true })}
    >
      <defs>
        <clipPath id={`body${uid}`}>
          <rect x={bx} y={bodyTop} width={bodyW} height={bodyH} rx={bodyH / 2} />
        </clipPath>
        <clipPath id={`head${uid}`}>
          <circle cx={hx} cy={hy} r={r} />
        </clipPath>
      </defs>
      <ellipse className="dog-shadow" cx={W / 2} cy={GROUND + 3} rx={bodyW * 0.62} ry={3} />
      <g className="dog-all">
        <g className="dog-tail" style={{ transformOrigin: `${tailX}px ${tailY}px` }}>
          <TailShape kind={L.tail} x={tailX} y={tailY} fill={L.saddle ?? L.coat} tip={L.tailTip} />
        </g>
        <g className="dog-legs-far">
          {leg(backX + 4, false, 'leg-b')}
          {leg(frontX + 4, false, 'leg-a')}
        </g>
        <g className="dog-torso" style={{ transformOrigin: `${bx + bodyW / 2}px ${GROUND}px` }}>
          {/* Neck: joins the body's front to the head. */}
          <path
            d={`M${bx + bodyW - bodyH * 0.95} ${bodyTop + 2} L${hx - r * 0.75} ${hy - r * 0.1} L${
              hx + r * 0.45
            } ${hy + r * 0.55} L${bx + bodyW - 1} ${bodyTop + bodyH * 0.7} Z`}
            fill={L.coat}
          />
          <rect x={bx} y={bodyTop} width={bodyW} height={bodyH} rx={bodyH / 2} fill={L.coat} />
          <g clipPath={`url(#body${uid})`}>
            {L.saddle && (
              <rect
                x={bx + bodyH * 0.2}
                y={bodyTop - 2}
                width={bodyW * 0.68}
                height={bodyH * 0.55}
                rx={bodyH * 0.3}
                fill={L.saddle}
              />
            )}
            {L.light && (
              <ellipse
                cx={bx + bodyW * 0.62}
                cy={bodyTop + bodyH + 1}
                rx={bodyW * 0.42}
                ry={bodyH * 0.38}
                fill={L.light}
              />
            )}
            {L.points && (
              <ellipse
                cx={bx + bodyW - 3}
                cy={bodyTop + bodyH * 0.55}
                rx={4.5}
                ry={bodyH * 0.3}
                fill={L.points}
              />
            )}
          </g>
          {leg(backX, true, 'leg-a')}
          {leg(frontX, true, 'leg-b')}
        </g>
        <g className="dog-head" style={{ transformOrigin: `${hx - r * 0.3}px ${hy + r * 0.6}px` }}>
          {(L.ear === 'pointy' || L.ear === 'big') && (
            <Ear kind={L.ear} hx={hx} hy={hy} r={r} fill={L.earColor ?? L.coat} far />
          )}
          <circle cx={hx} cy={hy} r={r} fill={L.mask ? L.light : headFill} />
          <g clipPath={`url(#head${uid})`}>
            {L.mask && (
              <ellipse
                cx={hx - r * 0.25}
                cy={hy - r * 0.62}
                rx={r * 1.15}
                ry={r * 0.62}
                fill={L.coat}
              />
            )}
            {L.light && !L.mask && (
              <ellipse
                cx={hx + r * 0.55}
                cy={hy + r * 0.75}
                rx={r * 0.6}
                ry={r * 0.5}
                fill={L.light}
              />
            )}
            {L.head && L.muzzle && (
              <rect
                x={hx + r * 0.02}
                y={hy - r * 1.1}
                width={r * 0.28}
                height={r * 1.2}
                rx={2}
                fill={L.muzzle}
              />
            )}
          </g>
          <rect
            x={hx + r * 0.1}
            y={snoutTop}
            width={tipX - hx - r * 0.1 + 1}
            height={snoutH}
            rx={snoutH / 2}
            fill={L.muzzle ?? L.points ?? (L.mask ? L.light : (L.light ?? headFill))}
          />
          {L.points && (
            <ellipse cx={eyeX + 0.4} cy={eyeY - 3.6} rx={1.8} ry={1.2} fill={L.points} />
          )}
          <circle className="dog-nose" cx={tipX - 1} cy={snoutTop + 2.3} r={2.7} fill={NOSE} />
          <path
            d={`M${tipX - 2.5} ${snoutTop + snoutH - 1.2} q-3 1.6 -6 0`}
            stroke={NOSE}
            strokeOpacity={0.55}
            strokeWidth={1}
            fill="none"
            strokeLinecap="round"
          />
          <g className="dog-eye" style={{ transformOrigin: `${eyeX}px ${eyeY}px` }}>
            {L.mask && <circle cx={eyeX} cy={eyeY} r={eyeR + 1.5} fill={L.coat} />}
            {L.eye && <circle cx={eyeX} cy={eyeY} r={eyeR + 0.7} fill={L.eye} />}
            <circle cx={eyeX} cy={eyeY} r={eyeR} fill={NOSE} />
            <circle cx={eyeX + eyeR * 0.35} cy={eyeY - eyeR * 0.4} r={eyeR * 0.35} fill="#fff" />
          </g>
          <path
            className="dog-eye-shut"
            d={`M${eyeX - eyeR - 0.5} ${eyeY} q${eyeR + 0.5} ${eyeR} ${2 * eyeR + 1} 0`}
            stroke={NOSE}
            strokeWidth={1.3}
            fill="none"
            strokeLinecap="round"
          />
          {(L.ear === 'floppy' || L.ear === 'long') && (
            <Ear kind={L.ear} hx={hx} hy={hy} r={r} fill={L.earColor ?? L.shade} />
          )}
          {(L.ear === 'pointy' || L.ear === 'big') && (
            <Ear kind={L.ear} hx={hx} hy={hy} r={r} fill={L.earColor ?? L.coat} />
          )}
        </g>
      </g>
      <Effects
        mood={mood}
        x={Math.min(hx + r * 0.9, W - 16)}
        y={Math.max(hy - r * 1.6, 13)}
        nose={[tipX + 2, snoutTop + 3]}
        tail={bx - 6}
      />
    </svg>
  );
}

function Ear({
  kind,
  hx,
  hy,
  r,
  fill,
  far,
}: {
  kind: Ear;
  hx: number;
  hy: number;
  r: number;
  fill: string;
  far?: boolean;
}) {
  const o = { transformOrigin: `${hx - r * 0.3}px ${hy - r * 0.7}px` };
  if (kind === 'pointy' || kind === 'big') {
    const big = kind === 'big';
    const dx = far ? -r * 0.42 : 0;
    const tipY = hy - r * (big ? 2.15 : 1.8);
    const d = `M${hx - r * (big ? 0.85 : 0.62) + dx} ${hy - r * 0.45} L${hx - r * (big ? 0.55 : 0.28) + dx} ${tipY} L${
      hx + r * (big ? 0.15 : 0.18) + dx
    } ${hy - r * 0.78} Z`;
    return (
      <g className={far ? 'dog-ear far' : 'dog-ear'} style={o}>
        <path
          d={d}
          fill={far ? shadeOf(fill) : fill}
          strokeLinejoin="round"
          stroke={far ? shadeOf(fill) : fill}
          strokeWidth={2}
        />
        {!far && (
          <path
            d={`M${hx - r * (big ? 0.62 : 0.45)} ${hy - r * 0.62} L${hx - r * (big ? 0.5 : 0.3)} ${
              tipY + r * 0.42
            } L${hx - r * (big ? 0.05 : 0.02)} ${hy - r * 0.8} Z`}
            fill="#e9a3a0"
            opacity={big ? 0.85 : 0.55}
          />
        )}
      </g>
    );
  }
  const len = kind === 'long' ? 1.35 : 1.0;
  const d = `M${hx - r * 0.05} ${hy - r * 0.85} C${hx - r * 0.95} ${hy - r * 0.9} ${hx - r * 1.05} ${
    hy + r * len * 0.4
  } ${hx - r * 0.62} ${hy + r * len * 0.62} C${hx - r * 0.25} ${hy + r * len * 0.75} ${hx - r * 0.05} ${
    hy + r * 0.1
  } ${hx + r * 0.08} ${hy - r * 0.5} Z`;
  return (
    <g className="dog-ear" style={o}>
      <path d={d} fill={fill} />
    </g>
  );
}

function TailShape({
  kind,
  x,
  y,
  fill,
  tip,
}: {
  kind: Tail;
  x: number;
  y: number;
  fill: string;
  tip?: string | undefined;
}) {
  const t = `translate(${x} ${y})`;
  switch (kind) {
    case 'saber':
      return (
        <path
          transform={t}
          d="M2 -1 C-8 1 -17 9 -20 22 C-17 21 -14 18 -12 15 C-9 9 -4 6 3 5 Z"
          fill={fill}
        />
      );
    case 'plume':
      return (
        <path
          transform={t}
          d="M2 -1 C-8 -1 -16 6 -20 17 C-18 16 -18 19 -15 18 C-14 20 -11 18 -11 16 C-8 10 -3 7 3 5 Z"
          fill={fill}
        />
      );
    case 'curl':
      return (
        <g transform={t}>
          <path
            d="M2 2 C-7 -2 -9 -14 -1 -17 C6 -19 9 -12 5 -9 C3 -12 -2 -12 -2 -8 C-2 -4 1 -2 4 -1 Z"
            fill={fill}
          />
          {tip && <path d="M-1 -17 C6 -19 9 -12 5 -9 C4 -12 2 -14 -1 -14 Z" fill={tip} />}
        </g>
      );
    case 'stub':
      return (
        <rect
          transform={`${t} rotate(-35)`}
          x={-7}
          y={-3}
          width={9}
          height={5}
          rx={2.5}
          fill={fill}
        />
      );
    case 'fluff':
      return <ellipse transform={`${t} rotate(-20)`} cx={-3} cy={0} rx={6} ry={4.5} fill={fill} />;
    case 'whip':
      return (
        <g transform={t}>
          <path
            d="M2 1 Q-9 -2 -12 -15"
            stroke={fill}
            strokeWidth={3.4}
            fill="none"
            strokeLinecap="round"
          />
          {tip && (
            <path
              d="M-10.6 -11 Q-11.5 -13 -12 -15"
              stroke={tip}
              strokeWidth={3.4}
              fill="none"
              strokeLinecap="round"
            />
          )}
        </g>
      );
  }
}

/** Bubbles and puffs above the dog that say what it's doing. */
function Effects({
  mood,
  x,
  y,
  nose,
  tail,
}: {
  mood: DogMood;
  x: number;
  y: number;
  nose: [number, number];
  tail: number;
}) {
  if (mood === 'thinking')
    return (
      <g className="fx fx-think" transform={`translate(${x} ${y})`}>
        <rect x={-13} y={-9} width={26} height={14} rx={7} className="fx-bubble" />
        <circle cx={-6} cy={-2} r={1.8} className="fx-dot d1" />
        <circle cx={0} cy={-2} r={1.8} className="fx-dot d2" />
        <circle cx={6} cy={-2} r={1.8} className="fx-dot d3" />
      </g>
    );
  if (mood === 'waiting')
    return (
      <g className="fx fx-wait" transform={`translate(${x} ${y})`}>
        <circle r={8} className="fx-bubble ask" />
        <text y={3.6} textAnchor="middle" className="fx-glyph">
          ?
        </text>
      </g>
    );
  if (mood === 'sniffing')
    return (
      <g className="fx fx-sniff" transform={`translate(${nose[0]} ${nose[1]})`}>
        <circle cx={3} cy={2} r={1.6} className="fx-puff p1" />
        <circle cx={6} cy={-1} r={1.2} className="fx-puff p2" />
        <circle cx={8} cy={3} r={1} className="fx-puff p3" />
      </g>
    );
  if (mood === 'fetching')
    return (
      <g className="fx fx-fetch">
        <g transform={`translate(${nose[0] - 6} ${nose[1] + 4})`} className="fx-bone">
          <rect x={-5} y={-1.3} width={10} height={2.6} rx={1.3} />
          <circle cx={-5} cy={-1.4} r={1.7} />
          <circle cx={-5} cy={1.4} r={1.7} />
          <circle cx={5} cy={-1.4} r={1.7} />
          <circle cx={5} cy={1.4} r={1.7} />
        </g>
        <path
          d={`M${tail - 4} ${nose[1] + 14} h-8 M${tail - 2} ${nose[1] + 22} h-11 M${tail - 4} ${nose[1] + 30} h-7`}
          className="fx-speed"
        />
      </g>
    );
  if (mood === 'done')
    return (
      <g className="fx fx-done" transform={`translate(${x} ${y})`}>
        <path d="M0 -8 L2 -2 L8 0 L2 2 L0 8 L-2 2 L-8 0 L-2 -2 Z" className="fx-star" />
      </g>
    );
  if (mood === 'error')
    return (
      <g className="fx fx-error" transform={`translate(${x} ${y})`}>
        <circle r={8} className="fx-bubble err" />
        <text y={3.6} textAnchor="middle" className="fx-glyph">
          !
        </text>
      </g>
    );
  if (mood === 'sleeping')
    return (
      <g className="fx fx-sleep" transform={`translate(${x - 4} ${y + 4})`}>
        <text className="fx-z z1">z</text>
        <text className="fx-z z2" x={6} y={-6}>
          z
        </text>
        <text className="fx-z z3" x={12} y={-12}>
          Z
        </text>
      </g>
    );
  return null;
}

/** A slightly darker version of a #rrggbb colour, for the far side. */
function shadeOf(hex: string): string {
  const n = parseInt(hex.slice(1), 16);
  const f = (v: number) => Math.round(v * 0.8);
  const r = f(n >> 16);
  const g = f((n >> 8) & 255);
  const b = f(n & 255);
  return `#${((r << 16) | (g << 8) | b).toString(16).padStart(6, '0')}`;
}
