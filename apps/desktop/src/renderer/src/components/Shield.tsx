import { useId } from 'react';

// The Vigil mark: Scout, the pack's husky, keeping watch on a shield. Black cap,
// ears and back, white mask and chest, blue eyes. Same drawing as
// resources/shield.svg, in the pack's colours (components/Dog.tsx).
const SHIELD = 'M7 2H33Q38 2 38 7V22C38 33 30.5 41 20 46C9.5 41 2 33 2 22V7Q2 2 7 2Z';
const CHEST = 'M9 48L11.2 31Q12.2 26 15.4 24.4L24.2 27.6Q24.4 37 32 48Z';
const BACK = 'M9 48L11.2 31Q12.2 26 15.4 24.4Q16.4 35 21.5 48Z';
const COLLAR = 'M12.6 33.2Q19 35.8 26.2 31.4L26.8 34.2Q19.4 38.8 12.2 36Z';
const EAR_BACK = 'M12.4 19.6L13.4 6.6L20.2 15Z';
const EAR = 'M16.2 16.4L20.2 5.4L24.6 15.2Z';
const EAR_INNER = 'M18.6 14.8L20.2 9.8L22.4 14.6Z';
const HEAD =
  'M11.6 21.4C11.6 16.2 15 13.2 19.4 13.2C22.6 13.2 24.6 14.8 26 17.2L30.2 19.4Q32 20.4 31.6 22.6L30.6 25Q27.4 27.2 24 27.6C21 28 18.6 29.6 17 31L12.6 28.6C11.9 26.6 11.6 24 11.6 21.4Z';
/** The black cap over the head, with its peak down the forehead, clipped to HEAD. */
const CAP =
  'M8 32V8H30L26.4 17.6Q25 19 23.6 17.2Q21.6 16.2 19.6 17.6Q18.4 19 18.2 21.4Q17.4 25 13.8 26.8L13.6 32Z';

const BLACK = '#1f1e23';
const WHITE = '#f6f5f1';
const INK = '#120e0d';
const GOLD = '#ffd45a';

export function Shield({ height = 22 }: { height?: number }) {
  // Gradient and clip ids must be unique per page, and the mark can appear more than once.
  const id = useId();
  return (
    <svg width={(height * 40) / 48} height={height} viewBox="0 0 40 48" aria-hidden="true">
      <defs>
        <linearGradient id={`${id}-body`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#4b9dff" />
          <stop offset="1" stopColor="#1d4fc4" />
        </linearGradient>
        <clipPath id={`${id}-inside`}>
          <path d={SHIELD} />
        </clipPath>
        <clipPath id={`${id}-head`}>
          <path d={HEAD} />
        </clipPath>
      </defs>
      <path d={SHIELD} fill={`url(#${id}-body)`} />
      <g clipPath={`url(#${id}-inside)`}>
        <path d={CHEST} fill={WHITE} />
        <path d={BACK} fill={BLACK} />
        <path d={COLLAR} fill={GOLD} />
        <circle cx="19.6" cy="37.6" r="1.7" fill={GOLD} />
      </g>
      <path d={EAR_BACK} fill={BLACK} />
      <path d={EAR} fill={BLACK} />
      <path d={EAR_INNER} fill="#e4e1dc" />
      <path d={HEAD} fill={WHITE} />
      <path d={CAP} fill={BLACK} clipPath={`url(#${id}-head)`} />
      <ellipse cx="31" cy="21" rx="1.6" ry="1.4" fill={INK} />
      <circle cx="21.8" cy="19.6" r="1.75" fill={BLACK} />
      <circle cx="21.9" cy="19.6" r="1.2" fill="#8ed1f7" />
      <circle cx="22" cy="19.6" r="0.55" fill={INK} />
      <circle cx="22.3" cy="19.2" r="0.32" fill="#fff" />
    </svg>
  );
}
