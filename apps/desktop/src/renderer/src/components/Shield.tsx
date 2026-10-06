import { useId } from 'react';

// The Vigil mark: Scout, the pack's German shepherd, keeping watch on a shield.
// Same drawing as resources/shield.svg, in the pack's colours (components/Dog.tsx).
const SHIELD = 'M7 2H33Q38 2 38 7V22C38 33 30.5 41 20 46C9.5 41 2 33 2 22V7Q2 2 7 2Z';
const NECK = 'M9 48L11.2 31Q12.2 26 15.4 24.4L24.2 27.6Q24.4 37 32 48Z';
const SADDLE = 'M9 48L11.2 31Q12.2 26 15.4 24.4Q14.6 36 18.5 48Z';
const COLLAR = 'M12.6 33.2Q19 35.8 26.2 31.4L26.8 34.2Q19.4 38.8 12.2 36Z';
const EAR_BACK = 'M12.6 19.4L13.6 6.4L20 15.2Z';
const EAR = 'M16.4 16.4L20.4 5.2L24.4 15Z';
const EAR_INNER = 'M18.6 14.8L20.4 9.6L22.4 14.4Z';
const HEAD =
  'M11.6 21.4C11.6 16.2 15 13.2 19.4 13.2C22.6 13.2 24.6 14.8 26 17.2L31.2 19.6Q33.2 20.6 32.8 22.8L31.6 25.4Q28 27.6 24 27.8C21 28 18.6 29.6 17 31L12.6 28.6C11.9 26.6 11.6 24 11.6 21.4Z';
const MUZZLE =
  'M26.6 17.5L31.2 19.6Q33.2 20.6 32.8 22.8L31.6 25.4Q29.2 26.9 25.8 27.5Q27.8 22.8 26.6 17.5Z';

const COAT = '#c98a45';
const DARK = '#2a2320';
const INK = '#120e0d';

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
      </defs>
      <path d={SHIELD} fill={`url(#${id}-body)`} />
      <g clipPath={`url(#${id}-inside)`}>
        <path d={NECK} fill={COAT} />
        <path d={SADDLE} fill={DARK} />
        <path d={COLLAR} fill="#ffd45a" />
        <circle cx="19.6" cy="37.6" r="1.7" fill="#ffd45a" />
      </g>
      <path d={EAR_BACK} fill={DARK} />
      <path d={EAR} fill={DARK} />
      <path d={EAR_INNER} fill="#9a6430" />
      <path d={HEAD} fill={COAT} />
      <path d={MUZZLE} fill={DARK} />
      <ellipse cx="32.4" cy="21.3" rx="1.7" ry="1.45" fill={INK} />
      <circle cx="21.8" cy="19" r="1.25" fill={INK} />
      <circle cx="22.2" cy="18.6" r="0.42" fill="#fff" />
    </svg>
  );
}
