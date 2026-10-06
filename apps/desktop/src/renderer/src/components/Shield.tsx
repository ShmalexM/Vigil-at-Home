import { useId } from 'react';

// The Vigil mark: a shield holding a vigil flame. Same drawing as resources/shield.svg.
const SHIELD = 'M7 2H33Q38 2 38 7V22C38 33 30.5 41 20 46C9.5 41 2 33 2 22V7Q2 2 7 2Z';
const FLAME =
  'M20.5 8.5C22 13.5 27.8 17 27.8 24.6C27.8 29.6 24.2 33.6 20 33.6C15.8 33.6 12.2 29.6 12.2 25C12.2 21.4 14 18.8 16 17.2C16 19.8 17 21.7 18.7 22.6C18 17.8 18.6 12.3 20.5 8.5Z';
const CORE =
  'M20.2 20.6C22 23 23.8 24.8 23.8 27.6C23.8 29.9 22.1 31.4 20 31.4C17.9 31.4 16.2 29.9 16.2 27.8C16.2 25.4 18.4 23.4 20.2 20.6Z';

export function Shield({ height = 22 }: { height?: number }) {
  // Gradient ids must be unique per page, and the mark can appear more than once.
  const id = useId();
  return (
    <svg width={(height * 40) / 48} height={height} viewBox="0 0 40 48" aria-hidden="true">
      <defs>
        <linearGradient id={`${id}-body`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#4b9dff" />
          <stop offset="1" stopColor="#1d4fc4" />
        </linearGradient>
        <linearGradient id={`${id}-flame`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#ffd45a" />
          <stop offset="1" stopColor="#ff8a2a" />
        </linearGradient>
      </defs>
      <path d={SHIELD} fill={`url(#${id}-body)`} />
      <path d={FLAME} fill={`url(#${id}-flame)`} />
      <path d={CORE} fill="#fff4cf" />
    </svg>
  );
}
