import { useEffect, useState } from 'react';

/** Per-viewer UI preference (panel sizes, last workspace). Falls back silently when storage is unavailable. */
export function useStoredState<T>(key: string, initial: T): [T, (v: T | ((p: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(`dropsuite.${key}`);
      return raw === null ? initial : (JSON.parse(raw) as T);
    } catch {
      return initial;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(`dropsuite.${key}`, JSON.stringify(value));
    } catch {
      /* storage blocked: keep in memory only */
    }
  }, [key, value]);

  return [value, setValue];
}
