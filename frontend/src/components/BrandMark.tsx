import React from 'react';

/**
 * DropSuite mark: an isometric slab and a folded slab, every slanted edge at 30°.
 * Drawn on a 64-unit grid whose vertical edges land on whole pixels at 16 px, the default size.
 * Inherits the text colour, so it works on any ground.
 */
export const BrandMark: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 64 64" fill="currentColor" aria-hidden="true" focusable="false">
    <path d="M30 3.76L52 16.46L52 49.76L44 45.14L44 25.84L30 17.76Z" />
    <path d="M12 16.37L36 30.22L36 60.22L12 46.37Z" />
  </svg>
);
