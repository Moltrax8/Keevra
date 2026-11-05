/** Tiny shared presentational bits: the brand mark. */

import markDark from "../assets/keevra-mark-dark.png";
import markLight from "../assets/keevra-mark-light.png";

/**
 * Keevra mark: the 3D icon from the brand kit, recolored to the app's warm
 * persimmon palette. The light and dark variants are both mounted and CSS
 * swaps them with `data-theme`, so the mark matches the surrounding surface.
 */
export function Logo({ size = 34 }: { size?: number }) {
  return (
    <span className="brand-mark" style={{ width: size, height: size }}>
      <img className="brand-mark__light" src={markLight} alt="" aria-hidden="true" />
      <img className="brand-mark__dark" src={markDark} alt="" aria-hidden="true" />
    </span>
  );
}
