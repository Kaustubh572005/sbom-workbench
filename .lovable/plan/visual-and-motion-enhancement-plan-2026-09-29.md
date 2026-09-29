# Visual and motion enhancement plan

## What will change
- Add the requested page fades, staggered row entrances, KPI slide-ups, and subtle severity pulses.
- Strengthen card hover lift and severity-specific glow feedback while preserving the current light visual system.
- Add loading progress, shimmer placeholders, loading dots, refresh spin, and brief status-change feedback where current loading states exist.
- Enable smooth 800ms chart entrances, animated tooltips, and number transitions for risk and KPI values.
- Add button press/ripple feedback, animated filter states, rotating sort indicators, copy confirmation, dropdown entry, and dismiss transitions.

## Implementation details
- Centralize reusable keyframes and motion utilities in the global styles, including reduced-motion fallbacks.
- Apply page-level motion in the authenticated layout so every existing page benefits without changing page content.
- Update shared tables and the component inventory for bounded row staggering, animated sorting/filtering, and copy feedback.
- Update dashboard, timeline, and report charts using their existing Recharts and Framer Motion support.
- Reuse the existing button and semantic severity tokens; no dependencies or data-layer changes.

## Validation
- Confirm the app builds cleanly.
- Check representative dashboard, vulnerability, and inventory views at desktop and compact widths.
- Verify interactions remain usable with reduced motion enabled.
