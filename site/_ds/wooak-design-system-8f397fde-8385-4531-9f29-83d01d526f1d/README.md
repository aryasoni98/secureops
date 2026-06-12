# Wooak Design System

A modern, 2026-feeling design system for **Wooak** — the all-in-one HR & people-operations platform that unifies employees, recruitment, attendance, leave, payroll, performance, assets, helpdesk, and projects into a single web app for SMBs and growing enterprises.

This folder defines the visual language (color, type, motion), copies in the brand assets (logo, icon system), and ships two UI kits that recreate the in-product app and the marketing landing page in React.

## Sources

- **Codebase:** `wooak/` — read-only Django codebase (an OpenHRMS-style backend that ships the actual product). Inspected for sidebar nomenclature, products surfaced, and feature copy, but the visual identity in this design system is the new 2026 brand defined in the brief — the legacy CSS in `wooak/static/src/scss/` does not match the new identity and is not used.
- **Logo:** `uploads/logo.png` (512×512 PNG). Copied to `assets/wooak-logo.png`.
- **Brief:** the spec the design system was built from — all colors, typographic scale, motion easings, and section descriptions were defined there.

If you have access to the source codebase, key references:
- `wooak/auth/login.html` — current legacy auth surface (visually superseded)
- `wooak/base/sidebar.py`, `wooak/asset/sidebar.py`, `wooak/leave/sidebar.py`, etc. — product surface names and ordering

## Index

```
.
├── README.md                  ← this file
├── SKILL.md                   ← Claude Skill manifest
├── colors_and_type.css        ← single source of truth for tokens (color, type, radius, shadow, motion)
├── assets/
│   └── wooak-logo.png         ← 512×512 brand mark (blue+green strokes, orange dot)
├── preview/                   ← Design System cards (one HTML per concept)
│   ├── color-primary.html, color-neutral.html, color-semantic.html, color-gradients.html
│   ├── type-display.html, type-scale.html, type-families.html
│   ├── spacing-scale.html, spacing-radii.html, spacing-shadows.html
│   ├── components-buttons.html, components-inputs.html, components-badges.html, components-cards.html
│   └── brand-logo.html, brand-iconography.html, brand-motion.html, brand-voice.html
└── ui_kits/
    ├── landing/                ← long-scroll marketing page (12 sections, Framer Motion)
    │   ├── index.html, landing.css, lib.jsx, sections-top.jsx, sections-bottom.jsx, App.jsx, README.md
    └── app/                    ← in-product dashboard (sidebar + Today + Hiring kanban)
        ├── index.html, app.css, App.jsx, README.md
```

---

## Brand at a glance

> "We say *your team*, not *human capital*. Confident, plainspoken, mildly funny — never corporate-stiff."

The Wooak mark is a **W formed by two flowing strokes** — a deep blue stroke on the left curving into a vibrant green stroke on the right, with a **small orange dot floating above the middle valley** (a person, a spark, the human-at-the-center). The orange dot is the brand's signature accent and **is used very sparingly** — only on the primary CTA, live indicators, and AI suggestions.

The signature **blue→green linear gradient at 135°** appears on hero text, primary CTAs, divider lines, and "active" states. The gradient is **never used on body copy**.

---

## CONTENT FUNDAMENTALS

Wooak's voice is the most important component in the system — it's how the brand carries itself across every screen.

### Tone
**Confident, human, plainspoken. Playful but professional — never corporate-stiff.** Wooak is a calm, slightly dry friend who happens to run a great HR department. The voice is closer to Linear or Stripe than to Workday or BambooHR.

### Person and pronouns
- "**Your team**" — never *employees*, *workforce*, *resources*, or *human capital* in marketing surfaces. In-product, *employees* is acceptable as a generic noun.
- "**We**" (Wooak) addressing "**you**" (the admin / founder / COO). Avoid the royal-we for product features ("Wooak runs payroll," not "We run your payroll for you" except in conversational empty states).
- First-name examples in mockups (Mia, Jonah, Priya, Dev, Ana, Reggie) — multicultural, no stock names.

### Casing
- **Sentence case** everywhere except the wordmark itself (`wooak`, lowercase) and proper nouns.
- Buttons: sentence case ("Start free", "Watch 2-min demo", "Approve & pay"). Never Title Case.
- Section labels in eyebrows are **UPPERCASE** with +0.10em tracking, but they're typographic accents, not full headlines.

### Sentence structure
- **Short.** Hero copy averages 4–7 words per line.
- **One-clause headlines** broken with a period: "One platform. Your whole team." "Payroll, run in 4 minutes." "Free under 25 people. Honest above."
- Em dashes used freely for parenthetical asides — like this one.

### What we say vs. don't say

| ✓ Wooak says | ✗ Wooak does not say |
|---|---|
| "Hire, onboard, pay, schedule, and grow your people." | "Empower your stakeholders to leverage talent." |
| "Payroll, run in 4 minutes." | "AI-powered next-gen payroll engine." |
| "Free for up to 25 employees. Forever." | "Try our solution today!" |
| "1 anomaly: overtime on J.W." | "An issue has been detected." |
| "wait, this is all one app?" | "Best-in-class unified HRIS platform." |
| "your team" | "human capital", "resources", "workforce" |

### Emoji
**No emoji in production UI.** The visual system carries personality through type, color, the orange spark, and motion. The one exception: the `✦` four-pointed star glyph used in the "Most popular" pricing pill and a couple of small accents — it's a typographic sparkle, not an emoji.

### Specific examples used in the kit
- Hero: *"One platform. Your whole team."*
- Hero sub: *"Hire, onboard, pay, schedule, and grow your people — without juggling six tools."*
- Pricing eyebrow: *"Pricing that doesn't grow legs"*
- Empty state: *"No leave requests yet. (Lucky you.)"*
- Toast: *"Saved. We've got you."*
- AI suggestion: *"Suggested: 3 candidates for Senior Designer."*

---

## VISUAL FOUNDATIONS

### Color
- **Primary palette:** Blue (`#1E64E6` → `#4A9CFF`), Green (`#22C55E` → `#4ADE80`), with full 50–900 ramps in both. Used in equal weight — neither dominates.
- **Orange spark:** `#F97316` — the accent. Used **sparingly**, only on the primary CTA's leading icon, AI suggestions, "live" pulse dots, and anomaly indicators. Never on a large fill.
- **Warm neutrals:** Paper `#FAFAF7` (surface), Cream `#F5F5F0` (muted), Bone `#ECEBE4` (divider), Ink `#0A0A0A` (near-black). The base background is warm — *never* pure white in light mode, *never* pure black in dark mode (dark mode uses `#0A0F1A`, a deep blue-ink).
- **Signature gradient:** `linear-gradient(135deg, #1E64E6 0%, #22C55E 100%)`. The single most important brand asset after the logo. Used on hero text accents, primary CTAs, divider lines, the W mark on dark, focus rings, progress arcs, and "active" sidebar states. **Never** on body copy. The hero animates the gradient position over an 8s loop.
- **Conic gradient** is reserved for the final-CTA background bloom only.

### Typography
- **Family:** Inter for everything (display + body). Weights 400/500/600/700. We considered Geist and Söhne; Inter is the production pick because it's free, geometric, and ships with great `tnum` and italic.
- **Display tracking:** −0.024em on H1 (the brief asks for −0.02em; we tightened slightly because Inter's default counters are open). H2 is −0.018em, H3 −0.012em, body 0.
- **Body:** 16/1.55 default. Lede 20/1.5. Small 14, micro 12.
- **Italic serif** (Instrument Serif, italic only) used **exclusively** for the testimonial pull-quotes and for the floating speech bubble in the comparison section. Never for UI chrome.
- **Mono** (JetBrains Mono / ui-mono fallback) for IDs, code, kbd, status timestamps.
- **Gradient text** utility (`.wk-text-gradient`) on hero word "whole" and on "better tools" in the final CTA. With an 8s slow shift animation on hero.

### Spacing
4px base. Tokens: 4 / 8 / 12 / 16 / 20 / 24 / 32 / 40 / 48 / 64 / 80 / 96 / 128. Section vertical padding is 96px desktop, 72px mobile.

### Corners
**Rounded but not soft** — per the brief. 12px on cards, 8px on buttons and inputs, 6px on tags, 999px on pills and CTAs. Bento tiles use 16px (slightly larger for marquee weight). Final-CTA conic and the gradient W badge use 24–32px.

### Backgrounds
- The dominant surface is the warm Paper (`#FAFAF7`). Sections alternate between Paper and lifted Cream (`#F5F5F0`) for visual rhythm.
- The **metrics band** and the **final CTA** are full-bleed gradient sheets. The metrics band carries a soft procedural SVG noise overlay (`feTurbulence`) at 35% opacity in `overlay` blend mode — this keeps the gradient from looking flat, which is the single biggest tell of an AI-rendered hero.
- Behind the hero text, **two blurred orbs** (blue + green) drift on scroll with parallax. A third small orange orb adds warmth.
- **No stock photos**, no images of people in suits, no abstract 3D blobs. All hero/tour imagery is "real-feeling product UI" — dashboards, kanbans, charts shown at a slight angle.

### Animation
- **Easing:** `cubic-bezier(0.22, 1, 0.36, 1)` (custom out-quint) for everything that moves. The brief specifies this exact curve; we never deviate.
- **Entrance:** 24px upward translate + opacity 0→1, **600ms**, triggered once via `IntersectionObserver` / `useInView({ once: true })`. Stagger children by 60ms.
- **Hover:** 200ms — color, shadow, and a 1–4px translateY for cards.
- **Layout transitions:** 400ms (shared-element morphs in the product tour, pricing digit slides).
- **Continuous loops:** gradient shift (8s linear infinite), spark pulse (1.6s), marquee (36s linear), conic final-CTA (30s).
- **Reduced motion:** `useReducedMotion()` disables every non-essential animation — entrance fades become instant, marquee stops, gradient stops cycling. The page must look intentional with motion off.
- **Never animate text content during read flow.** Only on entrance, only once.

### Hover states
- **Buttons:** background nudges (gradient brightens slightly via shadow growth, not color shift), translateY −1px, shadow grows.
- **Cards:** translateY −3 to −4px, shadow grows from `sm` → `lg`, gradient-border fades in (1px masked gradient).
- **Links:** underline replaced by a 200ms color shift toward `--wk-blue-500`, **never** opacity drop.
- **Icon buttons:** background fills with `--bg-muted`, color saturates to `--fg`.

### Press / active states
- Buttons: `translateY(1px) scale(0.99)` — gentle, springy, not bouncy.
- No color flash on press; the lift inversion is enough.

### Borders
- Default border: `--border` (`#ECEBE4` — warm bone, never gray).
- Soft border for nested elements: `rgba(10,10,10,0.06)`.
- Strong border for form controls: `rgba(10,10,10,0.16)`.
- **Gradient borders** on hover (bento tiles) and on the "Most popular" pricing card — implemented via a 1.5px masked gradient pseudo-element, not `border-image` (which has known rendering bugs in Safari).

### Shadows
Five-step shadow scale — all warm-tinted (not pure black):
- `--shadow-xs` for inputs at rest
- `--shadow-sm` for the default card base
- `--shadow-md` for hover lift
- `--shadow-lg` for floating elements (the hero dashboard frame uses a blue-cast variant)
- `--shadow-xl` for modals
- Plus three colored focus rings: blue / green / spark (12–18% alpha, 4px ring).

### Transparency and blur
- The **sticky nav** uses `backdrop-filter: blur(18px) saturate(140%)` over the page background mixed at 70% — feels like glass, not opaque.
- **Glassmorphism bento tiles** use 60% white + 14px blur, with a gradient hairline border.
- Tooltips on the integrations constellation use `backdrop-filter` for legibility over rotating logos.
- We don't use blur on body copy backgrounds — only on chrome.

### Cards
Standard card: 12px radius, 1px `--border`, `--bg-elevated` (#FFF in light, #111827 in dark), `--shadow-sm` at rest, `--shadow-lg` on hover with a 1px gradient border fading in. Padding 18–22px depending on context. No left-border accent colors (we explicitly avoid that pattern; it reads as "AI slop").

### Layout rules
- Page max-width 1280px, gutters 32px desktop / 20px mobile.
- The metrics band and product tour are **inset-bleed** (margin 32px from edges, 24px radius) rather than full-bleed — feels more like a contained moment than a hard color band.
- Sticky elements: top nav, the product-tour left visual (sticky at top 100px).

### Imagery color vibe
**Warm, never cool. Never grayscale.** Hero/tour mockups always include color — blue and green dominant, with the orange spark as the lone warm accent. No b&w photography, no "cold corporate" gradients.

### Iconography (see ICONOGRAPHY below for the full rule)
1.75 stroke Lucide as the working set, with a small set of brand-filled icon chips for marketing surfaces. No emoji.

---

## ICONOGRAPHY

**Working set:** [Lucide](https://lucide.dev) icons, 1.75 stroke weight, `currentColor` fill. Lucide is loaded by linking the SVG paths directly inline (not the npm package and not a CDN font) so the page stays font-light and icons can color-shift cleanly.

The codebase's own static icon set (`wooak/static/images/ionicons/*` — ionicons 5.5.2; `wooak/static/fonts/material_icons*.woff2`) was inspected; **we are not using it in the new design system** because it predates the brand refresh and uses a heavier stroke + filled style that fights the modern Wooak voice.

### Rules
- **Stroke:** 1.75 always — not 1.5 (too thin against Inter) and not 2 (too heavy against the geometric headlines).
- **Color:** `currentColor` — icons inherit color from the surrounding element. This is how the same SVG renders gray in nav, blue when active, white inside the gradient CTA, orange in AI / spark moments.
- **Size:** 14–18px in dense UI, 22–32px in bento tiles, 64–88px on the integration constellation logos.
- **Stroke linecaps / joins:** round, round. Always.

### Variants used
- **Outline (Lucide default)** — primary working set, used in 90% of the system.
- **Filled brand chips** — used on the bento tile leading icons and on integration constellation dots. The chip is a 32×32 squircle (`border-radius: 10px`) filled with either `--bg-muted` (default), `var(--wk-gradient)` (brand), or `#FFF1E6` (spark, when the section relates to AI / liveness).
- **The W logo** — used as the brand mark wherever the wordmark or favicon appears. Always as the PNG asset (`assets/wooak-logo.png`); never re-drawn in SVG by hand. In dark contexts the same PNG is flipped via `filter: brightness(0) invert(1)`.

### Unicode glyphs used
- `✦` (U+2726) — the typographic sparkle on "Most popular" pills and CTAs. Read as an icon, not as an emoji.
- `▷` (U+25B7) — the play triangle on the "Watch 2-min demo" ghost button.
- `↑ ↓ ←` arrows in delta pills.

### What we don't do
- No emoji (no ✅ ⭐ 🔥 🚀, none) — the spark glyph carries that energy.
- No flag emoji in the language switcher; we use the `🌐` glyph (the one exception, in the footer language pill).
- No hand-drawn SVG illustrations.
- No 3D blob renders.

### Substitution flag
We did **not** find Lucide vendored in the codebase. If the team has a preferred icon house style, drop the SVG sources into `assets/icons/` and rewrite the inline path data in `ui_kits/landing/lib.jsx` (`Icon` component) and `ui_kits/app/App.jsx` (`PIcon` component). Both render from a tiny path-lookup table — replacing the values keeps the component API stable.

### Font substitution flag
- The brief asks for "Inter, Geist, or Söhne." We chose **Inter** as the default because it's the only one fully free + permissive. **If the team licenses Söhne or Geist for production, swap the `--font-display` and `--font-sans` variables in `colors_and_type.css` — every consumer pulls from those vars.**
- **Instrument Serif** is used only for testimonial italics. If a paid serif is preferred (e.g. Söhne Mono italic, GT Sectra), swap `--font-serif`.
- Fonts load from Google Fonts at runtime; we did **not** vendor the woff2 files because Inter and Instrument Serif are both Google-Fonts-distributed at full character set. If offline use is required, run a font-download step and drop the files in `fonts/`.

---

## UI kits

| Kit | Path | What it covers |
|---|---|---|
| **Landing page** | `ui_kits/landing/` | The 2026 marketing site: 12 long-scroll sections (hero, marquee, bento, product tour, comparison, metrics, testimonials, integrations, pricing, FAQ, final CTA, footer). Framer Motion-driven entrance, parallax, layout, and gradient animations. Dark mode toggle in the nav. |
| **Product app** | `ui_kits/app/` | The in-product dashboard: branded sidebar (Today / People / Hiring / Calendar / Time off / Payroll, plus Operations), search topbar, KPI cards, today's-status table, AI-spark suggestions card, approvals list, attendance bars, payroll card, OKR card, and a kanban hiring pipeline. |

Each kit has its own README with a section-by-section breakdown.

---

## How to use this in a new design

1. Always pull tokens from `colors_and_type.css` — never re-declare a color or radius locally. `var(--wk-gradient)`, `var(--fg)`, `var(--r-card)`, etc.
2. For typography, use the `.wk-display / .wk-h1…h4 / .wk-eyebrow / .wk-lede / .wk-body / .wk-small / .wk-micro / .wk-mono / .wk-quote` utility classes — they encode tracking and line-height correctly.
3. For animation, follow the four numbers: **600ms entrance / 200ms hover / 400ms layout / 60ms stagger**, all on `cubic-bezier(0.22, 1, 0.36, 1)`. The `Reveal` and `Stagger` primitives in `ui_kits/landing/lib.jsx` are reusable.
4. For copy, read CONTENT FUNDAMENTALS above and the Voice card in the Design System tab before writing a single line.
5. Use the orange spark with restraint — if a screen has 3 orange dots on it, remove 2.

---

## Caveats and open questions

- The legacy `wooak/` codebase is OpenHRMS-style and **does not** match the new 2026 brand. We did not port any of its CSS. If there's an existing visual style guide for the in-product app that should be respected (other than the brief), please share it.
- **Fonts** are Inter + Instrument Serif via Google Fonts. If the org has licenses for Söhne / Geist / GT Sectra, point me at the woff2 files and I'll swap the `--font-*` variables.
- **Icons** are inline Lucide-style paths. If there's a house icon system, share an SVG sprite and I'll swap the path lookup tables.
- The integrations constellation uses **text labels** (Sl, Go, Mi, Zo, etc.) rather than real partner logos to avoid trademark issues. Drop in licensed partner logos as `assets/integrations/*.svg` and update the `Orbit` component.
- The brief specifies `clamp(56px, 8vw, 96px)` for hero H1; we use `clamp(56px, 7.6vw, 96px)` to match Inter's actual cap height more cleanly. Easy to revert.
- We did not build a dark-mode variant of the design-system preview cards — the cards always show the light theme. The full landing and product app both have dark mode wired through `[data-theme="dark"]`.
