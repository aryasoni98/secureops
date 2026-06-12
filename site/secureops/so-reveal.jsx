// CSS-transition-based Reveal / Stagger overrides.
// Same motion spec as the Wooak DS (600ms entrance, out-quint, 24px rise, 60ms
// stagger) but driven by CSS classes, so content degrades to its visible end
// state in contexts where JS/WAAPI animation frames are throttled.
const soRevealUseInView = (window.FramerMotion || {}).useInView;

function SORevealOverride({ children, delay = 0, y = 24, once = true, as: As = "div", style, className = "" }) {
  const ref = React.useRef(null);
  const inView = soRevealUseInView(ref, { once });
  return (
    <div ref={ref}
      className={`so-reveal ${inView ? "so-in" : ""} ${className}`}
      style={{ ...style, "--so-y": y + "px", transitionDelay: inView ? delay + "s" : "0s" }}>
      {children}
    </div>
  );
}

function SOStaggerOverride({ children, gap = 0.06, y = 24, once = true, className = "", style }) {
  const ref = React.useRef(null);
  const inView = soRevealUseInView(ref, { once });
  return (
    <div ref={ref} className={className} style={style}>
      {React.Children.map(children, (c, i) => (
        <div className={`so-reveal ${inView ? "so-in" : ""}`}
          style={{ "--so-y": y + "px", transitionDelay: inView ? i * gap + "s" : "0s" }}>{c}</div>
      ))}
    </div>
  );
}

Object.assign(window, { Reveal: SORevealOverride, Stagger: SOStaggerOverride });
