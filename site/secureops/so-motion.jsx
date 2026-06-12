// SecureOps — motion upgrades (Framer Motion + CSS, all reduced-motion aware)
const { motion: moM, useScroll: useScrollM, useSpring: useSpringM, useReducedMotion: useRMM } = window.FramerMotion || {};
const soMotionUseInView = (window.FramerMotion || {}).useInView;

/* ----------------------- SCROLL PROGRESS BAR ----------------------- */
function SOProgressBar() {
  const reduce = useRMM();
  const { scrollYProgress } = useScrollM();
  const scaleX = useSpringM(scrollYProgress, { stiffness: 140, damping: 26, mass: 0.3 });
  if (reduce) return null;
  return <moM.div className="so-progress" style={{ scaleX }} aria-hidden="true" />;
}

/* --------------------------- MAGNETIC CTA --------------------------- */
function SOMagnetic({ children, strength = 0.22 }) {
  const reduce = useRMM();
  const ref = React.useRef(null);
  const [d, setD] = React.useState({ x: 0, y: 0 });
  if (reduce) return <span>{children}</span>;
  const onMove = (e) => {
    const r = ref.current.getBoundingClientRect();
    setD({ x: (e.clientX - (r.left + r.width / 2)) * strength, y: (e.clientY - (r.top + r.height / 2)) * strength });
  };
  const onLeave = () => setD({ x: 0, y: 0 });
  return (
    <moM.span ref={ref} onPointerMove={onMove} onPointerLeave={onLeave}
      animate={{ x: d.x, y: d.y }}
      transition={{ type: "spring", stiffness: 260, damping: 18, mass: 0.5 }}
      style={{ display: "inline-block" }}>
      {children}
    </moM.span>
  );
}

/* ----------------- HEADLINE WORD-MASK STAGGER REVEAL ----------------- */
function SOWordReveal({ words, className = "", as: As = "h1" }) {
  const ref = React.useRef(null);
  const inView = soMotionUseInView(ref, { once: true });
  return (
    <As ref={ref} className={`so-words ${inView ? "so-in" : ""} ${className}`}>
      {words.map((w, i) => (
        <React.Fragment key={w.t + i}>
          <span className="so-word-wrap">
            <span className={`so-word ${w.grad ? "wk-text-gradient wk-text-gradient--animate" : ""}`}
              style={{ transitionDelay: inView ? 0.06 + i * 0.07 + "s" : "0s" }}>{w.t}</span>
          </span>
          {i < words.length - 1 ? " " : ""}
        </React.Fragment>
      ))}
    </As>
  );
}

/* ------------------- BLOB CURSOR (clean reimpl.) ------------------- */
function SOCursor() {
  const reduce = useRMM();
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (reduce) return;
    if (window.matchMedia("(pointer:coarse)").matches) return;
    const el = ref.current;
    if (!el) return;
    let tx = -100, ty = -100, cx = -100, cy = -100, raf = 0, hot = false;
    function frame() {
      cx += (tx - cx) * 0.2;
      cy += (ty - cy) * 0.2;
      el.style.transform = `translate(${cx}px, ${cy}px) translate(-50%, -50%) scale(${hot ? 1.6 : 1})`;
      if (Math.abs(tx - cx) + Math.abs(ty - cy) > 0.3) raf = requestAnimationFrame(frame);
      else raf = 0;
    }
    const move = (e) => { tx = e.clientX; ty = e.clientY; if (!raf) raf = requestAnimationFrame(frame); };
    const over = (e) => { if (e.target.closest && e.target.closest("[data-cursor-hot]")) { hot = true; el.classList.add("hot"); if (!raf) raf = requestAnimationFrame(frame); } };
    const out = (e) => { if (e.target.closest && e.target.closest("[data-cursor-hot]")) { hot = false; el.classList.remove("hot"); if (!raf) raf = requestAnimationFrame(frame); } };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseover", over);
    window.addEventListener("mouseout", out);
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseover", over);
      window.removeEventListener("mouseout", out);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [reduce]);
  if (reduce) return null;
  return <div ref={ref} className="so-cursor" aria-hidden="true"></div>;
}

Object.assign(window, { SOProgressBar, SOMagnetic, SOWordReveal, SOCursor });
