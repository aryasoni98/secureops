// SecureOps landing — entry point
function SOApp() {
  const [theme, setTheme] = React.useState(() => localStorage.getItem("so-theme") || "light");
  React.useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("so-theme", theme);
  }, [theme]);

  return (
    <div className="wk-shell">
      <SOProgressBar />
      <SOCursor />
      <SONav theme={theme} setTheme={setTheme} />
      <SOHero />
      <SOMarquee />
      <SOProblem />
      <SOMetrics />
      <SORings />
      <SOBento />
      <SOQuickstart />
      <SOTiers />
      <SOFinalCTA />
      <SOFooter />
    </div>
  );
}

const soRoot = ReactDOM.createRoot(document.getElementById("root"));
soRoot.render(<SOApp />);
