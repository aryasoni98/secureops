/* @ds-bundle: {"format":3,"namespace":"WooakDesignSystem_8f397f","components":[],"sourceHashes":{"ui_kits/app/App.jsx":"0c404dbfda49","ui_kits/landing/App.jsx":"a810f889213c","ui_kits/landing/lib.jsx":"395ee9dcfdcc","ui_kits/landing/sections-bottom.jsx":"98d812d395ba","ui_kits/landing/sections-top.jsx":"9fa01e668c8c"},"inlinedExternals":[],"unexposedExports":[]} */

(() => {

const __ds_ns = (window.WooakDesignSystem_8f397f = window.WooakDesignSystem_8f397f || {});

const __ds_scope = {};

(__ds_ns.__errors = __ds_ns.__errors || []);

// ui_kits/app/App.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/* Wooak product app — Sidebar, Topbar, Dashboard */

function PIcon({
  name,
  size = 16,
  stroke = 1.75
}) {
  const s = {
    width: size,
    height: size
  };
  const p = {
    fill: "none",
    stroke: "currentColor",
    strokeWidth: stroke,
    strokeLinecap: "round",
    strokeLinejoin: "round"
  };
  const paths = {
    home: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M3 12L12 4l9 8M5 10v10h14V10"
    })),
    users: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "9",
      cy: "7",
      r: "4"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M2 21v-2a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v2M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"
    }))),
    calendar: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "3",
      y: "4",
      width: "18",
      height: "18",
      rx: "2"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M16 2v4M8 2v4M3 10h18"
    }))),
    clock: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "9"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 7v5l3 2"
    }))),
    briefcase: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "2",
      y: "7",
      width: "20",
      height: "14",
      rx: "2"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"
    }))),
    dollar: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"
    })),
    target: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "9"
    })), /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "5"
    })), /*#__PURE__*/React.createElement("circle", {
      cx: "12",
      cy: "12",
      r: "1.4",
      fill: "currentColor"
    })),
    pin: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"
    })), /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "10",
      r: "3"
    }))),
    layers: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"
    })),
    ticket: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M3 8a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4z"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M9 6v12"
    }))),
    folder: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"
    })),
    bell: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M10 21a2 2 0 0 0 4 0"
    }))),
    search: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "11",
      cy: "11",
      r: "7"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M21 21l-4.3-4.3"
    }))),
    plus: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 5v14M5 12h14"
    })),
    chev: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M6 9l6 6 6-6"
    })),
    arrow: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M5 12h14M13 5l7 7-7 7"
    })),
    sparkle: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 3l1.6 4.6L18 9l-4.4 1.4L12 15l-1.6-4.6L6 9l4.4-1.4z"
    })),
    settings: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "3"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9 1.65 1.65 0 0 0 4.27 7.18l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6 1.65 1.65 0 0 0 10 3.09V3a2 2 0 0 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.6.24 1 .8 1 1.51V11a2 2 0 0 1 0 4h-.09c-.7 0-1.27.4-1.51 1z"
    })))
  };
  return /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 24 24",
    style: s,
    "aria-hidden": "true"
  }, paths[name] || null);
}
function Sidebar({
  active,
  onNav
}) {
  const main = [{
    k: "today",
    label: "Today",
    icon: "home",
    count: null
  }, {
    k: "people",
    label: "People",
    icon: "users",
    count: 238
  }, {
    k: "hiring",
    label: "Hiring",
    icon: "briefcase",
    count: 6
  }, {
    k: "calendar",
    label: "Calendar",
    icon: "calendar",
    count: null
  }, {
    k: "leave",
    label: "Time off",
    icon: "clock",
    count: 4
  }, {
    k: "payroll",
    label: "Payroll",
    icon: "dollar",
    count: null
  }];
  const ops = [{
    k: "performance",
    label: "Performance",
    icon: "target",
    count: null
  }, {
    k: "attendance",
    label: "Attendance",
    icon: "pin",
    count: null
  }, {
    k: "projects",
    label: "Projects",
    icon: "layers",
    count: null
  }, {
    k: "helpdesk",
    label: "Helpdesk",
    icon: "ticket",
    count: 12
  }, {
    k: "assets",
    label: "Assets",
    icon: "folder",
    count: null
  }];
  const Link = ({
    it
  }) => /*#__PURE__*/React.createElement("a", {
    className: `side__link ${active === it.k ? "active" : ""}`,
    onClick: () => onNav(it.k)
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: it.icon
  }), /*#__PURE__*/React.createElement("span", null, it.label), it.count != null && /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, it.count));
  return /*#__PURE__*/React.createElement("aside", {
    className: "side"
  }, /*#__PURE__*/React.createElement("div", {
    className: "side__brand"
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/wooak-logo.png",
    alt: ""
  }), /*#__PURE__*/React.createElement("span", {
    className: "word"
  }, "wooak")), main.map(it => /*#__PURE__*/React.createElement(Link, {
    key: it.k,
    it: it
  })), /*#__PURE__*/React.createElement("div", {
    className: "side__group"
  }, "Operations"), ops.map(it => /*#__PURE__*/React.createElement(Link, {
    key: it.k,
    it: it
  })), /*#__PURE__*/React.createElement("div", {
    className: "side__user"
  }, /*#__PURE__*/React.createElement("div", {
    className: "av"
  }, "MC"), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "name"
  }, "Maya Chen"), /*#__PURE__*/React.createElement("div", {
    className: "role"
  }, "Halcyon Studio \xB7 Admin")), /*#__PURE__*/React.createElement("button", {
    className: "icon-btn",
    style: {
      width: 28,
      height: 28
    },
    "aria-label": "Settings"
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "settings",
    size: 14
  }))));
}
function Topbar({
  onSpark
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "topbar"
  }, /*#__PURE__*/React.createElement("div", {
    className: "search-wrap"
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "search",
    size: 15
  }), /*#__PURE__*/React.createElement("input", {
    className: "search",
    placeholder: "Search people, jobs, payroll runs\u2026"
  })), /*#__PURE__*/React.createElement("div", {
    className: "actions"
  }, /*#__PURE__*/React.createElement("button", {
    className: "icon-btn",
    "aria-label": "AI assist",
    onClick: onSpark,
    title: "Wooak AI",
    style: {
      color: "#F97316"
    }
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "sparkle"
  })), /*#__PURE__*/React.createElement("button", {
    className: "icon-btn",
    "aria-label": "Notifications",
    style: {
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "bell"
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      position: "absolute",
      top: 6,
      right: 8,
      width: 7,
      height: 7,
      borderRadius: "50%",
      background: "#F97316",
      boxShadow: "0 0 0 3px var(--bg-elevated)"
    }
  })), /*#__PURE__*/React.createElement("button", {
    className: "grad-btn"
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "plus",
    size: 14
  }), " New")));
}

/* ----------------------------- DASHBOARD ----------------------------- */
function Dashboard() {
  return /*#__PURE__*/React.createElement("div", {
    className: "content"
  }, /*#__PURE__*/React.createElement("div", {
    className: "phead"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "crumb"
  }, "Today \xB7 Tue, May 17 \xB7 2026"), /*#__PURE__*/React.createElement("h1", null, "Good morning, Maya.")), /*#__PURE__*/React.createElement("div", {
    className: "right"
  }, /*#__PURE__*/React.createElement("button", {
    className: "btn-ghost"
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "calendar",
    size: 14
  }), " May 1 \u2013 17"), /*#__PURE__*/React.createElement("button", {
    className: "btn-ghost"
  }, "Export"))), /*#__PURE__*/React.createElement("div", {
    className: "kpis"
  }, /*#__PURE__*/React.createElement(Kpi, {
    label: "Headcount",
    val: "238",
    delta: "+4 this month",
    dir: "up"
  }), /*#__PURE__*/React.createElement(Kpi, {
    label: "Attendance today",
    val: "94%",
    delta: "+2.1% vs last wk",
    dir: "up"
  }), /*#__PURE__*/React.createElement(Kpi, {
    label: "Open roles",
    val: "6",
    delta: "2 in offer",
    dir: "up"
  }), /*#__PURE__*/React.createElement(Kpi, {
    label: "Pay run \xB7 April",
    val: "$284,310",
    delta: "1 anomaly",
    dir: "down"
  })), /*#__PURE__*/React.createElement("div", {
    className: "grid2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("h3", null, /*#__PURE__*/React.createElement(PIcon, {
    name: "users"
  }), " Today\u2019s status", /*#__PURE__*/React.createElement("span", {
    className: "more"
  }, "View all \u2192")), /*#__PURE__*/React.createElement("table", {
    className: "tbl"
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "Person"), /*#__PURE__*/React.createElement("th", null, "Status"), /*#__PURE__*/React.createElement("th", null, "Site"), /*#__PURE__*/React.createElement("th", null, "Hours"))), /*#__PURE__*/React.createElement("tbody", null, [["Mia Chen", "MC", "#1E64E6", "Present", "live", "HQ · Berlin", "6h 12m"], ["Jonah Wu", "JW", "#22C55E", "Late", "warn", "HQ · Berlin", "—"], ["Priya Reddy", "PR", "#F97316", "PTO", "muted", "Goa · approved", "—"], ["Dev Sundar", "DS", "#0B2768", "Present", "live", "BLR Office", "5h 04m"], ["Ana Karim", "AK", "#4A9CFF", "WFH", "info", "Approved", "3h 22m"]].map(([n, ini, c, st, kind, where, hrs], i) => {
    const pill = {
      live: {
        bg: "#E8FBEF",
        c: "#15803D",
        d: "#22C55E"
      },
      warn: {
        bg: "#FEF7E6",
        c: "#B45309",
        d: "#F59E0B"
      },
      muted: {
        bg: "var(--bg-muted)",
        c: "var(--fg-muted)",
        d: "#6B6A63"
      },
      info: {
        bg: "#EAF1FE",
        c: "#1547B0",
        d: "#1E64E6"
      }
    }[kind];
    return /*#__PURE__*/React.createElement("tr", {
      key: n
    }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("div", {
      className: "row-emp"
    }, /*#__PURE__*/React.createElement("div", {
      className: "av",
      style: {
        background: c
      }
    }, ini), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
      style: {
        fontWeight: 600
      }
    }, n), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        color: "var(--fg-muted)"
      }
    }, "Engineering")))), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("span", {
      className: "pill",
      style: {
        background: pill.bg,
        color: pill.c
      }
    }, /*#__PURE__*/React.createElement("span", {
      className: "d",
      style: {
        background: pill.d
      }
    }), st)), /*#__PURE__*/React.createElement("td", {
      style: {
        color: "var(--fg-muted)"
      }
    }, where), /*#__PURE__*/React.createElement("td", {
      style: {
        fontFamily: "var(--font-mono)"
      }
    }, hrs));
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      background: "linear-gradient(135deg, #FFF1E6, var(--bg-elevated))",
      borderColor: "rgba(249,115,22,0.25)"
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      color: "#C2410C"
    }
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "sparkle"
  }), " Wooak AI \xB7 suggestions"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 10,
      marginTop: 4
    }
  }, ["3 candidates ready for Senior Designer →", "Promote Mia Chen — 92nd %ile in 360° →", "Overtime anomaly: J. Wu, Tue 22:00–02:00 →"].map((t, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      background: "var(--bg-elevated)",
      padding: "10px 12px",
      borderRadius: 10,
      fontSize: 13,
      fontWeight: 500,
      cursor: "pointer",
      border: "1px solid var(--border-soft)"
    }
  }, t)))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("h3", null, /*#__PURE__*/React.createElement(PIcon, {
    name: "clock"
  }), " Approvals \xB7 4 pending"), [["Mia Chen", "PTO · 2 days", "#22C55E"], ["Jonah Wu", "Sick · today", "#F59E0B"], ["Ana Karim", "WFH · Fri", "#1E64E6"], ["Reggie T.", "Comp time", "#0B2768"]].map(([n, x, c]) => /*#__PURE__*/React.createElement("div", {
    key: n,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "8px 0",
      borderBottom: "1px dashed var(--border)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 26,
      height: 26,
      borderRadius: "50%",
      background: c,
      color: "#fff",
      display: "grid",
      placeItems: "center",
      fontSize: 10,
      fontWeight: 800
    }
  }, n[0]), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      fontSize: 13
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600
    }
  }, n), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--fg-muted)",
      fontSize: 11.5
    }
  }, x)), /*#__PURE__*/React.createElement("button", {
    className: "grad-btn",
    style: {
      height: 28,
      padding: "0 12px",
      fontSize: 12
    }
  }, "Approve")))))), /*#__PURE__*/React.createElement("div", {
    className: "grid3"
  }, /*#__PURE__*/React.createElement(Bars, null), /*#__PURE__*/React.createElement(PayCard, null), /*#__PURE__*/React.createElement(PerfCard, null)));
}
function Kpi({
  label,
  val,
  delta,
  dir
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "kpi"
  }, /*#__PURE__*/React.createElement("div", {
    className: "lab"
  }, label), /*#__PURE__*/React.createElement("div", {
    className: "val"
  }, val), /*#__PURE__*/React.createElement("div", {
    className: `delta ${dir === "up" ? "up" : "down"}`
  }, dir === "up" ? "↑" : "↓", " ", delta), /*#__PURE__*/React.createElement("svg", {
    className: "spark",
    width: "56",
    height: "22",
    viewBox: "0 0 60 24"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2 18 L10 14 L18 16 L26 8 L34 12 L42 6 L50 10 L58 4",
    fill: "none",
    stroke: "url(#kgrad)",
    strokeWidth: "1.8",
    strokeLinecap: "round"
  }), /*#__PURE__*/React.createElement("defs", null, /*#__PURE__*/React.createElement("linearGradient", {
    id: "kgrad",
    x1: "0",
    x2: "1"
  }, /*#__PURE__*/React.createElement("stop", {
    stopColor: "#1E64E6"
  }), /*#__PURE__*/React.createElement("stop", {
    offset: "1",
    stopColor: "#22C55E"
  })))));
}
function Bars() {
  return /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("h3", null, /*#__PURE__*/React.createElement(PIcon, {
    name: "pin"
  }), " Attendance this week"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "end",
      gap: 10,
      height: 130,
      padding: "10px 4px"
    }
  }, [60, 72, 58, 88, 94, 78, 84].map((h, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      flex: 1,
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      height: `${h}%`,
      background: "var(--wk-gradient)",
      opacity: i === 4 ? 1 : 0.6,
      borderRadius: "6px 6px 0 0",
      display: "flex",
      justifyContent: "center",
      alignItems: "flex-start",
      paddingTop: 6,
      color: "#fff",
      fontSize: 10.5,
      fontWeight: 700
    }
  }, h), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--fg-muted)"
    }
  }, ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][i])))));
}
function PayCard() {
  return /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("h3", null, /*#__PURE__*/React.createElement(PIcon, {
    name: "dollar"
  }), " Payroll \xB7 April"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 700,
      fontSize: 32,
      letterSpacing: "-0.025em",
      background: "var(--wk-gradient)",
      WebkitBackgroundClip: "text",
      backgroundClip: "text",
      color: "transparent",
      fontFeatureSettings: '"tnum"'
    }
  }, "$284,310"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "var(--fg-muted)",
      marginTop: 2
    }
  }, "238 employees \xB7 ready to send"), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 14,
      padding: "10px 12px",
      background: "#FFF1E6",
      borderRadius: 10,
      display: "flex",
      gap: 10,
      alignItems: "center",
      fontSize: 12.5
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: "#F97316",
      boxShadow: "0 0 0 4px rgba(249,115,22,.18)"
    }
  }), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("b", null, "1 anomaly:"), " overtime \xB7 J. Wu")), /*#__PURE__*/React.createElement("button", {
    className: "grad-btn",
    style: {
      width: "100%",
      marginTop: 12
    }
  }, "Review & send"));
}
function PerfCard() {
  const items = [{
    t: "Ship V2 platform",
    p: 78,
    c: "#1E64E6"
  }, {
    t: "Cut churn → 5%",
    p: 52,
    c: "#22C55E"
  }, {
    t: "Hire 12 engineers",
    p: 91,
    c: "#F97316"
  }];
  return /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("h3", null, /*#__PURE__*/React.createElement(PIcon, {
    name: "target"
  }), " Q2 OKRs"), items.map(it => /*#__PURE__*/React.createElement("div", {
    key: it.t,
    style: {
      marginBottom: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "space-between",
      fontSize: 12.5,
      fontWeight: 600
    }
  }, /*#__PURE__*/React.createElement("span", null, it.t), /*#__PURE__*/React.createElement("span", {
    style: {
      color: it.c
    }
  }, it.p, "%")), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 6,
      background: "var(--border-soft)",
      borderRadius: 99,
      marginTop: 6
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: `${it.p}%`,
      height: "100%",
      background: it.c,
      borderRadius: 99
    }
  })))));
}

/* ----------------------------- HIRING ----------------------------- */
function Hiring() {
  const cols = [{
    k: "Applied",
    n: 42,
    cards: [["Mia Chen", "Sr. Designer", "#1E64E6"], ["Aanya N.", "Sr. Designer", "#22C55E"], ["Tomás R.", "Sr. Designer", "#F97316"], ["Lina H.", "Sr. Designer", "#0B2768"]]
  }, {
    k: "Phone",
    n: 12,
    cards: [["Mei W.", "Sr. Designer", "#4A9CFF"], ["Sam O.", "Sr. Designer", "#22C55E"], ["Reggie T.", "Sr. Designer", "#1E64E6"]]
  }, {
    k: "Interview",
    n: 6,
    cards: [["Jonah Wu", "Eng Lead", "#22C55E"], ["Priya R.", "Sr. Designer", "#F97316"], ["Dev S.", "Eng Lead", "#0B2768"]]
  }, {
    k: "Offer",
    n: 1,
    cards: [["Ana Karim", "Sr. Designer", "#1E64E6"]]
  }];
  return /*#__PURE__*/React.createElement("div", {
    className: "content"
  }, /*#__PURE__*/React.createElement("div", {
    className: "phead"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "crumb"
  }, "Hiring"), /*#__PURE__*/React.createElement("h1", null, "Sr. Designer \xB7 pipeline")), /*#__PURE__*/React.createElement("div", {
    className: "right"
  }, /*#__PURE__*/React.createElement("button", {
    className: "btn-ghost"
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "sparkle",
    size: 14
  }), " AI screen all"), /*#__PURE__*/React.createElement("button", {
    className: "btn-ghost"
  }, "Share board"))), /*#__PURE__*/React.createElement("div", {
    className: "kb"
  }, cols.map(col => /*#__PURE__*/React.createElement("div", {
    className: "kb__col",
    key: col.k
  }, /*#__PURE__*/React.createElement("h4", null, col.k, " ", /*#__PURE__*/React.createElement("span", {
    className: "n"
  }, col.n)), col.cards.map(([nm, rl, c]) => /*#__PURE__*/React.createElement("div", {
    className: "kb__card",
    key: nm
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 24,
      height: 24,
      borderRadius: "50%",
      background: c,
      color: "#fff",
      display: "grid",
      placeItems: "center",
      fontSize: 10,
      fontWeight: 800
    }
  }, nm[0]), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "nm"
  }, nm), /*#__PURE__*/React.createElement("div", {
    className: "rl"
  }, rl))), /*#__PURE__*/React.createElement("div", {
    className: "ft"
  }, /*#__PURE__*/React.createElement("span", {
    className: "pill",
    style: {
      background: "var(--wk-blue-50)",
      color: "var(--wk-blue-700)"
    }
  }, "4.2 \u2605"), /*#__PURE__*/React.createElement("span", {
    className: "dt"
  }, "add. ", 3 + nm.length % 5, "d")))), /*#__PURE__*/React.createElement("button", {
    className: "btn-ghost",
    style: {
      width: "100%",
      marginTop: 6,
      justifyContent: "center"
    }
  }, /*#__PURE__*/React.createElement(PIcon, {
    name: "plus",
    size: 13
  }), " Add candidate")))));
}

/* App shell */
function AppRoot() {
  const [active, setActive] = React.useState("today");
  return /*#__PURE__*/React.createElement("div", {
    className: "app"
  }, /*#__PURE__*/React.createElement(Sidebar, {
    active: active,
    onNav: setActive
  }), /*#__PURE__*/React.createElement("main", {
    className: "main"
  }, /*#__PURE__*/React.createElement(Topbar, null), active === "hiring" ? /*#__PURE__*/React.createElement(Hiring, null) : /*#__PURE__*/React.createElement(Dashboard, null)));
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(AppRoot, null));
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/app/App.jsx", error: String((e && e.message) || e) }); }

// ui_kits/landing/App.jsx
try { (() => {
// Wooak landing page entry
function App() {
  const [theme, setTheme] = React.useState(() => localStorage.getItem("wk-theme") || "light");
  React.useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("wk-theme", theme);
  }, [theme]);
  return /*#__PURE__*/React.createElement("div", {
    className: "wk-shell"
  }, /*#__PURE__*/React.createElement(BlobCursor, null), /*#__PURE__*/React.createElement(NavBar, {
    theme: theme,
    setTheme: setTheme
  }), /*#__PURE__*/React.createElement(HeroSection, null), /*#__PURE__*/React.createElement(Marquee, null), /*#__PURE__*/React.createElement(BentoGrid, null), /*#__PURE__*/React.createElement(ProductTour, null), /*#__PURE__*/React.createElement(Comparison, null), /*#__PURE__*/React.createElement(Metrics, null), /*#__PURE__*/React.createElement(Testimonials, null), /*#__PURE__*/React.createElement(Integrations, null), /*#__PURE__*/React.createElement(Pricing, null), /*#__PURE__*/React.createElement(FAQ, null), /*#__PURE__*/React.createElement(FinalCTA, null), /*#__PURE__*/React.createElement(Footer, null));
}
const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(/*#__PURE__*/React.createElement(App, null));
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/landing/App.jsx", error: String((e && e.message) || e) }); }

// ui_kits/landing/lib.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
// Wooak landing-page UI primitives — shared across sections
// Loaded as a Babel script. Components are exported to window.
const {
  motion,
  AnimatePresence,
  useScroll,
  useTransform,
  useInView,
  useReducedMotion,
  useMotionValue,
  useSpring
} = window.FramerMotion || {};

/* ------------------------- ICON SET (lucide-style) ------------------------- */
function Icon({
  name,
  size = 18,
  stroke = 1.75,
  className = "",
  style
}) {
  const s = {
    width: size,
    height: size,
    ...style
  };
  const p = {
    fill: "none",
    stroke: "currentColor",
    strokeWidth: stroke,
    strokeLinecap: "round",
    strokeLinejoin: "round"
  };
  const paths = {
    sparkle: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 3l1.6 4.6L18 9l-4.4 1.4L12 15l-1.6-4.6L6 9l4.4-1.4L12 3z"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M19 14l.7 2L22 17l-2.3 1L19 20l-.7-2L16 17l2.3-1z"
    }))),
    arrow: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M5 12h14M13 5l7 7-7 7"
    })),
    play: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M7 4v16l13-8z",
      fill: "currentColor"
    })),
    sun: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "4"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"
    }))),
    moon: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"
    })),
    chev: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M6 9l6 6 6-6"
    })),
    plus: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 5v14M5 12h14"
    })),
    x: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M6 6l12 12M18 6L6 18"
    })),
    check: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M5 12l5 5L20 7"
    })),
    users: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "9",
      cy: "7",
      r: "4"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"
    }))),
    calendar: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "3",
      y: "4",
      width: "18",
      height: "18",
      rx: "2"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M16 2v4M8 2v4M3 10h18"
    }))),
    dollar: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"
    })),
    chart: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M3 3v18h18M7 15l3-3 4 4 6-7"
    })),
    pin: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"
    })), /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "10",
      r: "3"
    }))),
    ring: /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "9"
    })),
    briefcase: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "2",
      y: "7",
      width: "20",
      height: "14",
      rx: "2"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"
    }))),
    grid: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "3",
      y: "3",
      width: "7",
      height: "7"
    })), /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "14",
      y: "3",
      width: "7",
      height: "7"
    })), /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "3",
      y: "14",
      width: "7",
      height: "7"
    })), /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "14",
      y: "14",
      width: "7",
      height: "7"
    }))),
    zap: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M13 2L3 14h7l-1 8 10-12h-7l1-8z"
    })),
    bell: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M10 21a2 2 0 0 0 4 0"
    }))),
    bot: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "3",
      y: "8",
      width: "18",
      height: "12",
      rx: "2"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 2v4M9 13h.01M15 13h.01"
    }))),
    layers: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"
    })),
    target: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "9"
    })), /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "5"
    })), /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "12",
      cy: "12",
      r: "1",
      fill: "currentColor"
    }))),
    shield: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M12 2l8 4v6c0 5-4 9-8 10-4-1-8-5-8-10V6l8-4z"
    })),
    msg: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"
    })),
    search: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", _extends({}, p, {
      cx: "11",
      cy: "11",
      r: "7"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M21 21l-4.3-4.3"
    }))),
    menu: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M3 6h18M3 12h18M3 18h18"
    })),
    arrowUR: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M7 17L17 7M7 7h10v10"
    })),
    arrowDR: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M7 7l10 10M17 7v10H7"
    })),
    twitter: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M22 5.8a8 8 0 0 1-2.4.6 4 4 0 0 0 1.8-2.2 8.5 8.5 0 0 1-2.6 1 4 4 0 0 0-6.8 3.6A11.4 11.4 0 0 1 3 4.7a4 4 0 0 0 1.2 5.3A4 4 0 0 1 2.4 9v.05a4 4 0 0 0 3.2 4 4 4 0 0 1-1.8.07 4 4 0 0 0 3.7 2.8A8 8 0 0 1 2 17.7 11.4 11.4 0 0 0 8.2 19.5c7.5 0 11.6-6.2 11.6-11.6v-.5A8 8 0 0 0 22 5.8z"
    })),
    linkedin: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "2",
      y: "2",
      width: "20",
      height: "20",
      rx: "3"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M7 10v7M7 7v0M11 17v-4a2 2 0 0 1 4 0v4M11 13v4"
    }))),
    youtube: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", _extends({}, p, {
      x: "2",
      y: "5",
      width: "20",
      height: "14",
      rx: "3"
    })), /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M10 9l5 3-5 3z",
      fill: "currentColor"
    }))),
    github: /*#__PURE__*/React.createElement("path", _extends({}, p, {
      d: "M9 19c-4 1-4-2-6-2m12 4v-3.5c0-1 .1-1.5-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12 12 0 0 0-6.4 0C6.3 2.8 5.2 3.1 5.2 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 3.8 9.5c0 4.6 2.7 5.7 5.5 6-.6.5-.6 1-.5 2V21"
    }))
  };
  return /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 24 24",
    className: className,
    style: s,
    "aria-hidden": "true"
  }, paths[name] || null);
}

/* --------------------------------- LOGO ----------------------------------- */
function WLogo({
  size = 28,
  withWord = true,
  white = false
}) {
  return /*#__PURE__*/React.createElement("span", {
    className: "wk-logo",
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/wooak-logo.png",
    alt: "",
    style: {
      width: size,
      height: size,
      filter: white ? "brightness(0) invert(1)" : "none"
    }
  }), withWord && /*#__PURE__*/React.createElement("span", {
    style: {
      fontWeight: 700,
      fontSize: size * 0.66,
      letterSpacing: "-0.02em",
      color: white ? "#fff" : "var(--fg)"
    }
  }, "wooak"));
}

/* ----------------------------- BUTTON --------------------------------- */
function Button({
  variant = "grad",
  size = "md",
  children,
  icon,
  trailing,
  onClick,
  href,
  ariaLabel,
  className = ""
}) {
  const cls = `wk-btn wk-btn--${variant} wk-btn--${size} ${className}`;
  const inner = /*#__PURE__*/React.createElement(React.Fragment, null, icon && /*#__PURE__*/React.createElement("span", {
    className: "wk-btn__icon"
  }, icon), children, trailing && /*#__PURE__*/React.createElement("span", {
    className: "wk-btn__trail"
  }, trailing));
  if (href) return /*#__PURE__*/React.createElement("a", {
    className: cls,
    href: href,
    onClick: onClick,
    "aria-label": ariaLabel
  }, inner);
  return /*#__PURE__*/React.createElement("button", {
    className: cls,
    onClick: onClick,
    "aria-label": ariaLabel
  }, inner);
}

/* ----------------------------- SECTION REVEAL --------------------------- */
function Reveal({
  children,
  delay = 0,
  y = 24,
  once = true,
  as: As = "div",
  style,
  className
}) {
  const reduce = useReducedMotion();
  const ref = React.useRef(null);
  const inView = useInView(ref, {
    once,
    margin: "-10% 0px -10% 0px"
  });
  if (reduce) return /*#__PURE__*/React.createElement(As, {
    ref: ref,
    className: className,
    style: style
  }, children);
  return /*#__PURE__*/React.createElement(motion.div, {
    ref: ref,
    initial: {
      opacity: 0,
      y
    },
    animate: inView ? {
      opacity: 1,
      y: 0
    } : {},
    transition: {
      duration: 0.6,
      delay,
      ease: [0.22, 1, 0.36, 1]
    },
    className: className,
    style: style
  }, children);
}
function Stagger({
  children,
  gap = 0.06,
  y = 24,
  once = true,
  className,
  style
}) {
  const reduce = useReducedMotion();
  const ref = React.useRef(null);
  const inView = useInView(ref, {
    once,
    margin: "-10% 0px -10% 0px"
  });
  if (reduce) return /*#__PURE__*/React.createElement("div", {
    ref: ref,
    className: className,
    style: style
  }, children);
  return /*#__PURE__*/React.createElement(motion.div, {
    ref: ref,
    initial: "hidden",
    animate: inView ? "show" : "hidden",
    variants: {
      show: {
        transition: {
          staggerChildren: gap
        }
      }
    },
    className: className,
    style: style
  }, React.Children.map(children, (c, i) => /*#__PURE__*/React.createElement(motion.div, {
    key: i,
    variants: {
      hidden: {
        opacity: 0,
        y
      },
      show: {
        opacity: 1,
        y: 0,
        transition: {
          duration: 0.6,
          ease: [0.22, 1, 0.36, 1]
        }
      }
    }
  }, c)));
}

/* ----------------------------- BLOB CURSOR -------------------------------- */
function BlobCursor() {
  const reduce = useReducedMotion();
  const ref = React.useRef(null);
  const x = useMotionValue(-100),
    y = useMotionValue(-100);
  const sx = useSpring(x, {
    stiffness: 350,
    damping: 28,
    mass: 0.4
  });
  const sy = useSpring(y, {
    stiffness: 350,
    damping: 28,
    mass: 0.4
  });
  const [hot, setHot] = React.useState(false);
  const [isDark, setIsDark] = React.useState(() => document.documentElement.dataset.theme === 'dark');
  React.useEffect(() => {
    const obs = new MutationObserver(() => setIsDark(document.documentElement.dataset.theme === 'dark'));
    obs.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme']
    });
    return () => obs.disconnect();
  }, []);
  React.useEffect(() => {
    if (reduce) return;
    const isCoarse = window.matchMedia('(pointer:coarse)').matches;
    if (isCoarse) return;
    const move = e => {
      x.set(e.clientX);
      y.set(e.clientY);
    };
    const enter = e => {
      if (e.target.closest('[data-cursor-hot]')) setHot(true);
    };
    const leave = e => {
      if (e.target.closest('[data-cursor-hot]')) setHot(false);
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseover', enter);
    window.addEventListener('mouseout', leave);
    return () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseover', enter);
      window.removeEventListener('mouseout', leave);
    };
  }, [reduce]);
  if (reduce) return null;
  return /*#__PURE__*/React.createElement(motion.div, {
    "aria-hidden": "true",
    className: "wk-cursor",
    style: {
      position: "fixed",
      top: 0,
      left: 0,
      width: 24,
      height: 24,
      borderRadius: "50%",
      pointerEvents: "none",
      x: sx,
      y: sy,
      translateX: "-50%",
      translateY: "-50%",
      zIndex: 99,
      background: hot ? "var(--wk-gradient)" : isDark ? "rgba(244,244,238,0.55)" : "rgba(10,10,10,0.45)",
      mixBlendMode: hot ? "normal" : isDark ? "screen" : "multiply",
      transition: "background 200ms ease, transform 200ms ease",
      transform: `translate(-50%,-50%) scale(${hot ? 1.6 : 1})`,
      filter: "blur(2px)",
      opacity: 0.85
    }
  });
}
Object.assign(window, {
  Icon,
  WLogo,
  Button,
  Reveal,
  Stagger,
  BlobCursor
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/landing/lib.jsx", error: String((e && e.message) || e) }); }

// ui_kits/landing/sections-bottom.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
// Wooak landing — Comparison, Metrics, Testimonials, Integrations, Pricing, FAQ, Final CTA, Footer
const {
  motion: m2,
  AnimatePresence: AP2,
  useScroll: useScrl2,
  useTransform: useT2,
  useInView: useIV2,
  useReducedMotion: useRM2
} = window.FramerMotion || {};

/* ----------------------------- COMPARISON ----------------------------- */
function Comparison() {
  const tools = [{
    n: "Greenhouse",
    h: 0
  }, {
    n: "BambooHR",
    h: 1
  }, {
    n: "Gusto",
    h: 2
  }, {
    n: "Slack",
    h: 3
  }, {
    n: "Lattice",
    h: 4
  }, {
    n: "Notion",
    h: 5
  }];
  const containerRef = React.useRef(null);
  const inView = useIV2(containerRef, {
    once: true,
    margin: "-15% 0px"
  });
  const reduce = useRM2();
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-shead"
  }, /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("span", {
    className: "wk-shead__eyebrow"
  }, "Why teams switch to Wooak")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.05
  }, /*#__PURE__*/React.createElement("h2", {
    className: "wk-shead__title"
  }, "Six tools, one tab."))), /*#__PURE__*/React.createElement("div", {
    ref: containerRef,
    className: "wk-compare"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-compare__col wk-compare__col--old"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-compare__eyebrow"
  }, "The old way"), /*#__PURE__*/React.createElement("h3", {
    className: "wk-compare__title"
  }, "Six tabs. Two spreadsheets."), /*#__PURE__*/React.createElement("p", {
    className: "wk-compare__desc"
  }, "Plus one Slack channel called ", /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)"
    }
  }, "#hr-ops-help"), "."), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      marginTop: 32,
      height: 200
    }
  }, tools.map((t, i) => {
    const startX = (i % 3 - 1) * 80;
    const startY = Math.floor(i / 3) * 70 - 30;
    return /*#__PURE__*/React.createElement(m2.div, {
      key: t.n,
      initial: {
        x: startX,
        y: startY,
        opacity: 1,
        scale: 1
      },
      animate: inView && !reduce ? {
        x: 0,
        y: 0,
        opacity: 0.05,
        scale: 0.4
      } : {},
      transition: {
        duration: 1.2,
        delay: 0.8 + i * 0.05,
        ease: [0.22, 1, 0.36, 1]
      },
      style: {
        position: "absolute",
        left: "50%",
        top: "50%",
        transform: "translate(-50%,-50%)",
        background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        borderRadius: 10,
        padding: "8px 12px",
        fontSize: 12,
        fontWeight: 600,
        color: "var(--fg-muted)",
        boxShadow: "var(--shadow-sm)",
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        whiteSpace: "nowrap"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 8,
        height: 8,
        borderRadius: 2,
        background: ["#1E64E6", "#22C55E", "#F97316", "#0A4424", "#4A9CFF", "#C2410C"][i]
      }
    }), t.n);
  }))), /*#__PURE__*/React.createElement("div", {
    className: "wk-compare__col wk-compare__col--new"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-compare__eyebrow wk-compare__eyebrow--blue"
  }, "The Wooak way"), /*#__PURE__*/React.createElement("h3", {
    className: "wk-compare__title"
  }, "One app. The whole team."), /*#__PURE__*/React.createElement("p", {
    className: "wk-compare__desc"
  }, "Hiring, payroll, performance, and the rest \u2014 together at last."), /*#__PURE__*/React.createElement("div", {
    className: "wk-compare__stage"
  }, /*#__PURE__*/React.createElement(m2.div, {
    animate: !reduce ? {
      boxShadow: ["0 0 0 0 rgba(30,100,230,0.4)", "0 0 0 30px rgba(34,197,94,0)", "0 0 0 0 rgba(30,100,230,0.4)"]
    } : {},
    transition: {
      duration: 3,
      repeat: Infinity,
      ease: "easeInOut"
    },
    style: {
      width: 160,
      height: 160,
      borderRadius: 32,
      background: "var(--wk-gradient)",
      display: "grid",
      placeItems: "center",
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/wooak-logo.png",
    style: {
      width: 110,
      height: 110,
      filter: "brightness(0) invert(1)"
    },
    alt: ""
  })))), /*#__PURE__*/React.createElement("div", {
    className: "wk-compare__col wk-compare__col--reaction"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-compare__eyebrow wk-compare__eyebrow--spark"
  }, "Your team's reaction"), /*#__PURE__*/React.createElement("h3", {
    className: "wk-compare__title"
  }, "Light. Audible. Disbelief."), /*#__PURE__*/React.createElement("div", {
    className: "wk-compare__stage"
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 8
    }
  }, ["#1E64E6", "#22C55E", "#F97316", "#0B2768", "#4A9CFF"].map((c, i) => /*#__PURE__*/React.createElement(m2.div, {
    key: i,
    initial: {
      y: 0
    },
    animate: !reduce ? {
      y: [0, -6, 0]
    } : {},
    transition: {
      duration: 2 + i * 0.4,
      repeat: Infinity,
      delay: i * 0.2
    },
    style: {
      width: 46,
      height: 46,
      borderRadius: "50%",
      background: c,
      color: "#fff",
      display: "grid",
      placeItems: "center",
      fontWeight: 800,
      fontSize: 16,
      boxShadow: "0 8px 18px rgba(10,15,40,0.18)"
    }
  }, "MJPDR"[i]))), /*#__PURE__*/React.createElement(m2.div, {
    initial: {
      opacity: 0,
      y: 8
    },
    animate: inView ? {
      opacity: 1,
      y: 0
    } : {},
    transition: {
      delay: 1.6,
      duration: 0.5
    },
    style: {
      position: "absolute",
      top: "20%",
      right: "12%",
      background: "var(--bg-elevated)",
      border: "1px solid var(--border)",
      borderRadius: 16,
      padding: "10px 14px",
      fontFamily: "var(--font-serif)",
      fontStyle: "italic",
      fontSize: 14.5,
      boxShadow: "var(--shadow-md)",
      maxWidth: 230,
      lineHeight: 1.3
    }
  }, "\"wait, this is all one app?\"", /*#__PURE__*/React.createElement("span", {
    style: {
      position: "absolute",
      left: -7,
      bottom: 12,
      width: 14,
      height: 14,
      background: "var(--bg-elevated)",
      border: "1px solid var(--border)",
      borderRight: "none",
      borderTop: "none",
      transform: "rotate(45deg)"
    }
  })))))));
}

/* ------------------------------- METRICS ------------------------------- */
function Metrics() {
  const items = [{
    value: 4200,
    suffix: "+",
    label: "teams"
  }, {
    value: 1.2,
    suffix: "M",
    label: "employees managed",
    decimals: 1
  }, {
    value: 840,
    prefix: "$",
    suffix: "M",
    label: "payroll processed / mo"
  }, {
    value: 98,
    suffix: "%",
    label: "retention"
  }];
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-section wk-section--tight"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-metrics"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-metrics__grid"
  }, items.map(it => /*#__PURE__*/React.createElement(Counter, _extends({
    key: it.label
  }, it)))))));
}
function Counter({
  value,
  label,
  prefix = "",
  suffix = "",
  decimals = 0
}) {
  const ref = React.useRef(null);
  const inView = useIV2(ref, {
    once: true
  });
  const reduce = useRM2();
  const [v, setV] = React.useState(0);
  React.useEffect(() => {
    if (!inView) return;
    if (reduce) {
      setV(value);
      return;
    }
    let raf, start;
    const tick = t => {
      if (!start) start = t;
      const k = Math.min((t - start) / 1800, 1);
      const eased = 1 - Math.pow(1 - k, 4);
      setV(value * eased);
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView]);
  const display = decimals ? v.toFixed(decimals) : Math.round(v).toLocaleString();
  return /*#__PURE__*/React.createElement("div", {
    ref: ref
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-metrics__num"
  }, prefix, display, suffix), /*#__PURE__*/React.createElement("div", {
    className: "wk-metrics__label"
  }, label));
}

/* ----------------------------- TESTIMONIALS ---------------------------- */
const quotes = [{
  text: "We replaced four contracts in our first month. Payroll, ATS, and OKRs in one tab — our ops lead has time to breathe.",
  name: "Maya Chen",
  role: "COO · Halcyon Studio",
  brand: "halcyon",
  color: "#1E64E6"
}, {
  text: "Onboarding day used to be a scavenger hunt for accounts. Wooak hands a new hire one tab and a friendly checklist.",
  name: "Dev Patel",
  role: "Head of People · Plural",
  brand: "plural",
  color: "#22C55E"
}, {
  text: "The anomaly flag caught an overtime entry that would have cost us $4k. Honestly, paid for itself in week two.",
  name: "Reggie Thompson",
  role: "Finance Lead · Fieldhouse",
  brand: "fieldhouse",
  color: "#F97316"
}];
function Testimonials() {
  const trackRef = React.useRef(null);
  const [i, setI] = React.useState(0);
  const reduce = useRM2();
  const advance = dir => setI(prev => (prev + dir + quotes.length) % quotes.length);
  React.useEffect(() => {
    if (reduce) return;
    let id = setInterval(() => advance(1), 6000);
    const t = trackRef.current;
    const stop = () => clearInterval(id);
    const start = () => {
      id = setInterval(() => advance(1), 6000);
    };
    t && t.addEventListener("mouseenter", stop);
    t && t.addEventListener("mouseleave", start);
    return () => {
      clearInterval(id);
      t && t.removeEventListener("mouseenter", stop);
      t && t.removeEventListener("mouseleave", start);
    };
  }, []);
  React.useEffect(() => {
    const k = e => {
      if (e.key === "ArrowRight") advance(1);
      if (e.key === "ArrowLeft") advance(-1);
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);
  const q = quotes[i];
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-shead"
  }, /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("span", {
    className: "wk-shead__eyebrow"
  }, "From the people doing the work")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.05
  }, /*#__PURE__*/React.createElement("h2", {
    className: "wk-shead__title"
  }, "No screenshots. Real teams."))), /*#__PURE__*/React.createElement("div", {
    ref: trackRef,
    style: {
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement(AP2, {
    mode: "wait"
  }, /*#__PURE__*/React.createElement(m2.div, {
    key: i,
    initial: {
      opacity: 0,
      y: 20
    },
    animate: {
      opacity: 1,
      y: 0
    },
    exit: {
      opacity: 0,
      y: -20
    },
    transition: {
      duration: 0.55,
      ease: [0.22, 1, 0.36, 1]
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-quote-card",
    style: {
      width: "100%",
      maxWidth: 1080,
      margin: "0 auto"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-serif)",
      fontStyle: "italic",
      fontSize: "clamp(22px, 2.4vw, 34px)",
      lineHeight: 1.25,
      letterSpacing: "-0.01em"
    }
  }, "\"", q.text, "\""), /*#__PURE__*/React.createElement("div", {
    className: "wk-quote-card__author"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-quote-card__av",
    style: {
      background: q.color,
      color: "#fff",
      display: "grid",
      placeItems: "center",
      fontWeight: 800
    }
  }, q.name[0]), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "wk-quote-card__name"
  }, q.name), /*#__PURE__*/React.createElement("div", {
    className: "wk-quote-card__role"
  }, q.role)), /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto"
    },
    className: "wk-quote-card__brand"
  }, q.brand))), /*#__PURE__*/React.createElement("div", {
    className: "wk-quote-card__visual",
    style: {
      background: `linear-gradient(135deg, ${q.color}22, var(--bg-muted))`
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      display: "grid",
      placeItems: "center",
      color: q.color,
      fontWeight: 800,
      fontSize: 78,
      letterSpacing: "-0.04em",
      opacity: 0.18
    }
  }, q.brand), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      bottom: 14,
      left: 16,
      right: 16,
      fontSize: 12,
      color: "var(--fg-muted)",
      display: "flex",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("b", {
    style: {
      color: q.color
    }
  }, "\u221242%"), " tool spend"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("b", {
    style: {
      color: q.color
    }
  }, "4\xD7"), " faster onboarding")))))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "center",
      gap: 8,
      marginTop: 24
    }
  }, quotes.map((_, k) => /*#__PURE__*/React.createElement("button", {
    key: k,
    onClick: () => setI(k),
    "aria-label": `Quote ${k + 1}`,
    style: {
      width: k === i ? 28 : 8,
      height: 8,
      border: "none",
      borderRadius: 99,
      background: k === i ? "var(--wk-gradient)" : "var(--border-strong)",
      cursor: "pointer",
      transition: "all 300ms var(--ease-out-quint)"
    }
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      top: "50%",
      left: -8,
      right: -8,
      display: "flex",
      justifyContent: "space-between",
      pointerEvents: "none",
      transform: "translateY(-50%)"
    }
  }, /*#__PURE__*/React.createElement("button", {
    "aria-label": "Previous",
    onClick: () => advance(-1),
    className: "wk-btn wk-btn--ghost",
    style: {
      width: 44,
      height: 44,
      padding: 0,
      borderRadius: "50%",
      pointerEvents: "auto",
      background: "var(--bg-elevated)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "arrow",
    size: 16,
    style: {
      transform: "rotate(180deg)"
    }
  })), /*#__PURE__*/React.createElement("button", {
    "aria-label": "Next",
    onClick: () => advance(1),
    className: "wk-btn wk-btn--ghost",
    style: {
      width: 44,
      height: 44,
      padding: 0,
      borderRadius: "50%",
      pointerEvents: "auto",
      background: "var(--bg-elevated)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "arrow",
    size: 16
  }))))));
}

/* ----------------------------- INTEGRATIONS ---------------------------- */
const integrations = ["Slack", "Google", "Microsoft", "Zoom", "Stripe", "Xero", "QuickBooks", "Greenhouse", "Notion", "Linear", "GitHub", "Okta", "Workday", "Asana", "Figma", "Loom"];
function Integrations() {
  const reduce = useRM2();
  const [paused, setPaused] = React.useState(null);
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-shead"
  }, /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("span", {
    className: "wk-shead__eyebrow"
  }, "Plays nicely with the rest of your stack")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.05
  }, /*#__PURE__*/React.createElement("h2", {
    className: "wk-shead__title"
  }, "Sixteen integrations.", /*#__PURE__*/React.createElement("br", null), "Or pretend they're not even there."))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: "min(680px, 100%)",
      margin: "0 auto",
      aspectRatio: "1 / 1"
    }
  }, /*#__PURE__*/React.createElement(m2.div, {
    animate: paused === null && !reduce ? {
      rotate: 360
    } : {
      rotate: 0
    },
    transition: {
      duration: 40,
      repeat: Infinity,
      ease: "linear"
    },
    style: {
      position: "absolute",
      inset: 0,
      borderRadius: "50%",
      border: "1px dashed var(--border-strong)"
    }
  }, integrations.slice(0, 8).map((n, i) => {
    const a = i / 8 * Math.PI * 2;
    return /*#__PURE__*/React.createElement(Orbit, {
      key: n,
      name: n,
      a: a,
      r: "48%",
      idx: i,
      setPaused: setPaused,
      paused: paused
    });
  })), /*#__PURE__*/React.createElement(m2.div, {
    animate: paused === null && !reduce ? {
      rotate: -360
    } : {
      rotate: 0
    },
    transition: {
      duration: 30,
      repeat: Infinity,
      ease: "linear"
    },
    style: {
      position: "absolute",
      inset: "16%",
      borderRadius: "50%",
      border: "1px dashed var(--border-strong)"
    }
  }, integrations.slice(8, 16).map((n, i) => {
    const a = i / 8 * Math.PI * 2;
    return /*#__PURE__*/React.createElement(Orbit, {
      key: n,
      name: n,
      a: a,
      r: "50%",
      idx: i + 8,
      setPaused: setPaused,
      paused: paused,
      reverse: true
    });
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      display: "grid",
      placeItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 124,
      height: 124,
      borderRadius: 28,
      background: "var(--wk-gradient)",
      display: "grid",
      placeItems: "center",
      boxShadow: "0 30px 60px -20px rgba(30,100,230,0.45)"
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/wooak-logo.png",
    style: {
      width: 88,
      height: 88,
      filter: "brightness(0) invert(1)"
    },
    alt: ""
  }))))));
}
function Orbit({
  name,
  a,
  r,
  idx,
  setPaused,
  paused,
  reverse
}) {
  const x = 50 + Math.cos(a) * parseFloat(r);
  const y = 50 + Math.sin(a) * parseFloat(r);
  const isPaused = paused === idx;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      left: `${x}%`,
      top: `${y}%`,
      transform: "translate(-50%, -50%)"
    }
  }, /*#__PURE__*/React.createElement(m2.div, {
    animate: !isPaused ? {
      rotate: reverse ? 360 : -360
    } : {
      rotate: 0
    },
    transition: {
      duration: reverse ? 30 : 40,
      repeat: Infinity,
      ease: "linear"
    },
    onMouseEnter: () => setPaused(idx),
    onMouseLeave: () => setPaused(null),
    "data-cursor-hot": true,
    style: {
      width: 64,
      height: 64,
      background: "var(--bg-elevated)",
      border: "1px solid var(--border)",
      borderRadius: 18,
      display: "grid",
      placeItems: "center",
      boxShadow: "var(--shadow-sm)",
      cursor: "pointer",
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontWeight: 700,
      fontSize: 13,
      color: "var(--fg)",
      letterSpacing: "-0.01em"
    }
  }, name.slice(0, 2)), isPaused && /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      bottom: -34,
      left: "50%",
      transform: "translateX(-50%)",
      background: "var(--wk-ink)",
      color: "#fff",
      fontSize: 11,
      padding: "5px 10px",
      borderRadius: 8,
      whiteSpace: "nowrap"
    }
  }, name)));
}

/* -------------------------------- PRICING -------------------------------- */
const plans = [{
  id: "starter",
  name: "Starter",
  price: {
    mo: 0,
    yr: 0
  },
  desc: "For the first 25 people on the team. Free, forever.",
  features: ["Employees + HR core", "Time-off + shifts", "Recruitment (1 open role)", "Email support"],
  cta: "Get started",
  variant: "ghost"
}, {
  id: "growth",
  name: "Growth",
  price: {
    mo: 7,
    yr: 6
  },
  desc: "For teams of 25–500 doing real people ops. Best fit.",
  features: ["Everything in Starter", "Payroll + payslips", "Performance + 360°", "Geofenced attendance", "Integrations (16)", "Priority support"],
  cta: "Start free trial",
  variant: "grad",
  popular: true
}, {
  id: "ent",
  name: "Enterprise",
  price: {
    mo: "Talk",
    yr: "Talk"
  },
  desc: "For 500+ with custom roles, SSO, and dedicated CSM.",
  features: ["Everything in Growth", "SSO + SCIM + audit log", "Custom roles + workflows", "DPA + region pinning", "Dedicated success manager"],
  cta: "Contact sales",
  variant: "ink"
}];
function Pricing() {
  const [billing, setBilling] = React.useState("yr");
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-shead"
  }, /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("span", {
    className: "wk-shead__eyebrow"
  }, "Pricing that doesn't grow legs")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.05
  }, /*#__PURE__*/React.createElement("h2", {
    className: "wk-shead__title"
  }, "Free under 25 people.", /*#__PURE__*/React.createElement("br", null), "Honest above.")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.12
  }, /*#__PURE__*/React.createElement("div", {
    className: "seg-toggle",
    role: "tablist",
    style: {
      display: "inline-flex",
      padding: 4,
      background: "var(--bg-muted)",
      borderRadius: 999,
      gap: 4,
      marginTop: 10
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setBilling("mo"),
    className: "wk-btn wk-btn--sm",
    style: {
      background: billing === "mo" ? "var(--bg-elevated)" : "transparent",
      color: "var(--fg)",
      boxShadow: billing === "mo" ? "var(--shadow-sm)" : "none"
    }
  }, "Monthly"), /*#__PURE__*/React.createElement("button", {
    onClick: () => setBilling("yr"),
    className: "wk-btn wk-btn--sm",
    style: {
      background: billing === "yr" ? "var(--bg-elevated)" : "transparent",
      color: "var(--fg)",
      boxShadow: billing === "yr" ? "var(--shadow-sm)" : "none"
    }
  }, "Annual ", /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: 6,
      color: "var(--wk-green-700)",
      fontWeight: 700
    }
  }, "\xB7 save 20%"))))), /*#__PURE__*/React.createElement(Stagger, {
    gap: 0.08,
    className: "wk-price-grid"
  }, plans.map(plan => /*#__PURE__*/React.createElement(PricingCard, {
    key: plan.id,
    plan: plan,
    billing: billing
  })))));
}
function PricingCard({
  plan,
  billing
}) {
  const p = plan.price[billing];
  return /*#__PURE__*/React.createElement("div", {
    className: `wk-price-card ${plan.popular ? "wk-price-card--pop" : ""}`
  }, plan.popular && /*#__PURE__*/React.createElement("span", {
    className: "pop"
  }, "\u2726 Most popular"), /*#__PURE__*/React.createElement("h3", null, plan.name), /*#__PURE__*/React.createElement("p", {
    className: "desc"
  }, plan.desc), /*#__PURE__*/React.createElement("div", {
    className: "price"
  }, typeof p === "number" ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("span", {
    className: "big",
    style: {
      display: "inline-flex",
      alignItems: "baseline"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 30,
      marginRight: 2
    }
  }, "$"), /*#__PURE__*/React.createElement(PriceDigits, {
    value: p
  })), /*#__PURE__*/React.createElement("span", {
    className: "per"
  }, "/ employee \xB7 ", billing === "mo" ? "month" : "month, billed yearly")) : /*#__PURE__*/React.createElement("span", {
    className: "big",
    style: {
      fontSize: 40
    }
  }, p)), /*#__PURE__*/React.createElement("ul", null, plan.features.map(f => /*#__PURE__*/React.createElement("li", {
    key: f
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "check",
    size: 16
  }), " ", f))), /*#__PURE__*/React.createElement("div", {
    className: "cta"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: plan.variant === "grad" ? "grad" : plan.variant === "ink" ? "ink" : "ghost",
    size: "md",
    className: "wk-btn--w-100",
    trailing: plan.variant !== "ghost" ? /*#__PURE__*/React.createElement(Icon, {
      name: "arrow",
      size: 14
    }) : null,
    "data-cursor-hot": true
  }, plan.cta)));
}
function PriceDigits({
  value
}) {
  const digits = String(value).split("");
  return /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "baseline"
    }
  }, digits.map((d, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      display: "inline-block",
      width: "0.55em",
      textAlign: "center",
      overflow: "hidden",
      height: "1em",
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement(AP2, {
    mode: "popLayout"
  }, /*#__PURE__*/React.createElement(m2.span, {
    key: d,
    initial: {
      y: "-100%",
      opacity: 0
    },
    animate: {
      y: 0,
      opacity: 1
    },
    exit: {
      y: "100%",
      opacity: 0
    },
    transition: {
      duration: 0.32,
      ease: [0.22, 1, 0.36, 1]
    },
    style: {
      display: "block"
    }
  }, d)))));
}

/* --------------------------------- FAQ --------------------------------- */
const faqs = [{
  q: "Is there really a free plan?",
  a: "Yes — up to 25 employees, forever. No card needed. You only pay when you cross that line, and you'll know well in advance."
}, {
  q: "Can I import data from BambooHR / Gusto / Greenhouse?",
  a: "Yes. We support CSV, direct API import, and a guided migration session for teams above 100 people. Most teams are fully migrated in under a week."
}, {
  q: "How does payroll work — is it actually built-in?",
  a: "Yes, in supported regions (US, UK, EU, IN, AU). Wooak handles taxes, payslips, and direct deposit. Where we don't yet, we sync cleanly with Xero, QuickBooks, and Workday."
}, {
  q: "What about security and compliance?",
  a: "SOC 2 Type II, GDPR, ISO 27001. SSO + SCIM on the Enterprise plan. Region-pinned data, full audit log, and customer-managed encryption keys."
}, {
  q: "How does the AI use my data?",
  a: "It only ever runs on your tenant's data, never on customer data combined, never for training. You can disable all AI features per workspace. We will never sell your data."
}, {
  q: "Do you have an API and webhooks?",
  a: "Yes — REST + GraphQL with webhooks. Public-facing docs are at docs.wooak.com. Most of Wooak's own integrations are built on the same public API."
}];
function FAQ() {
  const [open, setOpen] = React.useState(0);
  const reduce = useRM2();
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-shead"
  }, /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("span", {
    className: "wk-shead__eyebrow"
  }, "FAQ")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.05
  }, /*#__PURE__*/React.createElement("h2", {
    className: "wk-shead__title"
  }, "Questions, asked honestly."))), /*#__PURE__*/React.createElement("div", {
    className: "wk-faq"
  }, faqs.map((f, i) => {
    const isOpen = open === i;
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      className: `wk-faq__item ${isOpen ? "open" : ""}`
    }, /*#__PURE__*/React.createElement("button", {
      className: "wk-faq__q",
      onClick: () => setOpen(isOpen ? -1 : i),
      "data-cursor-hot": true
    }, f.q, /*#__PURE__*/React.createElement("span", {
      className: "wk-faq__icon"
    }, /*#__PURE__*/React.createElement(Icon, {
      name: "plus",
      size: 14
    }))), /*#__PURE__*/React.createElement(AP2, {
      initial: false
    }, isOpen && /*#__PURE__*/React.createElement(m2.div, {
      className: "wk-faq__a",
      key: "a",
      initial: reduce ? false : {
        height: 0,
        opacity: 0
      },
      animate: {
        height: "auto",
        opacity: 1
      },
      exit: {
        height: 0,
        opacity: 0
      },
      transition: {
        duration: 0.4,
        ease: [0.22, 1, 0.36, 1]
      }
    }, /*#__PURE__*/React.createElement("div", {
      className: "wk-faq__a-inner"
    }, f.a))));
  }))));
}

/* ----------------------------- FINAL CTA ----------------------------- */
function FinalCTA() {
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-finalcta"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-finalcta__conic"
  }), /*#__PURE__*/React.createElement("img", {
    src: "../../assets/wooak-logo.png",
    alt: "",
    className: "wk-finalcta__bg-w"
  }), /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-finalcta__inner"
  }, /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("h2", {
    className: "wk-finalcta__title"
  }, "Your team deserves ", /*#__PURE__*/React.createElement("span", {
    className: "wk-text-gradient"
  }, "better tools"), ".")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.06
  }, /*#__PURE__*/React.createElement("p", {
    className: "wk-finalcta__sub"
  }, "Free for up to 25 employees. Forever.")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.12
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 12,
      justifyContent: "center",
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "grad",
    size: "lg",
    icon: /*#__PURE__*/React.createElement(Icon, {
      name: "sparkle",
      size: 15
    }),
    trailing: /*#__PURE__*/React.createElement(Icon, {
      name: "arrow",
      size: 15
    }),
    "data-cursor-hot": true
  }, "Start free \u2014 no card needed"), /*#__PURE__*/React.createElement(Button, {
    variant: "ghost",
    size: "lg",
    "data-cursor-hot": true
  }, "Talk to sales"))))));
}

/* ------------------------------- FOOTER ------------------------------- */
function Footer() {
  const cols = {
    Product: ["Hiring (ATS)", "Onboarding", "Attendance", "Leave & Shifts", "Payroll", "Performance", "Helpdesk", "Projects", "Assets"],
    Solutions: ["SMB", "Mid-market", "Enterprise", "Remote teams", "Field teams", "Healthcare", "Retail"],
    Resources: ["Docs", "Changelog", "Blog", "Templates", "Brand assets", "API status", "Trust center"],
    Company: ["About", "Careers · we're hiring", "Customers", "Partners", "Press", "Contact"]
  };
  return /*#__PURE__*/React.createElement("footer", {
    className: "wk-footer"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-footer__news"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h3", null, "Run your people ops, not your inbox."), /*#__PURE__*/React.createElement("p", null, "One short read per month. No spam, no growth-hacks.")), /*#__PURE__*/React.createElement("form", {
    onSubmit: e => e.preventDefault()
  }, /*#__PURE__*/React.createElement("input", {
    type: "email",
    placeholder: "you@team.com"
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "grad",
    size: "md",
    trailing: /*#__PURE__*/React.createElement(Icon, {
      name: "arrow",
      size: 14
    })
  }, "Subscribe"))), /*#__PURE__*/React.createElement("div", {
    className: "wk-footer__cols"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-footer__col"
  }, /*#__PURE__*/React.createElement(WLogo, {
    size: 28
  }), /*#__PURE__*/React.createElement("p", {
    style: {
      marginTop: 14,
      fontSize: 14,
      color: "var(--fg-muted)",
      lineHeight: 1.55,
      maxWidth: 280
    }
  }, "The all-in-one HR & people-ops platform \u2014 for teams who care about their people more than their tools.")), Object.entries(cols).map(([head, links]) => /*#__PURE__*/React.createElement("div", {
    className: "wk-footer__col",
    key: head
  }, /*#__PURE__*/React.createElement("h4", null, head), links.map(l => /*#__PURE__*/React.createElement("a", {
    key: l,
    href: "#"
  }, l))))), /*#__PURE__*/React.createElement("div", {
    className: "wk-footer__bot"
  }, /*#__PURE__*/React.createElement("span", {
    className: "copy"
  }, "\xA9 2026 Wooak Labs Inc. \xB7 Made with care in Bangalore + Berlin."), /*#__PURE__*/React.createElement("div", {
    className: "social"
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    "aria-label": "Twitter / X"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "twitter",
    size: 16
  })), /*#__PURE__*/React.createElement("a", {
    href: "#",
    "aria-label": "LinkedIn"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "linkedin",
    size: 16
  })), /*#__PURE__*/React.createElement("a", {
    href: "#",
    "aria-label": "YouTube"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "youtube",
    size: 16
  })), /*#__PURE__*/React.createElement("a", {
    href: "#",
    "aria-label": "GitHub"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "github",
    size: 16
  }))), /*#__PURE__*/React.createElement("span", {
    className: "wk-footer__lang"
  }, "\uD83C\uDF10 English \xB7 USA"))));
}
Object.assign(window, {
  Comparison,
  Metrics,
  Testimonials,
  Integrations,
  Pricing,
  FAQ,
  FinalCTA,
  Footer
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/landing/sections-bottom.jsx", error: String((e && e.message) || e) }); }

// ui_kits/landing/sections-top.jsx
try { (() => {
// Wooak landing — Nav, Hero, Marquee, Bento, Tour, Comparison
const {
  motion: mo,
  AnimatePresence: AP,
  useScroll: useScrl,
  useTransform: useT,
  useInView: useIV,
  useReducedMotion: useRM
} = window.FramerMotion || {};
function NavBar({
  theme,
  setTheme
}) {
  const links = [{
    label: "Product",
    chev: true
  }, {
    label: "Solutions",
    chev: true
  }, {
    label: "Pricing"
  }, {
    label: "Customers"
  }, {
    label: "Docs"
  }];
  return /*#__PURE__*/React.createElement("nav", {
    className: "wk-nav"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap wk-nav__inner"
  }, /*#__PURE__*/React.createElement("a", {
    href: "#"
  }, /*#__PURE__*/React.createElement(WLogo, {
    size: 26
  })), /*#__PURE__*/React.createElement("div", {
    className: "wk-nav__center"
  }, links.map(l => /*#__PURE__*/React.createElement("a", {
    key: l.label,
    className: "wk-nav__link",
    href: "#",
    "data-cursor-hot": true
  }, l.label, l.chev && /*#__PURE__*/React.createElement(Icon, {
    name: "chev",
    size: 14
  })))), /*#__PURE__*/React.createElement("div", {
    className: "wk-nav__right"
  }, /*#__PURE__*/React.createElement("button", {
    "aria-label": "Toggle theme",
    className: "wk-btn wk-btn--ghost wk-btn--sm",
    style: {
      width: 38,
      height: 38,
      padding: 0,
      borderRadius: "50%"
    },
    onClick: () => setTheme(theme === "dark" ? "light" : "dark"),
    "data-cursor-hot": true
  }, /*#__PURE__*/React.createElement(Icon, {
    name: theme === "dark" ? "sun" : "moon",
    size: 16
  })), /*#__PURE__*/React.createElement("div", {
    className: "wk-nav__divider"
  }), /*#__PURE__*/React.createElement("a", {
    className: "wk-btn wk-btn--link wk-btn--sm",
    href: "#",
    "data-cursor-hot": true
  }, "Sign in"), /*#__PURE__*/React.createElement(Button, {
    variant: "grad",
    size: "sm",
    trailing: /*#__PURE__*/React.createElement(Icon, {
      name: "arrow",
      size: 14
    }),
    ariaLabel: "Start free"
  }, "Start free"))));
}

/* ------------------------------- HERO ------------------------------- */
function HeroVisual() {
  const ref = React.useRef(null);
  const {
    scrollY
  } = useScrl();
  const yOrbs = useT(scrollY, [0, 600], [0, -80]);
  const yFrame = useT(scrollY, [0, 600], [0, -40]);
  const yNotif = useT(scrollY, [0, 600], [0, -10]);
  return /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__visual",
    ref: ref
  }, /*#__PURE__*/React.createElement(mo.div, {
    className: "wk-hero__orbs",
    style: {
      y: yOrbs
    },
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__orb",
    style: {
      left: "-6%",
      top: "8%",
      background: "#4A9CFF"
    }
  }), /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__orb",
    style: {
      right: "-10%",
      bottom: "5%",
      background: "#4ADE80"
    }
  }), /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__orb",
    style: {
      left: "30%",
      top: "55%",
      width: 220,
      height: 220,
      background: "#F97316",
      opacity: 0.35
    }
  })), /*#__PURE__*/React.createElement(mo.div, {
    className: "wk-hero__frame",
    style: {
      y: yFrame
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__frame-bar"
  }, /*#__PURE__*/React.createElement("div", {
    className: "dots"
  }, /*#__PURE__*/React.createElement("span", null), /*#__PURE__*/React.createElement("span", null), /*#__PURE__*/React.createElement("span", null)), /*#__PURE__*/React.createElement("span", {
    className: "url"
  }, "wooak.com/app/today")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: 18,
      display: "grid",
      gridTemplateColumns: "1.4fr 1fr",
      gap: 12,
      height: "calc(100% - 42px)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-widget",
    style: {
      background: "var(--bg-muted)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-w-title"
  }, "Today's attendance"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-w-big",
    style: {
      background: "var(--wk-gradient)",
      WebkitBackgroundClip: "text",
      backgroundClip: "text",
      color: "transparent"
    }
  }, "94%"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 12,
      color: "var(--wk-green-700)",
      fontWeight: 600
    }
  }, "+2.1% vs last wk")), /*#__PURE__*/React.createElement("div", {
    className: "wk-bars"
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      height: "62%"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      height: "70%"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      height: "55%"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      height: "82%"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      height: "94%"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      height: "76%"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      height: "88%"
    }
  }))), /*#__PURE__*/React.createElement("div", {
    className: "wk-widget",
    style: {
      background: "var(--bg-muted)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-w-title",
    style: {
      marginBottom: 8
    }
  }, "Onboarding this week"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr 1fr",
      gap: 6
    }
  }, ["Mia C.", "Jonah W.", "Priya R."].map((n, i) => /*#__PURE__*/React.createElement("div", {
    key: n,
    style: {
      background: "var(--bg-elevated)",
      borderRadius: 8,
      padding: "8px 10px",
      border: "1px solid var(--border-soft)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11.5,
      fontWeight: 600
    }
  }, n), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--fg-muted)",
      marginTop: 1
    }
  }, "Day ", i + 2), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 4,
      borderRadius: 99,
      background: "#ECEBE4",
      marginTop: 6
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      height: "100%",
      width: `${30 + i * 22}%`,
      background: "var(--wk-gradient)",
      borderRadius: 99
    }
  }))))))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-widget",
    style: {
      background: "var(--bg-muted)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-w-title"
  }, "Out today"), /*#__PURE__*/React.createElement("div", {
    className: "wk-stack",
    style: {
      marginTop: 8
    }
  }, ["#1E64E6", "#22C55E", "#F97316", "#4A9CFF", "#0A4424"].map((c, i) => /*#__PURE__*/React.createElement("div", {
    className: "av",
    key: i,
    style: {
      background: c
    }
  })), /*#__PURE__*/React.createElement("div", {
    className: "av",
    style: {
      background: "#ECEBE4",
      display: "grid",
      placeItems: "center",
      fontSize: 10,
      fontWeight: 700,
      color: "#6B6A63"
    }
  }, "+4")), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "var(--fg-muted)",
      marginTop: 8
    }
  }, "9 people \xB7 all approved")), /*#__PURE__*/React.createElement("div", {
    className: "wk-widget",
    style: {
      background: "var(--bg-muted)",
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-w-title",
    style: {
      marginBottom: 8
    }
  }, "Pay run \xB7 April"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 700,
      fontSize: 22,
      letterSpacing: "-0.02em"
    }
  }, "$284,310"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11.5,
      color: "var(--fg-muted)",
      marginTop: 2
    }
  }, "238 employees \xB7 ready to send"), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      padding: "8px 10px",
      background: "var(--bg-elevated)",
      borderRadius: 8,
      border: "1px solid var(--border-soft)",
      display: "flex",
      alignItems: "center",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: "#F97316",
      boxShadow: "0 0 0 4px rgba(249,115,22,.2)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 11.5,
      fontWeight: 600
    }
  }, "1 anomaly flagged")))))), /*#__PURE__*/React.createElement(mo.div, {
    className: "wk-hero__notif",
    style: {
      y: yNotif,
      top: 14,
      right: 0,
      width: 220
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "av",
    style: {
      background: "var(--wk-gradient)",
      color: "#fff",
      display: "grid",
      placeItems: "center",
      fontWeight: 700,
      fontSize: 12
    }
  }, "MA"), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "t"
  }, "Maria approved leave"), /*#__PURE__*/React.createElement("div", {
    className: "s"
  }, "2 days \xB7 Tue\u2013Wed"))), /*#__PURE__*/React.createElement(mo.div, {
    className: "wk-hero__notif",
    style: {
      y: useT(scrollY, [0, 600], [0, 30]),
      bottom: 28,
      left: -10,
      width: 230
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "av",
    style: {
      background: "var(--wk-spark-wash)",
      display: "grid",
      placeItems: "center"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "sparkle",
    size: 16,
    style: {
      color: "#F97316"
    }
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "t"
  }, "AI: 3 candidates for review"), /*#__PURE__*/React.createElement("div", {
    className: "s"
  }, "Senior Designer \xB7 top fits"))));
}
function HeroSection() {
  const reduce = useRM();
  const sparks = React.useMemo(() => Array.from({
    length: 5
  }).map((_, i) => ({
    id: i,
    x: 10 + i * 18,
    y: 20 + i % 3 * 22,
    d: 4 + i % 3
  })), []);
  return /*#__PURE__*/React.createElement("header", {
    className: "wk-hero"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, !reduce && sparks.map(s => /*#__PURE__*/React.createElement(mo.div, {
    key: s.id,
    className: "wk-spark",
    style: {
      left: `${s.x}%`,
      top: `${s.y}%`
    },
    animate: {
      y: [0, -22, 0],
      x: [0, 12, 0],
      opacity: [0.3, 0.9, 0.3]
    },
    transition: {
      duration: 6 + s.d,
      repeat: Infinity,
      ease: "easeInOut",
      delay: s.id * 0.6
    }
  })), /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("span", {
    className: "wk-hero__pill"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "sparkle",
    size: 13
  }), " Built for the 2026 workplace ", /*#__PURE__*/React.createElement("span", {
    className: "shimmer"
  }))), /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__grid"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.05
  }, /*#__PURE__*/React.createElement("h1", {
    className: "wk-hero__title"
  }, "One platform. Your ", /*#__PURE__*/React.createElement("span", {
    className: "wk-text-gradient wk-text-gradient--animate"
  }, "whole"), " team.")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.12
  }, /*#__PURE__*/React.createElement("p", {
    className: "wk-hero__sub"
  }, "Hire, onboard, pay, schedule, and grow your people \u2014 without juggling six tools.")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.18
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__ctas"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "grad",
    size: "lg",
    icon: /*#__PURE__*/React.createElement(Icon, {
      name: "sparkle",
      size: 15
    }),
    trailing: /*#__PURE__*/React.createElement(Icon, {
      name: "arrow",
      size: 15
    }),
    "data-cursor-hot": true
  }, "Start free \u2014 no card needed"), /*#__PURE__*/React.createElement(Button, {
    variant: "ghost",
    size: "lg",
    trailing: /*#__PURE__*/React.createElement(Icon, {
      name: "play",
      size: 12
    }),
    "data-cursor-hot": true
  }, "Watch 2-min demo"))), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.28
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__trust"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__trust-label"
  }, "Trusted by 4,200+ teams"), /*#__PURE__*/React.createElement("div", {
    className: "wk-hero__logos"
  }, ["airframe", "linear", "stripe", "loomly", "plural", "fieldhouse"].map(n => /*#__PURE__*/React.createElement("span", {
    key: n
  }, n)))))), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.1
  }, /*#__PURE__*/React.createElement(HeroVisual, null)))));
}

/* ------------------------------ MARQUEE ----------------------------- */
function Marquee() {
  const logos = ["airframe", "linear", "stripe", "loomly", "plural", "fieldhouse", "northstar", "kettlebar", "obsidian", "halcyon"];
  const reel = [...logos, ...logos];
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-marquee"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-marquee__reel"
  }, reel.map((l, i) => /*#__PURE__*/React.createElement("span", {
    className: "wk-marquee__logo",
    key: i
  }, l))));
}

/* ------------------------------- BENTO ------------------------------ */
function BentoGrid() {
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-shead"
  }, /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("span", {
    className: "wk-shead__eyebrow"
  }, "Everything, finally in one place")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.05
  }, /*#__PURE__*/React.createElement("h2", {
    className: "wk-shead__title"
  }, "Twelve tools became one app.")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.1
  }, /*#__PURE__*/React.createElement("p", {
    className: "wk-shead__sub"
  }, "Recruit, onboard, pay, manage, and grow. Without the duct tape."))), /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("div", {
    className: "wk-bento"
  }, /*#__PURE__*/React.createElement(BentoATS, null), /*#__PURE__*/React.createElement(BentoPayroll, null), /*#__PURE__*/React.createElement(BentoAttendance, null), /*#__PURE__*/React.createElement(BentoReviews, null), /*#__PURE__*/React.createElement(BentoLeave, null), /*#__PURE__*/React.createElement(BentoAI, null)))));
}
function BentoATS() {
  // animated mini pipeline
  const cols = ["Applied", "Interview", "Offer"];
  const [tick, setTick] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 2400);
    return () => clearInterval(id);
  }, []);
  const cards = [{
    name: "Mia C.",
    role: "Sr. Designer",
    c: 0 + tick % 3
  }, {
    name: "Jonah W.",
    role: "Eng Lead",
    c: 1 + tick % 3
  }, {
    name: "Priya R.",
    role: "Marketer",
    c: 2 + tick % 3
  }].map(card => ({
    ...card,
    c: card.c % 3
  }));
  return /*#__PURE__*/React.createElement("div", {
    className: "tile tile--big"
  }, /*#__PURE__*/React.createElement("span", {
    className: "ic-chip"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "briefcase",
    size: 16
  })), /*#__PURE__*/React.createElement("h3", null, "Hiring that doesn't suck."), /*#__PURE__*/React.createElement("p", null, "An ATS your hiring managers will actually keep open."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr 1fr",
      gap: 10,
      marginTop: 16
    }
  }, cols.map((title, ci) => /*#__PURE__*/React.createElement("div", {
    key: title,
    style: {
      background: "var(--bg-muted)",
      borderRadius: 12,
      padding: 10,
      minHeight: 170
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: ".06em",
      textTransform: "uppercase",
      color: "var(--fg-muted)",
      marginBottom: 8
    }
  }, title, " ", /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: 4,
      opacity: .6
    }
  }, ci === 0 ? "42" : ci === 1 ? "6" : "1")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 6,
      position: "relative",
      height: 130
    }
  }, /*#__PURE__*/React.createElement(AP, null, cards.filter(c => c.c === ci).map(c => /*#__PURE__*/React.createElement(mo.div, {
    key: c.name,
    layout: true,
    layoutId: c.name,
    initial: {
      opacity: 0,
      y: 12
    },
    animate: {
      opacity: 1,
      y: 0
    },
    exit: {
      opacity: 0,
      y: -12
    },
    transition: {
      duration: 0.55,
      ease: [0.22, 1, 0.36, 1]
    },
    style: {
      background: "var(--bg-elevated)",
      borderRadius: 8,
      padding: "8px 10px",
      border: "1px solid var(--border-soft)",
      display: "flex",
      alignItems: "center",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 22,
      height: 22,
      borderRadius: "50%",
      background: "var(--wk-gradient)",
      color: "#fff",
      display: "grid",
      placeItems: "center",
      fontSize: 9,
      fontWeight: 800
    }
  }, c.name[0]), /*#__PURE__*/React.createElement("div", {
    style: {
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11.5,
      fontWeight: 600,
      lineHeight: 1.2
    }
  }, c.name), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--fg-muted)"
    }
  }, c.role))))))))));
}
function BentoPayroll() {
  const ref = React.useRef(null);
  const inView = useIV(ref, {
    once: true
  });
  const reduce = useRM();
  const target = 284310;
  const [val, setVal] = React.useState(0);
  React.useEffect(() => {
    if (!inView) return;
    if (reduce) {
      setVal(target);
      return;
    }
    let raf, start;
    const tick = t => {
      if (!start) start = t;
      const k = Math.min((t - start) / 1600, 1);
      const eased = 1 - Math.pow(1 - k, 4);
      setVal(Math.round(target * eased));
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, reduce]);
  return /*#__PURE__*/React.createElement("div", {
    className: "tile tile--tall",
    ref: ref
  }, /*#__PURE__*/React.createElement("span", {
    className: "ic-chip"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "dollar",
    size: 16
  })), /*#__PURE__*/React.createElement("h3", null, "Payroll, run in 4 minutes."), /*#__PURE__*/React.createElement("p", null, "Approvals, taxes, payslips, and anomaly checks \u2014 done in one flow."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "auto"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 700,
      fontSize: 44,
      letterSpacing: "-0.025em",
      lineHeight: 1,
      fontFeatureSettings: '"tnum"',
      background: "var(--wk-gradient)",
      WebkitBackgroundClip: "text",
      backgroundClip: "text",
      color: "transparent"
    }
  }, "$", val.toLocaleString()), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12.5,
      color: "var(--fg-muted)",
      marginTop: 6
    }
  }, "April pay run \xB7 238 people \xB7 0 errors"), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 14,
      padding: "10px 12px",
      borderRadius: 10,
      background: "var(--bg-muted)",
      display: "flex",
      alignItems: "center",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: "#F97316",
      boxShadow: "0 0 0 4px rgba(249,115,22,.18)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 12,
      fontWeight: 600
    }
  }, "1 anomaly: overtime on J.W."))));
}
function BentoAttendance() {
  return /*#__PURE__*/React.createElement("div", {
    className: "tile tile--wide",
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 16,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "ic-chip"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "pin",
    size: 16
  })), /*#__PURE__*/React.createElement("h3", null, "Attendance with geofencing."), /*#__PURE__*/React.createElement("p", null, "Check-ins only count when people are actually at the office, site, or job.")), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      height: 140,
      borderRadius: 12,
      overflow: "hidden",
      background: "linear-gradient(135deg, #EAF1FE, #E8FBEF)"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 200 120",
    style: {
      position: "absolute",
      inset: 0,
      width: "100%",
      height: "100%",
      opacity: 0.6
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M0 80 Q40 60 80 75 T160 70 T200 65",
    stroke: "#1E64E6",
    strokeWidth: "1.4",
    fill: "none",
    opacity: ".4"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M0 50 Q60 35 110 48 T200 40",
    stroke: "#22C55E",
    strokeWidth: "1.4",
    fill: "none",
    opacity: ".4"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "40",
    cy: "44",
    r: "2",
    fill: "#1E64E6"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "90",
    cy: "74",
    r: "2",
    fill: "#22C55E"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "146",
    cy: "38",
    r: "2",
    fill: "#1E64E6"
  })), /*#__PURE__*/React.createElement(mo.div, {
    animate: {
      scale: [1, 1.2, 1],
      opacity: [0.6, 0.1, 0.6]
    },
    transition: {
      duration: 2.4,
      repeat: Infinity
    },
    style: {
      position: "absolute",
      left: "calc(50% - 28px)",
      top: "calc(50% - 28px)",
      width: 56,
      height: 56,
      borderRadius: "50%",
      background: "#1E64E6",
      opacity: 0.2
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      left: "calc(50% - 10px)",
      top: "calc(50% - 10px)",
      width: 20,
      height: 20,
      borderRadius: "50%",
      background: "var(--wk-gradient)",
      border: "3px solid #fff",
      boxShadow: "0 6px 14px rgba(30,100,230,0.4)"
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      right: 12,
      bottom: 10,
      fontSize: 11,
      fontWeight: 600,
      color: "var(--wk-blue-700)",
      background: "rgba(255,255,255,0.7)",
      borderRadius: 999,
      padding: "4px 10px",
      backdropFilter: "blur(8px)"
    }
  }, "12 active sites")));
}
function BentoReviews() {
  const ref = React.useRef(null);
  const inView = useIV(ref, {
    once: true
  });
  const reduce = useRM();
  const [pct, setPct] = React.useState(0);
  React.useEffect(() => {
    if (!inView) return;
    if (reduce) {
      setPct(87);
      return;
    }
    let raf, start;
    const tick = t => {
      if (!start) start = t;
      const k = Math.min((t - start) / 1600, 1);
      setPct(Math.round(87 * (1 - Math.pow(1 - k, 4))));
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, reduce]);
  const C = 2 * Math.PI * 36;
  return /*#__PURE__*/React.createElement("div", {
    className: "tile tile--sq",
    ref: ref
  }, /*#__PURE__*/React.createElement("span", {
    className: "ic-chip"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "target",
    size: 16
  })), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontSize: 17
    }
  }, "Reviews people finish."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 14,
      marginTop: 12
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "86",
    height: "86",
    viewBox: "0 0 86 86"
  }, /*#__PURE__*/React.createElement("defs", null, /*#__PURE__*/React.createElement("linearGradient", {
    id: "rGrad",
    x1: "0",
    x2: "1"
  }, /*#__PURE__*/React.createElement("stop", {
    offset: "0%",
    stopColor: "#1E64E6"
  }), /*#__PURE__*/React.createElement("stop", {
    offset: "100%",
    stopColor: "#22C55E"
  }))), /*#__PURE__*/React.createElement("circle", {
    cx: "43",
    cy: "43",
    r: "36",
    stroke: "var(--border)",
    strokeWidth: "7",
    fill: "none"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "43",
    cy: "43",
    r: "36",
    stroke: "url(#rGrad)",
    strokeWidth: "7",
    fill: "none",
    strokeDasharray: C,
    strokeDashoffset: C * (1 - pct / 100),
    strokeLinecap: "round",
    style: {
      transform: "rotate(-90deg)",
      transformOrigin: "43px 43px",
      transition: "stroke-dashoffset 80ms linear"
    }
  }), /*#__PURE__*/React.createElement("text", {
    x: "43",
    y: "48",
    textAnchor: "middle",
    fontWeight: "700",
    fontSize: "20",
    fill: "var(--fg)",
    fontFamily: "Inter"
  }, pct, "%")), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "var(--fg-muted)",
      lineHeight: 1.4
    }
  }, "completion rate", /*#__PURE__*/React.createElement("br", null), "across 360\xB0 + OKRs")));
}
function BentoLeave() {
  const days = ["M", "T", "W", "T", "F", "S", "S"];
  const reduce = useRM();
  return /*#__PURE__*/React.createElement("div", {
    className: "tile tile--sq"
  }, /*#__PURE__*/React.createElement("span", {
    className: "ic-chip"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "calendar",
    size: 16
  })), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontSize: 17
    }
  }, "Leave & shifts."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(7, 1fr)",
      gap: 4,
      marginTop: 12
    }
  }, Array.from({
    length: 14
  }).map((_, i) => {
    const states = ["#FAFAF7", "#E8FBEF", "#FFF1E6", "#EAF1FE"];
    const targetIdx = i * 3 % states.length;
    return /*#__PURE__*/React.createElement(mo.div, {
      key: i,
      initial: {
        rotateX: 0
      },
      animate: reduce ? {} : {
        rotateX: [0, 90, 0, 0]
      },
      transition: {
        duration: 1.4,
        delay: 1.6 + i * 0.07,
        repeat: Infinity,
        repeatDelay: 4
      },
      style: {
        aspectRatio: "1 / 1",
        borderRadius: 4,
        background: states[targetIdx],
        border: "1px solid var(--border-soft)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 9,
        fontWeight: 700,
        color: "var(--fg-muted)",
        transformStyle: "preserve-3d"
      }
    }, i < 7 ? days[i] : "");
  })));
}
function BentoAI() {
  const text = "Suggested: 3 candidates for Senior Designer.";
  const reduce = useRM();
  const [typed, setTyped] = React.useState(reduce ? text : "");
  React.useEffect(() => {
    if (reduce) return;
    let i = 0;
    const id = setInterval(() => {
      i++;
      setTyped(text.slice(0, i));
      if (i >= text.length) {
        clearInterval(id);
        setTimeout(() => {
          i = 0;
          setTyped("");
        }, 2800);
      }
    }, 38);
    return () => clearInterval(id);
  }, [reduce, typed === ""]);
  return /*#__PURE__*/React.createElement("div", {
    className: "tile tile--wide",
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 16,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "ic-chip"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "bot",
    size: 16
  })), /*#__PURE__*/React.createElement("h3", null, "AI that helps, not haunts."), /*#__PURE__*/React.createElement("p", null, "Suggestions you actually want. No \"AI-powered everything.\" No surveillance.")), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "#0A0F1A",
      color: "#fff",
      padding: "16px 18px",
      borderRadius: 12,
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      minHeight: 110,
      position: "relative",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 4,
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: "#ff5f56"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: "#ffbd2e"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: "#27c93f"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "#4ADE80"
    }
  }, "$ wooak ai assist"), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 4,
      color: "#fff"
    }
  }, typed, /*#__PURE__*/React.createElement("span", {
    style: {
      background: "var(--wk-gradient)",
      color: "transparent",
      display: "inline-block",
      width: 8,
      height: 16,
      verticalAlign: "-2px",
      marginLeft: 2,
      animation: "wk-blink 1s steps(2) infinite"
    }
  })), /*#__PURE__*/React.createElement("style", null, "@keyframes wk-blink { to { opacity: 0; }}")));
}

/* ------------------------------ TOUR ------------------------------ */
const tourSteps = [{
  k: "Recruit",
  title: "Recruit",
  desc: "Job posts, an applicant pipeline, scorecards, and offer letters. All from one tab.",
  widget: "ats"
}, {
  k: "Onboard",
  title: "Onboard",
  desc: "Pre-boarding checklists, IT provisioning, signed docs, and a first-week schedule that builds itself.",
  widget: "onb"
}, {
  k: "Manage",
  title: "Manage",
  desc: "Attendance with geofencing. Leave with one-tap approvals. Shifts that nobody has to plead for.",
  widget: "mng"
}, {
  k: "Grow",
  title: "Grow",
  desc: "OKRs, 360° reviews, learning paths, and salary insights — without the dread.",
  widget: "grw"
}];
function ProductTour() {
  const [active, setActive] = React.useState(0);
  const containerRef = React.useRef(null);
  const [isMobile, setIsMobile] = React.useState(() => typeof window !== "undefined" && window.matchMedia("(max-width: 880px)").matches);
  React.useEffect(() => {
    const mq = window.matchMedia("(max-width: 880px)");
    const onChange = () => setIsMobile(mq.matches);
    mq.addEventListener ? mq.addEventListener("change", onChange) : mq.addListener(onChange);
    return () => {
      mq.removeEventListener ? mq.removeEventListener("change", onChange) : mq.removeListener(onChange);
    };
  }, []);

  // Scroll-progress-driven active index (reliable across browsers)
  React.useEffect(() => {
    if (isMobile) return; // mobile uses inline stack, no sticky
    const onScroll = () => {
      const el = containerRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const vh = window.innerHeight;
      // Treat the captions column as the scroll-driver:
      // map the band from when the section top hits 30% of viewport to when its bottom hits 70%.
      const start = rect.top - vh * 0.30;
      const span = rect.height - vh * 0.40;
      const p = Math.max(0, Math.min(1, -start / Math.max(1, span)));
      const idx = Math.min(tourSteps.length - 1, Math.floor(p * tourSteps.length));
      setActive(idx);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, {
      passive: true
    });
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, [isMobile]);
  return /*#__PURE__*/React.createElement("section", {
    className: "wk-tour-section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-shead"
  }, /*#__PURE__*/React.createElement(Reveal, null, /*#__PURE__*/React.createElement("span", {
    className: "wk-shead__eyebrow"
  }, "A 30-second tour")), /*#__PURE__*/React.createElement(Reveal, {
    delay: 0.05
  }, /*#__PURE__*/React.createElement("h2", {
    className: "wk-shead__title"
  }, "From \"Hello, you're hired\"", /*#__PURE__*/React.createElement("br", null), "to \"Promoted, congrats.\""))), isMobile ?
  /*#__PURE__*/
  // MOBILE — stack visual above each caption block
  React.createElement("div", {
    className: "wk-tour-mobile"
  }, tourSteps.map((s, i) => /*#__PURE__*/React.createElement("div", {
    key: s.k,
    className: "wk-tour-mobile__item"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-tour-mobile__visual"
  }, /*#__PURE__*/React.createElement(TourVisual, {
    which: s.widget
  })), /*#__PURE__*/React.createElement(TourCaption, {
    idx: i,
    step: s,
    active: true
  })))) :
  /*#__PURE__*/
  // DESKTOP — sticky-left + scrolling captions
  React.createElement("div", {
    ref: containerRef,
    className: "wk-tour-grid"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-tour-sticky"
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-tour-frame"
  }, /*#__PURE__*/React.createElement(TourVisual, {
    which: tourSteps[active].widget
  })), /*#__PURE__*/React.createElement("div", {
    className: "wk-tour-stepper",
    "aria-hidden": "true"
  }, tourSteps.map((s, i) => /*#__PURE__*/React.createElement("button", {
    key: s.k,
    onClick: () => {
      const captions = document.querySelectorAll("[data-tour-step]");
      captions[i] && captions[i].scrollIntoView({
        behavior: "smooth",
        block: "center"
      });
    },
    className: `wk-tour-stepper__dot ${i === active ? "active" : ""}`,
    "aria-label": `Jump to ${s.title}`
  }, /*#__PURE__*/React.createElement("span", {
    className: "lbl"
  }, s.title))))), /*#__PURE__*/React.createElement("div", {
    className: "wk-tour-captions"
  }, tourSteps.map((s, i) => /*#__PURE__*/React.createElement(TourCaption, {
    key: s.k,
    idx: i,
    step: s,
    active: i === active
  }))))));
}
function TourCaption({
  idx,
  step,
  active
}) {
  return /*#__PURE__*/React.createElement("div", {
    "data-tour-step": idx,
    className: `wk-tour-caption ${active ? "active" : ""}`
  }, /*#__PURE__*/React.createElement("div", {
    className: "wk-tour-caption__eyebrow"
  }, /*#__PURE__*/React.createElement("span", {
    className: "num"
  }, String(idx + 1).padStart(2, "0")), "Step ", idx + 1), /*#__PURE__*/React.createElement("h3", {
    className: "wk-tour-caption__title"
  }, step.title), /*#__PURE__*/React.createElement("p", {
    className: "wk-tour-caption__desc"
  }, step.desc));
}
function TourVisual({
  which
}) {
  return /*#__PURE__*/React.createElement(mo.div, {
    layout: true,
    style: {
      background: "var(--bg-elevated)",
      borderRadius: 18,
      padding: 18,
      boxShadow: "0 40px 80px -32px rgba(10,15,40,0.28), 0 12px 28px -10px rgba(30,100,230,0.10)",
      border: "1px solid var(--border-soft)",
      height: "100%",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement(AP, {
    mode: "popLayout"
  }, which === "ats" && /*#__PURE__*/React.createElement(mo.div, {
    key: "ats",
    initial: {
      opacity: 0
    },
    animate: {
      opacity: 1
    },
    exit: {
      opacity: 0
    },
    transition: {
      duration: 0.4
    }
  }, /*#__PURE__*/React.createElement(TourTitle, {
    label: "Hiring \xB7 Pipeline"
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr 1fr 1fr",
      gap: 10
    }
  }, ["Applied · 42", "Phone · 12", "Interview · 6", "Offer · 1"].map((t, i) => /*#__PURE__*/React.createElement("div", {
    key: t,
    style: {
      background: "var(--bg-muted)",
      borderRadius: 10,
      padding: 10,
      minHeight: 280
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 700,
      letterSpacing: ".08em",
      textTransform: "uppercase",
      color: "var(--fg-muted)",
      marginBottom: 8
    }
  }, t), [0, 1, 2].map(k => /*#__PURE__*/React.createElement(mo.div, {
    layoutId: `card-${i}-${k}`,
    key: k,
    style: {
      background: "var(--bg-elevated)",
      borderRadius: 8,
      padding: "8px 10px",
      marginBottom: 6,
      border: "1px solid var(--border-soft)",
      display: "flex",
      alignItems: "center",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 22,
      height: 22,
      borderRadius: "50%",
      background: ["#1E64E6", "#22C55E", "#F97316", "#4A9CFF"][(i * 3 + k) % 4],
      color: "#fff",
      display: "grid",
      placeItems: "center",
      fontSize: 9,
      fontWeight: 800
    }
  }, "MJPDRTKL"[(i * 3 + k) % 8]), /*#__PURE__*/React.createElement("div", {
    style: {
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600
    }
  }, ["Mia C.", "Jonah W.", "Priya R.", "Dev S.", "Ana K.", "Reggie T."][(i * 3 + k) % 6]), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9.5,
      color: "var(--fg-muted)"
    }
  }, ["Sr. Designer", "Eng Lead", "Marketer", "Recruiter"][(i * 3 + k) % 4])))))))), which === "onb" && /*#__PURE__*/React.createElement(mo.div, {
    key: "onb",
    initial: {
      opacity: 0
    },
    animate: {
      opacity: 1
    },
    exit: {
      opacity: 0
    },
    transition: {
      duration: 0.4
    }
  }, /*#__PURE__*/React.createElement(TourTitle, {
    label: "Onboarding \xB7 Day 1 plan"
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--bg-muted)",
      borderRadius: 12,
      padding: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      fontWeight: 700,
      marginBottom: 8
    }
  }, "Checklist"), ["Sign offer letter", "Provision laptop", "Add to payroll", "Buddy: Priya R.", "Welcome lunch · Wed"].map((t, i) => /*#__PURE__*/React.createElement("div", {
    key: t,
    style: {
      display: "flex",
      gap: 8,
      padding: "6px 0",
      fontSize: 12
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 16,
      height: 16,
      borderRadius: 4,
      background: i < 3 ? "var(--wk-gradient)" : "var(--bg-elevated)",
      border: i < 3 ? "none" : "1px solid var(--border)",
      display: "grid",
      placeItems: "center",
      color: "#fff",
      fontSize: 10,
      fontWeight: 800
    }
  }, i < 3 ? "✓" : ""), t))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--bg-muted)",
      borderRadius: 12,
      padding: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      fontWeight: 700,
      marginBottom: 8
    }
  }, "This week"), [["Mon · 9:00", "Welcome + setup"], ["Mon · 14:00", "Tour of the stack"], ["Tue · 10:30", "1:1 with manager"], ["Wed · 12:00", "Team lunch"], ["Thu · 15:00", "First PR review"]].map(([w, t]) => /*#__PURE__*/React.createElement("div", {
    key: w,
    style: {
      display: "grid",
      gridTemplateColumns: "100px 1fr",
      gap: 8,
      padding: "5px 0",
      fontSize: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--fg-muted)",
      fontFamily: "var(--font-mono)",
      fontSize: 11
    }
  }, w), /*#__PURE__*/React.createElement("div", null, t)))))), which === "mng" && /*#__PURE__*/React.createElement(mo.div, {
    key: "mng",
    initial: {
      opacity: 0
    },
    animate: {
      opacity: 1
    },
    exit: {
      opacity: 0
    },
    transition: {
      duration: 0.4
    }
  }, /*#__PURE__*/React.createElement(TourTitle, {
    label: "People \xB7 Attendance & Leave"
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--bg-muted)",
      borderRadius: 12,
      padding: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--fg-muted)",
      marginBottom: 6
    }
  }, "Today \xB7 attendance"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 700,
      fontSize: 36,
      letterSpacing: "-0.02em",
      background: "var(--wk-gradient)",
      WebkitBackgroundClip: "text",
      backgroundClip: "text",
      color: "transparent"
    }
  }, "94%"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 4,
      alignItems: "end",
      marginTop: 12,
      height: 70
    }
  }, [60, 72, 58, 88, 94, 78, 84].map((h, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      flex: 1,
      height: `${h}%`,
      background: "var(--wk-gradient)",
      borderRadius: "4px 4px 0 0",
      opacity: i === 4 ? 1 : 0.65
    }
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--bg-muted)",
      borderRadius: 12,
      padding: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      fontWeight: 700,
      marginBottom: 10
    }
  }, "Requests \xB7 4 pending"), [["Mia C.", "PTO · 2 days"], ["Jonah W.", "Sick · today"], ["Ana K.", "WFH · Fri"], ["Reggie T.", "Comp time"]].map(([n, x], i) => /*#__PURE__*/React.createElement("div", {
    key: n,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "6px 0",
      borderBottom: "1px dashed var(--border)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 22,
      height: 22,
      borderRadius: "50%",
      background: ["#1E64E6", "#22C55E", "#F97316", "#0B2768"][i],
      color: "#fff",
      display: "grid",
      placeItems: "center",
      fontSize: 9,
      fontWeight: 800
    }
  }, n[0]), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      fontSize: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600
    }
  }, n), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--fg-muted)",
      fontSize: 11
    }
  }, x)), /*#__PURE__*/React.createElement("button", {
    style: {
      height: 24,
      padding: "0 10px",
      borderRadius: 999,
      border: "none",
      background: "var(--wk-gradient)",
      color: "#fff",
      fontSize: 11,
      fontWeight: 700,
      cursor: "pointer"
    }
  }, "Approve")))))), which === "grw" && /*#__PURE__*/React.createElement(mo.div, {
    key: "grw",
    initial: {
      opacity: 0
    },
    animate: {
      opacity: 1
    },
    exit: {
      opacity: 0
    },
    transition: {
      duration: 0.4
    }
  }, /*#__PURE__*/React.createElement(TourTitle, {
    label: "Performance \xB7 OKRs"
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr 1fr",
      gap: 10
    }
  }, [["Ship V2 platform", 78, "#1E64E6"], ["Cut churn 10% → 5%", 52, "#22C55E"], ["Hire 12 engineers", 91, "#F97316"]].map(([t, p, c]) => /*#__PURE__*/React.createElement("div", {
    key: t,
    style: {
      background: "var(--bg-muted)",
      borderRadius: 12,
      padding: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12.5,
      fontWeight: 600,
      marginBottom: 14,
      minHeight: 36
    }
  }, t), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      justifyContent: "space-between",
      marginBottom: 8
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontWeight: 700,
      fontSize: 24,
      color: c,
      letterSpacing: "-.02em"
    }
  }, p, "%"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 10.5,
      color: "var(--fg-muted)"
    }
  }, "Q2 \xB7 on track")), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 6,
      background: "var(--border-soft)",
      borderRadius: 99
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: `${p}%`,
      height: "100%",
      background: c,
      borderRadius: 99
    }
  }))))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 16,
      padding: "10px 14px",
      background: "var(--wk-spark-wash)",
      borderRadius: 10,
      display: "flex",
      alignItems: "center",
      gap: 10,
      fontSize: 12.5
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "sparkle",
    size: 14,
    style: {
      color: "#F97316"
    }
  }), /*#__PURE__*/React.createElement("b", null, "Wooak AI:"), " Mia C. is ready for a Senior promotion. View 360\xB0 summary \u2192"))));
}
function TourTitle({
  label
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "4px 4px 14px",
      borderBottom: "1px solid var(--border-soft)",
      marginBottom: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 9,
      height: 9,
      borderRadius: "50%",
      background: "#ECEBE4"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 9,
      height: 9,
      borderRadius: "50%",
      background: "#ECEBE4"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 9,
      height: 9,
      borderRadius: "50%",
      background: "#ECEBE4"
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "var(--fg-muted)"
    }
  }, "wooak.com/app \xB7 ", label));
}
Object.assign(window, {
  NavBar,
  HeroSection,
  Marquee,
  BentoGrid,
  ProductTour
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/landing/sections-top.jsx", error: String((e && e.message) || e) }); }

})();
