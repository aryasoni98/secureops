import { describe, expect, it } from "vitest";
import { buildGraph, layoutGraph } from "./graphLayout";

const PATHS = [
  { nodes: ["internet", "ec2-web", "rds-prod"] },
  { nodes: ["internet", "ec2-web", "s3-data"] },
];

describe("buildGraph", () => {
  it("dedupes nodes and edges across paths", () => {
    const g = buildGraph(PATHS);
    expect(g.nodes).toEqual(["internet", "ec2-web", "rds-prod", "s3-data"]);
    expect(g.edges).toEqual([
      ["internet", "ec2-web"],
      ["ec2-web", "rds-prod"],
      ["ec2-web", "s3-data"],
    ]);
  });

  it("handles empty input", () => {
    const g = buildGraph([]);
    expect(g.nodes).toEqual([]);
    expect(g.edges).toEqual([]);
  });
});

describe("layoutGraph", () => {
  it("positions every node inside the padded canvas", () => {
    const g = buildGraph(PATHS);
    const out = layoutGraph(g, 800, 460);
    expect(out).toHaveLength(4);
    for (const n of out) {
      expect(n.x).toBeGreaterThanOrEqual(24);
      expect(n.x).toBeLessThanOrEqual(800 - 24);
      expect(n.y).toBeGreaterThanOrEqual(24);
      expect(n.y).toBeLessThanOrEqual(460 - 24);
    }
  });

  it("is deterministic (same input, same layout)", () => {
    const g = buildGraph(PATHS);
    expect(layoutGraph(g, 800, 460)).toEqual(layoutGraph(g, 800, 460));
  });

  it("separates nodes (no two coincide)", () => {
    const g = buildGraph(PATHS);
    const out = layoutGraph(g, 800, 460);
    for (let i = 0; i < out.length; i++) {
      for (let j = i + 1; j < out.length; j++) {
        const d = Math.hypot(out[i].x - out[j].x, out[i].y - out[j].y);
        expect(d).toBeGreaterThan(20);
      }
    }
  });

  it("centers a single node", () => {
    const out = layoutGraph({ nodes: ["only"], edges: [] }, 800, 460);
    expect(out).toEqual([{ id: "only", x: 400, y: 230 }]);
  });
});
