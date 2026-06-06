//! Live **Neo4j** backend for the security knowledge graph (PRODUCT.md §11),
//! gated behind the `neo4j` feature. Loads a tenant's asset/identity topology
//! out of Neo4j (via Cypher over Bolt) into an in-memory [`SecurityGraph`], so
//! the same attack-path / blast-radius analysis runs against either backend.
//!
//! Community tier uses the in-memory / Postgres-CTE path (no extra container);
//! Pro/Enterprise point this at the `neo4j` Helm subchart.

use neo4rs::{query, Graph as Neo4jClient};

use crate::{EdgeKind, NodeData, SecurityGraph};

/// A connected Neo4j client scoped to graph loading.
pub struct Neo4jGraph {
    client: Neo4jClient,
}

fn edge_kind_from_str(s: &str) -> EdgeKind {
    match s {
        "CAN_ASSUME" => EdgeKind::CanAssume,
        "HAS_PERMISSION" => EdgeKind::HasPermission,
        "EXPOSES" => EdgeKind::Exposes,
        "HAS_VULN" => EdgeKind::HasVuln,
        "VIOLATES" => EdgeKind::Violates,
        "OWNS" => EdgeKind::Owns,
        _ => EdgeKind::ConnectsTo,
    }
}

impl Neo4jGraph {
    /// Connect over Bolt.
    pub async fn connect(uri: &str, user: &str, pass: &str) -> anyhow::Result<Self> {
        let client = Neo4jClient::new(uri, user, pass).await?;
        Ok(Self { client })
    }

    /// Load a tenant's nodes + typed edges into an in-memory [`SecurityGraph`].
    pub async fn load(&self, tenant: &str) -> anyhow::Result<SecurityGraph> {
        let mut g = SecurityGraph::new();

        let mut nodes = self
            .client
            .execute(
                query(
                    "MATCH (n:Asset {tenant: $t}) \
                     RETURN n.id AS id, n.kind AS kind, \
                            coalesce(n.exposed, false) AS exposed, \
                            coalesce(n.sensitive, false) AS sensitive",
                )
                .param("t", tenant),
            )
            .await?;
        while let Some(row) = nodes.next().await? {
            let id: String = row.get("id")?;
            let kind: String = row.get("kind")?;
            let mut nd = NodeData::new(id, kind);
            nd.exposed = row.get("exposed").unwrap_or(false);
            nd.sensitive = row.get("sensitive").unwrap_or(false);
            g.add_node(nd);
        }

        let mut edges = self
            .client
            .execute(
                query(
                    "MATCH (a:Asset {tenant: $t})-[r]->(b:Asset {tenant: $t}) \
                     RETURN a.id AS from, b.id AS to, type(r) AS kind, \
                            coalesce(r.difficulty, 1.0) AS difficulty",
                )
                .param("t", tenant),
            )
            .await?;
        while let Some(row) = edges.next().await? {
            let from: String = row.get("from")?;
            let to: String = row.get("to")?;
            let kind: String = row.get("kind")?;
            let difficulty: f64 = row.get("difficulty").unwrap_or(1.0);
            g.add_edge(from, to, edge_kind_from_str(&kind), difficulty as f32);
        }

        Ok(g)
    }
}
