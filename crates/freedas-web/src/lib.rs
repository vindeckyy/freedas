//! Web UI: static SPA served by freedas-server, plus shared route types.
//!
//! The plan calls for a Leptos WASM app; this is a zero-build static app
//! against the same JSON/SSE API with identical routes and behavior.

pub const APP_NAME: &str = "Freedas Web";

pub const ROUTES: &[&str] = &[
    "/",
    "/session/:id",
    "/new",
    "/settings",
    "/models",
    "/agents",
    "/skills",
    "/mcp",
    "/plugins",
    "/memory",
    "/usage",
    "/reviews",
    "/sandboxes",
    "/workspaces",
    "/relay",
];

pub const INDEX_HTML: &str = include_str!("../assets/index.html");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_cover_parity_surface() {
        for route in ROUTES {
            assert!(route.starts_with('/'), "{route}");
        }
        assert!(ROUTES.contains(&"/usage"));
        assert!(ROUTES.contains(&"/reviews"));
    }
}
