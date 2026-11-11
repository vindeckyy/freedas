mod cmd;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "freedas",
    version,
    about = "Freedas — open-source coding agent"
)]
struct Cli {
    /// Project directory (starts in directory)
    project: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
    #[arg(long, short = 'c')]
    continue_: bool,
    #[arg(long, short = 's')]
    session: Option<String>,
    #[arg(long)]
    fork: bool,
    #[arg(long)]
    worktree: Option<Option<String>>,
    #[arg(long)]
    agent: Option<String>,
    #[arg(long, short = 'm')]
    model: Option<String>,
    #[arg(long)]
    variant: Option<String>,
    #[arg(long, conflicts_with = "manual")]
    auto: bool,
    #[arg(long, conflicts_with = "auto")]
    manual: bool,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Run one task headlessly
    Run {
        task: String,
        #[arg(long, default_value = "text", value_parser = ["json", "text"])]
        format: String,
        #[arg(long, short = 'f')]
        file: Vec<String>,
        #[arg(long)]
        attach: Option<String>,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        worktree: Option<Option<String>>,
        #[arg(long, short = 'c')]
        continue_: bool,
        #[arg(long, short = 's')]
        session: Option<String>,
        #[arg(long)]
        fork: bool,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, short = 'm')]
        model: Option<String>,
        #[arg(long)]
        variant: Option<String>,
        #[arg(long, conflicts_with = "manual")]
        auto: bool,
        #[arg(long, conflicts_with = "auto")]
        manual: bool,
    },
    /// Connect the TUI to a running server
    Attach { url: String },
    /// Check out a pull request and start
    Pr { number: u64 },
    /// Session management
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },
    /// Export a session as JSON
    Export {
        id: Option<String>,
        /// Disable secret/home-path redaction (raw backup; default sanitizes)
        #[arg(long)]
        unsanitized: bool,
        #[arg(long)]
        output: Option<String>,
    },
    /// Import a session JSON file
    Import { file: String },
    /// Token and cost statistics
    Stats {
        #[arg(long)]
        days: Option<i64>,
        #[arg(long)]
        tools: bool,
        #[arg(long)]
        models: bool,
        #[arg(long)]
        project: Option<String>,
    },
    /// Preview or apply import of instruction/skill files
    Sync {
        #[arg(default_value = "")]
        action: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        dir: Option<String>,
        #[arg(long)]
        memory: Option<String>,
        /// Store imported memories globally (user scope) instead of the current project.
        #[arg(long)]
        global: bool,
    },
    /// Agent management
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    /// Skill registry
    Skill {
        #[command(subcommand)]
        command: SkillCommands,
    },
    /// MCP server management
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },
    /// Plugins
    Plugin {
        module: Option<String>,
        #[arg(long)]
        global: bool,
        #[command(subcommand)]
        command: Option<PluginCommands>,
    },
    /// List models
    Models {
        #[arg(long)]
        json: bool,
    },
    /// Provider credentials
    Providers {
        #[command(subcommand)]
        command: ProvidersCommands,
    },
    /// Workspace selection
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommands,
    },
    /// Start the local web interface
    Web {
        #[arg(long)]
        port: Option<u16>,
    },
    /// Start the headless server
    Serve {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        cors: Vec<String>,
        /// Bind a non-loopback address. Requires FREEDAS_SERVER_TOKEN.
        #[arg(long)]
        allow_remote: bool,
    },
    /// Agent Client Protocol server over stdio
    Acp,
    /// Remote control relay
    Relay {
        #[command(subcommand)]
        command: RelayCommands,
    },
    /// Router diagnostics
    Router {
        #[command(subcommand)]
        command: RouterCommands,
    },
    /// Memory management
    Memory {
        #[command(subcommand)]
        command: MemoryCommands,
    },
    /// Print the another-harness rule set
    Rules,
    /// Benchmark harness
    Bench {
        #[command(subcommand)]
        command: BenchCommands,
    },
    /// Print data/config/state paths
    Debug {
        #[arg(default_value = "")]
        what: String,
    },
    /// Upgrade to the latest version
    Upgrade { version: Option<String> },
    /// Uninstall
    Uninstall {
        #[arg(long)]
        keep_config: bool,
        #[arg(long)]
        keep_data: bool,
        /// Delete without the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum SessionCommands {
    List,
    Delete {
        id: String,
    },
    Fork {
        id: String,
        #[arg(long)]
        at: Option<String>,
    },
    Rename {
        id: String,
        title: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum AgentCommands {
    Create {
        #[arg(long)]
        global: bool,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        model: Option<String>,
        /// Extra rule as `action:resource=effect` (repeatable).
        #[arg(long)]
        permission: Vec<String>,
    },
    List,
}

#[derive(Subcommand, Debug, Clone)]
enum SkillCommands {
    List {
        #[arg(long)]
        local: bool,
        #[arg(long)]
        auto: bool,
    },
    Push {
        name: String,
        #[arg(long)]
        dir: Option<String>,
    },
    Pull {
        name: String,
        #[arg(long)]
        global: bool,
        #[arg(long)]
        force: bool,
    },
    Forget {
        id: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum PluginCommands {
    List,
    Remove { name: String },
    Update { name: Option<String> },
}
#[derive(Subcommand, Debug, Clone)]
enum McpCommands {
    List,
    Add {
        name: String,
        #[arg(long)]
        url: Option<String>,
        /// Local server command: everything after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    Auth {
        name: String,
    },
    Logout {
        name: String,
    },
    Debug {
        name: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ProvidersCommands {
    Login { provider: Option<String> },
    List,
    Logout { provider: Option<String> },
}

#[derive(Subcommand, Debug, Clone)]
enum WorkspaceCommands {
    List,
    Use { slug: String },
}

#[derive(Subcommand, Debug, Clone)]
enum RelayCommands {
    Start {
        #[arg(long)]
        foreground: bool,
    },
    Stop,
    Share {
        id: String,
    },
    Unshare {
        id: String,
    },
    Status,
}

#[derive(Subcommand, Debug, Clone)]
enum RouterCommands {
    Explain {
        #[arg(long)]
        last: bool,
    },
    Stats,
}

#[derive(Subcommand, Debug, Clone)]
enum MemoryCommands {
    List {
        /// Include every project's memories, not just this project's.
        #[arg(long)]
        global: bool,
    },
    Show {
        id: String,
        #[arg(long)]
        global: bool,
    },
    Forget {
        id: String,
        #[arg(long)]
        global: bool,
    },
    Export,
}

#[derive(Subcommand, Debug, Clone)]
enum BenchCommands {
    Run {
        #[arg(long)]
        suite: String,
        #[arg(long)]
        repeat: Option<u32>,
        #[arg(long, value_parser = ["static", "learned", "off"])]
        router: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::try_init().ok();
    let cli = Cli::parse();
    let project = cli.project.clone().unwrap_or_else(|| ".".into());
    let project_root = std::path::PathBuf::from(project);
    let project_root = freedas_core::paths::find_project_root(&project_root);

    match cmd::run(cli, project_root).await {
        Ok(0) => Ok(()),
        // Distinct exit codes: 3 permission-blocked, 4 budget, 5 sandbox.
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("freedas: {e:#}");
            std::process::exit(1);
        }
    }
}
