//! A2G governance demo — CLI entry point.
//!
//! Subcommands:
//!   `run`    — four-beat showcase (starts an embedded gateway internally)
//!   `listen` — subscribe to vcan0 and print enforcement frames as they arrive

use a2g_demo::{listen, showcase};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "a2g-demo",
    about = "A2G governance demo — watch the enforcement pipeline end-to-end",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the four-beat governance showcase.
    ///
    /// Starts an embedded gateway, runs all four beats in sequence, and prints
    /// narrated output.  Beats 1 and 4 produce CAN frames; beats 2 and 3 do not.
    /// Use --pause to wait for Enter between beats (useful for screen recording).
    Run {
        /// CAN interface the embedded gateway writes to.
        #[arg(long, default_value = "vcan0")]
        vcan: String,

        /// Pause between beats (waits for Enter — useful for screen recording).
        #[arg(long)]
        pause: bool,
    },

    /// Listen on a SocketCAN interface and print A2G enforcement frames.
    ///
    /// Run this in a second terminal pane while `a2g-demo run` executes.
    /// The listener prints only real CAN frames (CAN ID 0x7A2) — silence in
    /// this pane during beats 2 and 3 is intentional and meaningful.
    Listen {
        /// CAN interface to subscribe to.
        #[arg(long, default_value = "vcan0")]
        iface: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run { vcan, pause } => {
            showcase::run(&vcan, pause);
        }
        Commands::Listen { iface } => {
            listen::listen(&iface);
        }
    }
}
