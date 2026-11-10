//! Router outcome recording (methods on Db).

use crate::Db;
use freedas_core::Result;
use rusqlite::params;

impl Db {
    pub fn record_router_outcome(
        &self,
        task_class: &str,
        model: &str,
        success: bool,
        cost: f64,
    ) -> Result<()> {
        let now = freedas_core::paths::now_ms();
        self.lock().execute(
            "INSERT INTO router_stats (task_class, model, attempts, successes, failures, total_cost_usd, updated_at)
             VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6)
             ON CONFLICT(task_class, model) DO UPDATE SET
               attempts = attempts + 1,
               successes = successes + excluded.successes,
               failures = failures + excluded.failures,
               total_cost_usd = total_cost_usd + excluded.total_cost_usd,
               updated_at = excluded.updated_at",
            params![
                task_class,
                model,
                if success { 1 } else { 0 },
                if success { 0 } else { 1 },
                cost,
                now
            ],
        )?;
        Ok(())
    }
}
