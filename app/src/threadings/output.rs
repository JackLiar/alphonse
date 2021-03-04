use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::{Datelike, Timelike};
use crossbeam_channel::Receiver;
use elasticsearch::{http::transport::Transport, Elasticsearch};

use alphonse_api as api;
use api::session::Session;
use api::utils::timeval::{precision::Millisecond, TimeVal};

use crate::config::Config;

enum Rotate {
    Hourly(u32),
    Daily,
    Weekly,
    Monthly,
}

impl TryFrom<&str> for Rotate {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let r = match value {
            "daily" => Rotate::Daily,
            "week" => Rotate::Weekly,
            "monthly" => Rotate::Monthly,
            "hourly" => Rotate::Hourly(1),
            "hourly2" => Rotate::Hourly(2),
            "hourly3" => Rotate::Hourly(3),
            "hourly4" => Rotate::Hourly(4),
            "hourly6" => Rotate::Hourly(6),
            "hourly8" => Rotate::Hourly(8),
            "hourly12" => Rotate::Hourly(12),
            _ => return Err(anyhow!("Unknown Rotate: {}", value)),
        };
        Ok(r)
    }
}

/// Convert timestamp to index suffix
fn to_index_suffix(rotate: Rotate, ts: &TimeVal<Millisecond>) -> String {
    let stime = std::time::UNIX_EPOCH
        + std::time::Duration::from_nanos(ts.tv_sec as u64 * 1000000000 + ts.tv_usec as u64 * 1000);
    let datetime = chrono::DateTime::<chrono::Utc>::from(stime);
    match rotate {
        Rotate::Daily => datetime.format("%y%m%d").to_string(),
        Rotate::Weekly => {
            format!(
                "{:2}{:2}{:2}",
                datetime.year() % 100,
                datetime.month(),
                datetime.day() / 7,
            )
        }
        Rotate::Monthly => datetime.format("%y%m").to_string(),
        Rotate::Hourly(hours) => {
            format!(
                "{:2}{:2}{:2}{}",
                datetime.year() % 100,
                datetime.month(),
                datetime.day(),
                (datetime.time().hour() / hours) * hours,
            )
        }
    }
}

pub struct Thread {
    receiver: Receiver<Box<Session>>,
}

impl Thread {
    pub fn new(receiver: Receiver<Box<Session>>) -> Self {
        Thread { receiver }
    }

    pub fn name(&self) -> String {
        format!("alphonse-output")
    }

    pub fn spawn(&mut self, cfg: Arc<Config>) -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("alphonse-output-tokio")
            .enable_all()
            .build()
            .unwrap();
        let host = cfg.get_str("elasticsearch", "http://localhost:9200");
        let es = Arc::new(Elasticsearch::new(Transport::single_node(host.as_str())?));

        println!("{} started", self.name());

        let mut sessions = vec![];

        rt.block_on(async {
            loop {
                let ses = match self.receiver.try_recv() {
                    Ok(ses) => ses,
                    Err(err) => match err {
                        crossbeam_channel::TryRecvError::Disconnected => break,
                        _ => continue,
                    },
                };

                if cfg.dry_run {
                    continue;
                }
                sessions.push(Arc::from(ses));
                if sessions.len() == 5 {
                    let sessions_cloned = Box::new(sessions.clone());
                    let cfg = cfg.clone();
                    let es = es.clone();
                    tokio::spawn(async {
                        Thread::save_sessions(cfg, es, sessions_cloned)
                            .await
                            .unwrap();
                    })
                    .await
                    .unwrap();
                    sessions.clear();
                }
            }
        });

        println!("{} exit", self.name());

        Ok(())
    }

    async fn save_sessions(
        _cfg: Arc<Config>,
        es: Arc<Elasticsearch>,
        sessions: Box<Vec<Arc<Session>>>,
    ) -> Result<()> {
        let mut body = vec![];
        for ses in sessions.iter() {
            let index = format!(
                "sessions2-{}",
                to_index_suffix(Rotate::Daily, &ses.start_time)
            );
            let bulk_op = elasticsearch::BulkOperation::index(ses.clone()).index(index);
            body.push(bulk_op);
        }
        let body = sessions
            .iter()
            .map(|ses| {
                let index = format!(
                    "sessions2-{}",
                    to_index_suffix(Rotate::Daily, &ses.start_time)
                );
                elasticsearch::BulkOperation::from(
                    elasticsearch::BulkOperation::index(ses.as_ref()).index(index),
                )
            })
            .collect();
        let resp = es
            .bulk(elasticsearch::BulkParts::None)
            .body(body)
            .send()
            .await?;
        let code = resp.status_code();
        match code.as_u16() {
            200 => {}
            c => {
                println!("status code: {}", c);
                println!("response message: {}", resp.text().await.unwrap());
            }
        };

        Ok(())
    }
}
