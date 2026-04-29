use anyhow::{Context, Result};
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
};

mod snp;

thread_local! {
    static PREOPEN_CACHE_DIR: RefCell<Option<PathBuf>> = RefCell::new(None);
}

struct CacheDirGuard {
    previous: Option<PathBuf>,
}

impl CacheDirGuard {
    fn set(cache_dir: &Path) -> Self {
        let previous = PREOPEN_CACHE_DIR.with(|slot| slot.replace(Some(cache_dir.to_path_buf())));
        Self { previous }
    }
}

impl Drop for CacheDirGuard {
    fn drop(&mut self) {
        PREOPEN_CACHE_DIR.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

fn current_preopen_directories() -> Vec<(wasip2::filesystem::preopens::Descriptor, String)> {
    PREOPEN_CACHE_DIR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|path| {
                vec![(
                    wasip2::filesystem::preopens::Descriptor,
                    path.display().to_string(),
                )]
            })
            .unwrap_or_default()
    })
}

#[derive(Clone, Debug, Default)]
pub struct NativeSnpVerifier;

impl NativeSnpVerifier {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    pub fn verify_bytes(
        &self,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        cache_dir: &Path,
    ) -> Result<serde_json::Value> {
        std::fs::create_dir_all(cache_dir)
            .with_context(|| format!("create {}", cache_dir.display()))?;

        let _cache_dir_guard = CacheDirGuard::set(cache_dir);
        let evidence = snp::parse_evidence_bytes(evidence).context("parse SNP evidence")?;
        snp::evaluate(
            &snp::Snp::new(),
            evidence,
            expected_report_data,
            expected_init_data_hash,
        )
    }
}

mod wasip2 {
    pub mod filesystem {
        pub mod preopens {
            #[derive(Debug)]
            pub struct Descriptor;

            pub fn get_directories() -> Vec<(Descriptor, String)> {
                super::super::super::current_preopen_directories()
            }
        }
    }
}

mod waki {
    use anyhow::{Context, Result};

    pub struct Client {
        inner: reqwest::blocking::Client,
    }

    impl Client {
        pub fn new() -> Self {
            Self {
                inner: reqwest::blocking::Client::new(),
            }
        }

        pub fn get(&self, url: &str) -> RequestBuilder {
            RequestBuilder {
                inner: self.inner.get(url),
            }
        }
    }

    pub struct RequestBuilder {
        inner: reqwest::blocking::RequestBuilder,
    }

    impl RequestBuilder {
        pub fn send(self) -> Result<Response> {
            let response = self.inner.send().context("send native HTTP request")?;
            Ok(Response { inner: response })
        }
    }

    pub struct Response {
        inner: reqwest::blocking::Response,
    }

    impl Response {
        pub fn status_code(&self) -> u16 {
            self.inner.status().as_u16()
        }

        pub fn body(self) -> Result<Vec<u8>> {
            Ok(self
                .inner
                .bytes()
                .context("read native HTTP response body")?
                .to_vec())
        }
    }
}
