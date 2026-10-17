use aho_corasick::AhoCorasick;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const REDACTED_MARKER: &[u8] = b"[REDACTED_BY_SENTINEL]";

/// Minimum character length for a secret to be eligible for DLP masking.
/// Prevents short, common values (e.g., "true", "db", "ok") from corrupting JSON payloads.
pub const MIN_SECRET_LEN: usize = 5;

pub struct StreamRedactor {
    ac: Option<AhoCorasick>,
    patterns: Vec<Vec<u8>>,
    replacements: Vec<&'static [u8]>,
    carryover: Vec<u8>,
}

impl StreamRedactor {
    pub fn new(secrets: &[String]) -> Self {
        let valid_secrets: Vec<Vec<u8>> = secrets
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .filter(|b| b.len() >= MIN_SECRET_LEN)
            .collect();

        if valid_secrets.is_empty() {
            return Self {
                ac: None,
                patterns: Vec::new(),
                replacements: Vec::new(),
                carryover: Vec::new(),
            };
        }

        let ac = AhoCorasick::new(&valid_secrets).ok();
        let replacements = vec![REDACTED_MARKER; valid_secrets.len()];

        Self {
            ac,
            patterns: valid_secrets,
            replacements,
            carryover: Vec::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.ac.is_some()
    }

    /// Redacts secrets from an in-memory byte slice.
    pub fn redact_bytes(&self, input: &[u8]) -> Vec<u8> {
        if let Some(ref ac) = self.ac {
            ac.replace_all_bytes(input, &self.replacements)
        } else {
            input.to_vec()
        }
    }

    /// Streams from `reader` to `writer`, transparently redacting known secrets even across chunk boundaries.
    pub async fn pipe_and_redact<R, W>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if self.ac.is_none() {
            tokio::io::copy(&mut reader, &mut writer).await?;
            return Ok(());
        }

        let ac = self.ac.as_ref().unwrap();
        let mut buf = [0u8; 8192];

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                // EOF: Process any remaining carryover bytes and flush completely
                if !self.carryover.is_empty() {
                    let final_redacted = ac.replace_all_bytes(&self.carryover, &self.replacements);
                    writer.write_all(&final_redacted).await?;
                    self.carryover.clear();
                }
                writer.flush().await?;
                break;
            }

            // Combine previous carryover with new incoming bytes
            let mut combined = std::mem::take(&mut self.carryover);
            combined.extend_from_slice(&buf[..n]);

            // Replace all complete matches found in the combined window
            let redacted = ac.replace_all_bytes(&combined, &self.replacements);

            // Calculate if the tail of the redacted buffer forms a prefix of any secret pattern
            let max_overlap = longest_matching_suffix_prefix(&redacted, &self.patterns);

            if max_overlap == 0 {
                // No prefix overlap at the end: safe to flush 100% of the buffer immediately
                writer.write_all(&redacted).await?;
            } else {
                // Suffix matches a secret prefix: output everything except the matching suffix
                let safe_boundary = redacted.len() - max_overlap;
                if safe_boundary > 0 {
                    writer.write_all(&redacted[..safe_boundary]).await?;
                }
                self.carryover = redacted[safe_boundary..].to_vec();
            }

            writer.flush().await?;
        }

        Ok(())
    }
}

/// Finds the length of the longest suffix of `data` that is a non-empty proper prefix of any pattern.
fn longest_matching_suffix_prefix(data: &[u8], patterns: &[Vec<u8>]) -> usize {
    if data.is_empty() || patterns.is_empty() {
        return 0;
    }

    let mut max_overlap = 0;
    for pat in patterns {
        let max_k = (pat.len() - 1).min(data.len());
        for k in (1..=max_k).rev() {
            if k <= max_overlap {
                break;
            }
            if pat.starts_with(&data[data.len() - k..]) {
                max_overlap = max_overlap.max(k);
                break;
            }
        }
    }

    max_overlap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redactor_basic_replacement() {
        let secrets = vec![
            "sk-ant-api03-verylongsecretkey12345".to_string(),
            "my_super_db_password_888".to_string(),
        ];
        let redactor = StreamRedactor::new(&secrets);

        let input = b"Connecting to db with my_super_db_password_888 using token sk-ant-api03-verylongsecretkey12345 done";
        let output = redactor.redact_bytes(input);
        let output_str = String::from_utf8(output).unwrap();

        assert_eq!(
            output_str,
            "Connecting to db with [REDACTED_BY_SENTINEL] using token [REDACTED_BY_SENTINEL] done"
        );
    }

    #[test]
    fn test_redactor_ignores_short_secrets() {
        let secrets = vec!["abc".to_string(), "foo".to_string(), "1234".to_string()];
        let redactor = StreamRedactor::new(&secrets);
        assert!(!redactor.is_active());

        let input = b"This is abc and foo and 1234";
        let output = redactor.redact_bytes(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_longest_matching_suffix_prefix() {
        let patterns = vec![b"ghp_123456789".to_vec()];

        // Exact partial prefix at the end
        assert_eq!(longest_matching_suffix_prefix(b"hello ghp_", &patterns), 4);
        assert_eq!(
            longest_matching_suffix_prefix(b"hello ghp_123", &patterns),
            7
        );
        assert_eq!(longest_matching_suffix_prefix(b"g", &patterns), 1);

        // No overlap
        assert_eq!(
            longest_matching_suffix_prefix(b"hello world\n", &patterns),
            0
        );
        assert_eq!(longest_matching_suffix_prefix(b"", &patterns), 0);
    }

    #[tokio::test]
    async fn test_redactor_streaming_chunk_boundary_split() {
        let secrets = vec!["ghp_SPLIT_SECRET_TOKEN_9999".to_string()];
        let mut redactor = StreamRedactor::new(&secrets);

        // Split the secret exactly across 2 reads
        let chunk1 = b"Prefix text... ghp_SPLIT_";
        let chunk2 = b"SECRET_TOKEN_9999 suffix text";

        let (mut client_writer, server_reader) = tokio::io::duplex(1024);
        let (output_reader, mut host_writer) = tokio::io::duplex(1024);

        let pipe_task = tokio::spawn(async move {
            redactor
                .pipe_and_redact(server_reader, &mut host_writer)
                .await
        });

        // Write chunk 1
        client_writer.write_all(chunk1).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Write chunk 2
        client_writer.write_all(chunk2).await.unwrap();
        drop(client_writer); // Send EOF

        pipe_task.await.unwrap().unwrap();

        let mut output_bytes = Vec::new();
        let mut reader = output_reader;
        reader.read_to_end(&mut output_bytes).await.unwrap();

        let output_str = String::from_utf8(output_bytes).unwrap();
        assert_eq!(
            output_str,
            "Prefix text... [REDACTED_BY_SENTINEL] suffix text"
        );
    }
}
