// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Unit tests for wireguard-ringlog.

#[cfg(test)]
mod tests {
    use crate::types::*;
    use crate::RingLogger;
    use std::io::Write;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_binary_layout() {
        assert_eq!(std::mem::size_of::<LogLine>(), 520);
        assert_eq!(std::mem::align_of::<LogLine>(), 8);
        assert_eq!(std::mem::size_of::<LogMem>(), 1_064_968);
        assert_eq!(std::mem::align_of::<LogMem>(), 8);
        assert_eq!(MAGIC, 0x0bad_babe);
        assert_eq!(MAX_LOG_LINE_LENGTH, 512);
        assert_eq!(MAX_TAG_LENGTH, 5);
        assert_eq!(MAX_LINES, 2048);
    }

    #[test]
    fn test_tag_length_validation() {
        assert!(RingLogger::new_in_memory("12345").is_ok());
        assert!(RingLogger::new_in_memory("A").is_ok());
        assert!(RingLogger::new_in_memory("").is_ok());

        // 6 characters should fail
        let err = RingLogger::new_in_memory("123456").unwrap_err();
        match err {
            RinglogError::TagTooLong(len, max) => {
                assert_eq!(len, 6);
                assert_eq!(max, 5);
            }
            _ => panic!("Expected TagTooLong error, got: {:?}", err),
        }
    }

    #[test]
    fn test_write_and_read_single() {
        let rl = RingLogger::new_in_memory("TUN").unwrap();
        let ts = 1_600_000_000_123_456_789i64;

        let written = rl
            .write_with_timestamp(b"WireGuard adapter up", ts)
            .unwrap();
        assert_eq!(written, b"WireGuard adapter up".len());

        let log = rl.log_mem();
        assert_eq!(log.next_index.load(Ordering::Acquire), 1);

        let line = &log.lines[0];
        assert_eq!(line.timestamp_ns(), ts);
        let text = line.get_text().expect("Line should have valid text");
        assert_eq!(text, "[TUN] WireGuard adapter up");
    }

    #[test]
    fn test_whitespace_and_newline_trimming() {
        let rl = RingLogger::new_in_memory("MGR").unwrap();

        rl.write_bytes(b"  \t hello world \r\n  ").unwrap();
        let lines = rl.all_lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line, "[MGR] hello world");

        // Blank or whitespace-only lines must not append an entry
        rl.write_bytes(b"   \r\n\t   ").unwrap();
        assert_eq!(rl.all_lines().len(), 1);
    }

    #[test]
    fn test_line_truncation() {
        let rl = RingLogger::new_in_memory("TAG").unwrap();
        // Tag is 3 chars. Prefix: "[TAG] " is 6 chars.
        // Max line is 512, reserving 1 byte for null terminator -> max text 511.
        // Max payload is 511 - 6 = 505 chars.
        let huge_payload = "X".repeat(1000);
        rl.write_str(&huge_payload).unwrap();

        let lines = rl.all_lines();
        assert_eq!(lines.len(), 1);
        let text = &lines[0].line;
        assert_eq!(text.len(), 511);
        assert!(text.starts_with("[TAG] "));
        assert_eq!(&text[6..], "X".repeat(505));
    }

    #[test]
    fn test_cursor_streaming() {
        let rl = RingLogger::new_in_memory("ONE").unwrap();
        let mut cursor = rl.cursor();

        // Initially empty
        let initial = cursor.next_batch();
        assert!(initial.is_empty());

        // Write 3 lines
        rl.write_str("Line 1").unwrap();
        rl.write_str("Line 2").unwrap();
        rl.write_str("Line 3").unwrap();

        let batch1 = cursor.next_batch();
        assert_eq!(batch1.len(), 3);
        assert_eq!(batch1[0].line, "[ONE] Line 1");
        assert_eq!(batch1[1].line, "[ONE] Line 2");
        assert_eq!(batch1[2].line, "[ONE] Line 3");

        // Next poll should yield no new lines
        let batch2 = cursor.next_batch();
        assert!(batch2.is_empty());

        // Write 2 more lines
        rl.write_str("Line 4").unwrap();
        rl.write_str("Line 5").unwrap();

        let batch3 = cursor.next_batch();
        assert_eq!(batch3.len(), 2);
        assert_eq!(batch3[0].line, "[ONE] Line 4");
        assert_eq!(batch3[1].line, "[ONE] Line 5");
    }

    #[test]
    fn test_circular_wrap_around() {
        let rl = RingLogger::new_in_memory("WRAP").unwrap();

        // Write 3000 lines (exceeds MAX_LINES 2048)
        let total_lines = 3000;
        for i in 0..total_lines {
            rl.write_with_timestamp(format!("Message {}", i).as_bytes(), (i + 1) as i64)
                .unwrap();
        }

        assert_eq!(rl.next_index(), 3000);

        // Fetching all lines from cursor CURSOR_ALL should return exactly MAX_LINES (2048)
        // lines in chronological order starting from Message 952 to Message 2999
        let lines = rl.all_lines();
        assert_eq!(lines.len(), MAX_LINES);

        let first_expected_idx = total_lines - MAX_LINES; // 3000 - 2048 = 952
        for (i, item) in lines.iter().enumerate() {
            let expected_idx = first_expected_idx + i;
            let expected_text = format!("[WRAP] Message {}", expected_idx);
            assert_eq!(item.line, expected_text);
            assert_eq!(item.timestamp_ns, (expected_idx + 1) as i64);
        }
    }

    #[test]
    fn test_concurrent_multithreaded_writes() {
        let rl = Arc::new(RingLogger::new_in_memory("PAR").unwrap());
        let num_threads = 8;
        let lines_per_thread = 100;
        let mut handles = Vec::new();

        for t in 0..num_threads {
            let rl_clone = Arc::clone(&rl);
            handles.push(thread::spawn(move || {
                for i in 0..lines_per_thread {
                    let msg = format!("Thread {} message {}", t, i);
                    rl_clone.write_str(&msg).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(rl.next_index(), (num_threads * lines_per_thread) as u32);
        let lines = rl.all_lines();
        assert_eq!(lines.len(), num_threads * lines_per_thread);

        for line in &lines {
            assert!(line.line.starts_with("[PAR] Thread "));
            assert!(line.timestamp_ns > 0);
        }
    }

    #[test]
    fn test_write_to_formatting() {
        let rl = RingLogger::new_in_memory("FMT").unwrap();
        let ts = 1_700_000_000_000_000_000i64; // Exact seconds
        rl.write_with_timestamp(b"Formatted message", ts).unwrap();

        let mut output = Vec::new();
        let bytes_written = rl.write_to(&mut output).unwrap();
        assert!(bytes_written > 0);

        let out_str = String::from_utf8(output).unwrap();
        assert!(out_str.contains(": [FMT] Formatted message\n"));
    }

    #[test]
    fn test_std_io_write_implementation() {
        let mut rl = RingLogger::new_in_memory("IO").unwrap();
        writeln!(rl, "Hello via writeln! {}", 42).unwrap();

        let lines = rl.all_lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line, "[IO] Hello via writeln! 42");
    }

    #[test]
    fn test_civil_date_calculation() {
        // Epoch 0 nanos = 1970-01-01 00:00:00.000000
        assert_eq!(
            format_timestamp(0),
            "1970-01-01 00:00:00.000000"
        );

        // 1 billion nanos = 1 second
        assert_eq!(
            format_timestamp(1_000_000_000),
            "1970-01-01 00:00:01.000000"
        );

        // 1 microsecond = 1000 nanos
        assert_eq!(
            format_timestamp(1_000),
            "1970-01-01 00:00:00.000001"
        );

        // Specific date: 2026-11-07 12:00:00 UTC
        // 2026 is non-leap.
        let (y, m, d, hh, mm, ss, _) = unix_nanos_to_utc(1_794_052_800_000_000_000);
        assert_eq!(y, 2026);
        assert_eq!(m, 11);
        assert_eq!(d, 7);
        assert_eq!(hh, 12);
        assert_eq!(mm, 0);
        assert_eq!(ss, 0);

        // Leap day 2024-02-29 00:00:00 UTC (19782 days * 86400s)
        let (y, m, d, hh, mm, ss, _) = unix_nanos_to_utc(1_709_164_800_000_000_000);
        assert_eq!((y, m, d, hh, mm, ss), (2024, 2, 29, 0, 0, 0));

        // Leap day 2028-02-29 23:59:59 UTC (21243 days * 86400s + 86399s)
        let (y, m, d, hh, mm, ss, _) = unix_nanos_to_utc(1_835_481_599_000_000_000);
        assert_eq!((y, m, d, hh, mm, ss), (2028, 2, 29, 23, 59, 59));

        // Century leap day 2000-02-29 00:00:00 UTC (11016 days * 86400s)
        let (y, m, d, _, _, _, _) = unix_nanos_to_utc(951_782_400_000_000_000);
        assert_eq!((y, m, d), (2000, 2, 29));

        // Non-leap century 2100-03-01 00:00:00 UTC (47541 days * 86400s)
        let (y, m, d, _, _, _, _) = unix_nanos_to_utc(4_107_542_400_000_000_000);
        assert_eq!((y, m, d), (2100, 3, 1));
    }

    #[test]
    fn test_stream_mem_to_beyond_max_lines() {
        use std::sync::mpsc;

        struct NotifyWriter {
            buf: Vec<u8>,
            tx: mpsc::Sender<()>,
        }

        impl Write for NotifyWriter {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.buf.extend_from_slice(data);
                Ok(data.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                let _ = self.tx.send(());
                Ok(())
            }
        }

        let rl = Arc::new(RingLogger::new_in_memory("STRM").unwrap());
        for i in 0..2500 {
            rl.write_with_timestamp(format!("Msg {}", i).as_bytes(), (i + 1) as i64)
                .unwrap();
        }

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let rl_clone = Arc::clone(&rl);
        let (tx, rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let mut writer = NotifyWriter {
                buf: Vec::new(),
                tx,
            };
            let _ = crate::stream_mem_to(
                rl_clone.log_mem(),
                &mut writer,
                std::time::Duration::from_millis(5),
                Some(&stop_clone),
            );
            String::from_utf8(writer.buf).unwrap()
        });

        // Wait for initial 2048 lines flush, then append one more line and wait for its flush.
        rx.recv().unwrap();
        rl.write_with_timestamp(b"Msg 2500", 2501).unwrap();
        rx.recv().unwrap();
        stop.store(true, Ordering::Relaxed);

        let dumped = handle.join().unwrap();
        let dumped_lines: Vec<&str> = dumped.lines().collect();
        assert_eq!(dumped_lines.len(), MAX_LINES + 1);
        assert!(dumped_lines.first().unwrap().ends_with(": [STRM] Msg 452"));
        assert!(dumped_lines.last().unwrap().ends_with(": [STRM] Msg 2500"));
    }

    #[test]
    fn test_file_backed_persistence() {
        let temp_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wg_test_ringlog");
        let _ = std::fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join(format!(
            "ringlog_test_{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        // Create and write
        {
            let rl = RingLogger::create(&file_path, "PERS").unwrap();
            rl.write_str("Entry 1").unwrap();
            rl.write_str("Entry 2").unwrap();
            rl.flush().unwrap();
        }

        // Re-open and verify contents
        {
            let rl = RingLogger::open(&file_path, "READ").unwrap();
            let lines = rl.all_lines();
            assert_eq!(lines.len(), 2);
            assert_eq!(lines[0].line, "[PERS] Entry 1");
            assert_eq!(lines[1].line, "[PERS] Entry 2");
        }

        let _ = std::fs::remove_file(&file_path);
    }
}
