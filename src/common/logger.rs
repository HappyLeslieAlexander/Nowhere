// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Service log levels and terminal output.

use std::fmt;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI32, Ordering},
};

use chrono::Local;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum LogLevel {
    None = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

const LEVEL_STRINGS: [&str; 5] = ["NONE", "DEBUG", "INFO", "WARN", "ERROR"];
const LEVEL_COLORS: [&str; 5] = ["", "\x1b[34m", "\x1b[32m", "\x1b[33m", "\x1b[31m"];
const RESET_COLOR: &str = "\x1b[0m";

#[derive(Clone, Debug)]
pub struct Logger {
    level: Arc<AtomicI32>,
    color_enabled: bool,
    output_lock: Arc<Mutex<()>>,
}

impl Logger {
    pub fn new(log_level: LogLevel, enable_color: bool) -> Self {
        Self {
            level: Arc::new(AtomicI32::new(log_level as i32)),
            color_enabled: enable_color,
            output_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn set_log_level(&self, log_level: LogLevel) {
        self.level.store(log_level as i32, Ordering::Relaxed);
    }

    pub fn debug_enabled(&self) -> bool {
        self.enabled(LogLevel::Debug)
    }

    pub fn debug(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Debug, args);
    }

    pub fn info(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Info, args);
    }

    pub fn warn(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Warn, args);
    }

    pub fn error(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Error, args);
    }

    pub fn flush(&self) {}

    fn do_log(&self, log_level: LogLevel, args: fmt::Arguments<'_>) {
        if !self.enabled(log_level) {
            return;
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let level = LEVEL_STRINGS[log_level as usize];
        let line = if self.color_enabled {
            format!(
                "{timestamp}  {}{}{}  {args}\n",
                LEVEL_COLORS[log_level as usize], level, RESET_COLOR
            )
        } else {
            format!("{timestamp}  {level}  {args}\n")
        };

        if let Ok(_guard) = self.output_lock.lock() {
            print!("{line}");
        }
    }

    fn enabled(&self, log_level: LogLevel) -> bool {
        let current = self.level.load(Ordering::Relaxed);
        current != LogLevel::None as i32 && (log_level as i32) >= current
    }
}

#[cfg(test)]
#[path = "../tests/common/logger.rs"]
mod tests;
