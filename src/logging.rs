use std::sync::OnceLock;

static VERBOSE: OnceLock<bool> = OnceLock::new();

pub fn init_verbose(verbose: bool) {
    VERBOSE.set(verbose).expect("Verbose flag already initialized");
}

pub fn is_verbose() -> bool {
    *VERBOSE.get().unwrap_or(&false)
}

#[macro_export]
macro_rules! verbose_println {
    ($($arg:tt)*) => {
        if $crate::logging::is_verbose() {
            println!($($arg)*);
        }
    };
}