//! PL011 UART driver for the QEMU `virt` machine (MMIO at 0x0900_0000).
//!
//! Drives `print!`/`println!` and blocking line input for the shell. QEMU wires
//! the first PL011 to the `-nographic` serial console, so this is the kernel's
//! only console.

use core::fmt::{self, Write};

use crate::sync::SpinLock;

const UART0_BASE: usize = 0x0900_0000;

// Register offsets.
const DR: usize = 0x00; // data register
const FR: usize = 0x18; // flag register
const IBRD: usize = 0x24;
const FBRD: usize = 0x28;
const LCRH: usize = 0x2C;
const CR: usize = 0x30;
const IMSC: usize = 0x38;

// Flag register bits.
const FR_RXFE: u32 = 1 << 4; // receive FIFO empty
const FR_TXFF: u32 = 1 << 5; // transmit FIFO full

pub struct Uart {
    base: usize,
}

impl Uart {
    const fn new(base: usize) -> Self {
        Self { base }
    }

    #[inline]
    unsafe fn reg(&self, off: usize) -> *mut u32 {
        (self.base + off) as *mut u32
    }

    pub fn init(&self) {
        unsafe {
            // Disable UART during configuration.
            self.reg(CR).write_volatile(0);
            // Mask all interrupts (we poll).
            self.reg(IMSC).write_volatile(0);
            // 115200 baud at QEMU's 24 MHz reference: IBRD=13, FBRD=1.
            self.reg(IBRD).write_volatile(13);
            self.reg(FBRD).write_volatile(1);
            // 8N1, FIFOs disabled (WLEN=8 -> bits 6:5). A 1-char holding
            // register lets QEMU flow-control piped input losslessly instead of
            // overrunning a 16-byte FIFO while the kernel is busy.
            self.reg(LCRH).write_volatile(0b11 << 5);
            // Enable UART, TX, RX.
            self.reg(CR).write_volatile((1 << 0) | (1 << 8) | (1 << 9));
        }
    }

    pub fn put(&self, c: u8) {
        unsafe {
            while self.reg(FR).read_volatile() & FR_TXFF != 0 {
                core::hint::spin_loop();
            }
            self.reg(DR).write_volatile(c as u32);
        }
    }

    /// Non-blocking read of one byte, if the RX FIFO is non-empty.
    pub fn try_get(&self) -> Option<u8> {
        unsafe {
            if self.reg(FR).read_volatile() & FR_RXFE != 0 {
                None
            } else {
                Some((self.reg(DR).read_volatile() & 0xFF) as u8)
            }
        }
    }

}

impl Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.put(b'\r');
            }
            self.put(b);
        }
        Ok(())
    }
}

pub static UART: SpinLock<Uart> = SpinLock::new(Uart::new(UART0_BASE));

pub fn init() {
    UART.lock().init();
}

pub fn _print(args: fmt::Arguments) {
    UART.lock().write_fmt(args).ok();
}

/// Blocking single-byte read from the console.
pub fn getc() -> u8 {
    // Take the lock only for the register poke, releasing between polls so the
    // rest of the system is not starved while waiting for input.
    loop {
        if let Some(b) = UART.lock().try_get() {
            return b;
        }
        core::hint::spin_loop();
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::uart::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::uart::_print(format_args!("{}\n", format_args!($($arg)*))));
}
