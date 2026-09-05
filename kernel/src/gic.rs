//! GICv2 interrupt controller for the QEMU `virt` machine.
//! Distributor at 0x0800_0000, CPU interface at 0x0801_0000.

const GICD_BASE: usize = 0x0800_0000;
const GICC_BASE: usize = 0x0801_0000;

// Distributor registers.
const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_IPRIORITYR: usize = 0x400;

// CPU interface registers.
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;

#[inline]
unsafe fn gicd(off: usize) -> *mut u32 {
    (GICD_BASE + off) as *mut u32
}

#[inline]
unsafe fn gicc(off: usize) -> *mut u32 {
    (GICC_BASE + off) as *mut u32
}

pub fn init() {
    unsafe {
        // Enable the distributor.
        gicd(GICD_CTLR).write_volatile(1);
        // Accept all priorities on the CPU interface and enable it.
        gicc(GICC_PMR).write_volatile(0xFF);
        gicc(GICC_CTLR).write_volatile(1);
    }
}

/// Enable an interrupt id (PPI or SPI) and give it the highest priority.
pub fn enable(intid: u32) {
    unsafe {
        let reg = GICD_ISENABLER + (intid as usize / 32) * 4;
        gicd(reg).write_volatile(1 << (intid % 32));
        // IPRIORITYR is byte-addressed; write 0 (highest) for this id.
        let pri = (GICD_IPRIORITYR + intid as usize) as *mut u8;
        pri.write_volatile(0x00);
    }
}

/// Read the interrupt acknowledge register (returns the full IAR value).
pub fn acknowledge() -> u32 {
    unsafe { gicc(GICC_IAR).read_volatile() }
}

/// Signal end-of-interrupt for a previously acknowledged IAR value.
pub fn end_of_interrupt(iar: u32) {
    unsafe { gicc(GICC_EOIR).write_volatile(iar) }
}
