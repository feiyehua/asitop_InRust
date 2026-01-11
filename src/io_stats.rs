use core_foundation_sys::{
    base::{Boolean, CFAllocatorRef, CFRelease, CFTypeRef},
    dictionary::{CFDictionaryRef, CFMutableDictionaryRef},
    number::{CFNumberRef, CFNumberType, kCFNumberSInt64Type},
    string::{CFStringEncoding, CFStringRef, kCFStringEncodingUTF8},
};
use libc::{
    self, AF_LINK, IFF_LOOPBACK, IFF_UP, KERN_SUCCESS, c_char, c_void, freeifaddrs, getifaddrs,
    if_data, ifaddrs, mach_port_t,
};
use std::{
    ffi::CString,
    ptr,
    time::{Duration, Instant},
};

const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, Default)]
pub struct IoStats {
    pub net_in_mbps: f32,
    pub net_out_mbps: f32,
    pub disk_read_mbps: f32,
    pub disk_write_mbps: f32,
}

pub struct IoSampler {
    last_net: Option<(u64, u64)>,
    last_disk: Option<(u64, u64)>,
    last_instant: Option<Instant>,
    current: IoStats,
}

impl IoSampler {
    pub fn new() -> Self {
        Self {
            last_net: None,
            last_disk: None,
            last_instant: None,
            current: IoStats::default(),
        }
    }

    pub fn sample(&mut self) -> IoStats {
        let now = Instant::now();

        // Skip sampling if not enough time has passed
        if let Some(last) = self.last_instant {
            if now.duration_since(last) < MIN_SAMPLE_INTERVAL {
                return self.current;
            }
        }

        let net_totals = read_network_counters();
        let disk_totals = read_disk_counters();

        if self.last_instant.is_none() {
            self.last_instant = Some(now);
            self.last_net = net_totals;
            self.last_disk = disk_totals;
            self.current = IoStats::default();
            return self.current;
        }

        let delta = now
            .duration_since(self.last_instant.unwrap_or(now))
            .as_secs_f64()
            .max(0.001);

        if let Some((in_bytes, out_bytes)) = net_totals {
            if let Some((prev_in, prev_out)) = self.last_net {
                self.current.net_in_mbps = rate_from_delta(in_bytes, prev_in, delta);
                self.current.net_out_mbps = rate_from_delta(out_bytes, prev_out, delta);
            }
            self.last_net = Some((in_bytes, out_bytes));
        }

        if let Some((read_bytes, write_bytes)) = disk_totals {
            if let Some((prev_read, prev_write)) = self.last_disk {
                self.current.disk_read_mbps = rate_from_delta(read_bytes, prev_read, delta);
                self.current.disk_write_mbps = rate_from_delta(write_bytes, prev_write, delta);
            }
            self.last_disk = Some((read_bytes, write_bytes));
        }

        self.last_instant = Some(now);
        self.current
    }
}

fn rate_from_delta(current: u64, previous: u64, delta_secs: f64) -> f32 {
    if current <= previous || delta_secs <= 0.0 {
        0.0
    } else {
        let diff = current - previous;
        (diff as f64 / delta_secs / (1024.0 * 1024.0)) as f32
    }
}

/// RAII wrapper for interface addresses list
struct IfAddrs {
    ptr: *mut ifaddrs,
}

impl IfAddrs {
    fn new() -> Option<Self> {
        let mut ptr = ptr::null_mut();
        // SAFETY: getifaddrs is called with a valid pointer to store the result
        let result = unsafe { getifaddrs(&mut ptr) };
        if result != 0 || ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    fn iter(&self) -> IfAddrsIter {
        IfAddrsIter {
            current: self.ptr,
            remaining: 1000, // MAX_INTERFACES
        }
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr is guaranteed to be valid and non-null from successful getifaddrs
            unsafe { freeifaddrs(self.ptr) };
        }
    }
}

struct IfAddrsIter {
    current: *const ifaddrs,
    remaining: usize,
}

impl Iterator for IfAddrsIter {
    type Item = IfAddrRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() || self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;

        // SAFETY: current is checked to be non-null and comes from valid getifaddrs result
        let iface = unsafe { &*self.current };
        self.current = iface.ifa_next;

        Some(IfAddrRef { inner: iface })
    }
}

struct IfAddrRef {
    inner: &'static ifaddrs,
}

impl IfAddrRef {
    fn is_valid_link_interface(&self) -> bool {
        if self.inner.ifa_addr.is_null() {
            return false;
        }

        // SAFETY: ifa_addr is checked to be non-null
        let sa_family = unsafe { (*self.inner.ifa_addr).sa_family as i32 };
        if sa_family != AF_LINK {
            return false;
        }

        let flags = self.inner.ifa_flags as i32;
        (flags & IFF_UP) != 0 && (flags & IFF_LOOPBACK) == 0
    }

    fn get_traffic_stats(&self) -> Option<(u64, u64)> {
        let data_ptr = self.inner.ifa_data as *const if_data;
        if data_ptr.is_null() {
            return None;
        }

        // SAFETY: data_ptr is checked to be non-null and comes from valid ifaddrs
        unsafe {
            data_ptr
                .as_ref()
                .map(|data| (data.ifi_ibytes as u64, data.ifi_obytes as u64))
        }
    }
}

fn read_network_counters() -> Option<(u64, u64)> {
    let ifaddrs = IfAddrs::new()?;

    let mut total_in = 0u64;
    let mut total_out = 0u64;

    for iface in ifaddrs.iter() {
        if iface.is_valid_link_interface() {
            if let Some((rx, tx)) = iface.get_traffic_stats() {
                total_in = total_in.saturating_add(rx);
                total_out = total_out.saturating_add(tx);
            }
        }
    }

    Some((total_in, total_out))
}

/// Safe wrapper for IOKit iterator
struct IOIterator {
    handle: io_iterator_t,
}

impl IOIterator {
    fn for_block_storage() -> Option<Self> {
        // SAFETY: IOServiceMatching is called with a valid C string
        let matching =
            unsafe { IOServiceMatching(b"IOBlockStorageDriver\0".as_ptr() as *const c_char) };
        if matching.is_null() {
            return None;
        }

        let mut handle: io_iterator_t = 0;
        // SAFETY: IOServiceGetMatchingServices is called with valid parameters
        let result = unsafe { IOServiceGetMatchingServices(0, matching, &mut handle) };

        if result != KERN_SUCCESS {
            if handle != 0 {
                // SAFETY: handle is valid from IOServiceGetMatchingServices
                unsafe { IOObjectRelease(handle) };
            }
            return None;
        }

        Some(Self { handle })
    }
}

impl Iterator for IOIterator {
    type Item = IOObject;

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: handle is guaranteed to be valid from constructor
        let entry = unsafe { IOIteratorNext(self.handle) };
        if entry == 0 {
            None
        } else {
            Some(IOObject { handle: entry })
        }
    }
}

impl Drop for IOIterator {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: handle is guaranteed to be valid from constructor
            unsafe { IOObjectRelease(self.handle) };
        }
    }
}

/// Safe wrapper for IOKit object
struct IOObject {
    handle: io_object_t,
}

impl Drop for IOObject {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: handle is guaranteed to be valid from IOIteratorNext
            unsafe { IOObjectRelease(self.handle) };
        }
    }
}

fn read_disk_counters() -> Option<(u64, u64)> {
    let iterator = IOIterator::for_block_storage()?;

    let mut total_read = 0u64;
    let mut total_write = 0u64;

    for entry in iterator {
        if let Some((read, write)) = read_entry_bytes(entry.handle) {
            total_read = total_read.saturating_add(read);
            total_write = total_write.saturating_add(write);
        }
    }

    Some((total_read, total_write))
}

/// Safe wrapper for CoreFoundation types
struct CFRef {
    ptr: CFTypeRef,
}

impl CFRef {
    fn from_registry_entry(entry: io_registry_entry_t) -> Option<Self> {
        let mut properties: CFMutableDictionaryRef = ptr::null_mut();
        // SAFETY: IORegistryEntryCreateCFProperties is called with valid parameters
        let result =
            unsafe { IORegistryEntryCreateCFProperties(entry, &mut properties, ptr::null(), 0) };

        if result != KERN_SUCCESS || properties.is_null() {
            None
        } else {
            Some(Self {
                ptr: properties as CFTypeRef,
            })
        }
    }

    fn as_dict(&self) -> CFDictionaryRef {
        self.ptr as CFDictionaryRef
    }
}

impl Drop for CFRef {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr is guaranteed to be valid from constructor
            unsafe { CFRelease(self.ptr) };
        }
    }
}

fn read_entry_bytes(entry: io_registry_entry_t) -> Option<(u64, u64)> {
    let properties = CFRef::from_registry_entry(entry)?;

    let stats_dict = get_dict_value(properties.as_dict(), "Statistics")?;
    let bytes_read = get_number(stats_dict, "Bytes (Read)")?;
    let bytes_write = get_number(stats_dict, "Bytes (Write)")?;

    Some((bytes_read, bytes_write))
}

fn get_dict_value(dict: CFDictionaryRef, key: &str) -> Option<CFDictionaryRef> {
    let cf_key = CFString::new(key)?;
    let mut value: *const c_void = ptr::null();

    // SAFETY: CFDictionaryGetValueIfPresent is called with valid dictionary and key
    let success = unsafe { CFDictionaryGetValueIfPresent(dict, cf_key.as_ptr(), &mut value) };

    if success == 0 || value.is_null() {
        None
    } else {
        Some(value as CFDictionaryRef)
    }
}

fn get_number(dict: CFDictionaryRef, key: &str) -> Option<u64> {
    let cf_key = CFString::new(key)?;
    let mut value: *const c_void = ptr::null();

    // SAFETY: CFDictionaryGetValueIfPresent is called with valid dictionary and key
    let success = unsafe { CFDictionaryGetValueIfPresent(dict, cf_key.as_ptr(), &mut value) };

    if success == 0 || value.is_null() {
        return None;
    }

    let mut raw: i64 = 0;
    // SAFETY: CFNumberGetValue is called with valid number reference and buffer
    let ok = unsafe {
        CFNumberGetValue(
            value as CFNumberRef,
            kCFNumberSInt64Type as CFNumberType,
            &mut raw as *mut _ as *mut c_void,
        )
    };

    if ok == 0 {
        None
    } else {
        Some(raw.max(0) as u64)
    }
}

/// Safe wrapper for CFString
struct CFString {
    ptr: CFStringRef,
}

impl CFString {
    fn new(value: &str) -> Option<Self> {
        let cstring = CString::new(value).ok()?;
        // SAFETY: CFStringCreateWithCString is called with valid C string and encoding
        let ptr = unsafe {
            CFStringCreateWithCString(
                ptr::null(),
                cstring.as_ptr(),
                kCFStringEncodingUTF8 as CFStringEncoding,
            )
        };

        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    fn as_ptr(&self) -> *const c_void {
        self.ptr as *const c_void
    }
}

impl Drop for CFString {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr is guaranteed to be valid from constructor
            unsafe { CFRelease(self.ptr as CFTypeRef) };
        }
    }
}

#[allow(non_camel_case_types)]
type io_object_t = mach_port_t;
#[allow(non_camel_case_types)]
type io_iterator_t = io_object_t;
#[allow(non_camel_case_types)]
type io_registry_entry_t = io_object_t;

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    unsafe fn IOServiceMatching(name: *const c_char) -> CFMutableDictionaryRef;
    unsafe fn IOServiceGetMatchingServices(
        master_port: mach_port_t,
        matching: CFMutableDictionaryRef,
        existing: *mut io_iterator_t,
    ) -> libc::kern_return_t;
    unsafe fn IOIteratorNext(iterator: io_iterator_t) -> io_object_t;
    unsafe fn IOObjectRelease(object: io_object_t) -> libc::kern_return_t;
    unsafe fn IORegistryEntryCreateCFProperties(
        entry: io_registry_entry_t,
        properties: *mut CFMutableDictionaryRef,
        allocator: CFAllocatorRef,
        options: u32,
    ) -> libc::kern_return_t;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    unsafe fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const c_char,
        encoding: CFStringEncoding,
    ) -> CFStringRef;
    unsafe fn CFDictionaryGetValueIfPresent(
        dict: CFDictionaryRef,
        key: *const c_void,
        value: *mut *const c_void,
    ) -> Boolean;
    unsafe fn CFNumberGetValue(
        number: CFNumberRef,
        the_type: CFNumberType,
        value_ptr: *mut c_void,
    ) -> Boolean;
}
