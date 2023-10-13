#![crate_type = "staticlib"]
#![allow(non_camel_case_types)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
// TODO(#333): Fix this clippy warning.
#![allow(clippy::arc_with_non_send_sync)]
#![cfg_attr(feature = "read_buf", feature(read_buf))]

//! This package contains bindings for using rustls via a C API. If
//! you're looking at this on docs.rs, [you may want the rustls docs
//! instead](https://docs.rs/rustls/latest/rustls/).
//!
//! Even though this is a C API, it is published on crates.io so other crates that
//! wrap a different C API (like curl) can depend on it.
//!
//! [You may also want to read the rustls-ffi README](https://github.com/rustls/rustls-ffi#rustls-ffi-bindings).

use crate::rslice::rustls_str;
use libc::c_void;
use std::cell::RefCell;
use std::mem;
use std::sync::Arc;

pub mod acceptor;
pub mod cipher;
pub mod client;
pub mod connection;
pub mod enums;
mod error;
pub mod io;
pub mod log;
mod panic;
pub mod rslice;
pub mod server;
pub mod session;

pub use error::rustls_result;
pub use error::*;

use crate::log::rustls_log_callback;
use crate::panic::PanicOrDefault;

// version.rs gets written at compile time by build.rs
include!(concat!(env!("OUT_DIR"), "/version.rs"));

// For C callbacks, we need to offer a `void *userdata` parameter, so the
// application can associate callbacks with particular pieces of state. We
// allow setting a userdata pointer on a per-session basis, but the rustls
// session objects don't offer a way to store a `c_void` attached to a session.
// So we use thread-locals. Before calling out to rustls code that may call
// a callback, we set USERDATA for the current thread to the userdata pointer
// for the current session. Before returning to the C caller, we restore
// USERDATA to its previous value. Because a C callback may call back into
// Rust code, we model these thread locals as a stack, so we can always
// restore the previous version.
thread_local! {
    pub(crate) static USERDATA: RefCell<Vec<Userdata>> = RefCell::new(Vec::new());
}

pub(crate) struct Userdata {
    userdata: *mut c_void,
    log_callback: rustls_log_callback,
}

/// UserdataGuard pops an entry off the USERDATA stack, restoring the
/// thread-local state to its value previous to the creation of the UserdataGuard.
/// Invariants: As long as a UserdataGuard is live:
///  - The stack of userdata items for this thread must have at least one item.
///  - The top item on that stack must be the one this guard was built with.
///  - The `data` field must not be None.
/// If any of these invariants fails, try_drop will return an error.
pub(crate) struct UserdataGuard {
    // Keep a copy of the data we expect to be popping off the stack. This allows
    // us to check for consistency, and also serves to make this type !Send:
    // https://doc.rust-lang.org/nightly/std/primitive.pointer.html#impl-Send-1
    data: Option<Userdata>,
}

impl UserdataGuard {
    fn new(u: *mut c_void) -> Self {
        UserdataGuard {
            data: Some(Userdata {
                userdata: u,
                log_callback: None,
            }),
        }
    }

    /// Even though we have a Drop impl on this guard, when possible it's
    /// best to call try_drop explicitly. That way any failures of internal
    /// variants can be signaled to the user immediately by returning
    /// rustls_result::Panic.
    fn try_drop(mut self) -> Result<(), UserdataError> {
        self.try_pop()
    }

    fn try_pop(&mut self) -> Result<(), UserdataError> {
        let expected_data = self
            .data
            .as_ref()
            .ok_or(UserdataError::AlreadyPopped)?
            .userdata;
        USERDATA
            .try_with(|userdata| {
                userdata.try_borrow_mut().map_or_else(
                    |_| Err(UserdataError::AlreadyBorrowed),
                    |mut v| {
                        let u = v.pop().ok_or(UserdataError::EmptyStack)?;
                        self.data = None;
                        if u.userdata == expected_data {
                            Ok(())
                        } else {
                            Err(UserdataError::WrongData)
                        }
                    },
                )
            })
            .unwrap_or(Err(UserdataError::AccessError))
    }
}

impl Drop for UserdataGuard {
    fn drop(&mut self) {
        self.try_pop().ok();
    }
}

#[derive(Clone, Debug)]
pub(crate) enum UserdataError {
    /// try_pop was called twice.
    AlreadyPopped,
    /// The RefCell is borrowed somewhere else.
    AlreadyBorrowed,
    /// The stack of userdata items was already empty.
    EmptyStack,
    /// The LocalKey was destroyed before this call.
    /// See <https://doc.rust-lang.org/std/thread/struct.LocalKey.html#method.try_with>
    AccessError,
    /// Unexpected pointer when popping.
    WrongData,
}

#[must_use = "If you drop the guard, userdata will be immediately cleared"]
pub(crate) fn userdata_push(
    u: *mut c_void,
    cb: rustls_log_callback,
) -> Result<UserdataGuard, UserdataError> {
    USERDATA
        .try_with(|userdata| {
            userdata.try_borrow_mut().map_or_else(
                |_| Err(UserdataError::AlreadyBorrowed),
                |mut v| {
                    v.push(Userdata {
                        userdata: u,
                        log_callback: cb,
                    });
                    Ok(())
                },
            )
        })
        .unwrap_or(Err(UserdataError::AccessError))?;
    Ok(UserdataGuard::new(u))
}

pub(crate) fn userdata_get() -> Result<*mut c_void, UserdataError> {
    USERDATA
        .try_with(|userdata| {
            userdata.try_borrow_mut().map_or_else(
                |_| Err(UserdataError::AlreadyBorrowed),
                |v| match v.last() {
                    Some(u) => Ok(u.userdata),
                    None => Err(UserdataError::EmptyStack),
                },
            )
        })
        .unwrap_or(Err(UserdataError::AccessError))
}

pub(crate) fn log_callback_get() -> Result<(rustls_log_callback, *mut c_void), UserdataError> {
    USERDATA
        .try_with(|userdata| {
            userdata.try_borrow_mut().map_or_else(
                |_| Err(UserdataError::AlreadyBorrowed),
                |v| match v.last() {
                    Some(u) => Ok((u.log_callback, u.userdata)),
                    None => Err(UserdataError::EmptyStack),
                },
            )
        })
        .unwrap_or(Err(UserdataError::AccessError))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn guard_try_pop() {
        let data = "hello";
        let data_ptr: *mut c_void = data as *const _ as _;
        let mut guard = userdata_push(data_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), data_ptr);
        guard.try_pop().unwrap();
        assert!(matches!(guard.try_pop(), Err(_)));
    }

    #[test]
    fn guard_try_drop() {
        let data = "hello";
        let data_ptr: *mut c_void = data as *const _ as _;
        let guard = userdata_push(data_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), data_ptr);
        guard.try_drop().unwrap();
        assert!(matches!(userdata_get(), Err(_)));
    }

    #[test]
    fn guard_drop() {
        let data = "hello";
        let data_ptr: *mut c_void = data as *const _ as _;
        {
            let _guard = userdata_push(data_ptr, None).unwrap();
            assert_eq!(userdata_get().unwrap(), data_ptr);
        }
        assert!(matches!(userdata_get(), Err(_)));
    }

    #[test]
    fn nested_guards() {
        let hello = "hello";
        let hello_ptr: *mut c_void = hello as *const _ as _;
        {
            let guard = userdata_push(hello_ptr, None).unwrap();
            assert_eq!(userdata_get().unwrap(), hello_ptr);
            {
                let yo = "yo";
                let yo_ptr: *mut c_void = yo as *const _ as _;
                let guard2 = userdata_push(yo_ptr, None).unwrap();
                assert_eq!(userdata_get().unwrap(), yo_ptr);
                guard2.try_drop().unwrap();
            }
            assert_eq!(userdata_get().unwrap(), hello_ptr);
            guard.try_drop().unwrap();
        }
        assert!(matches!(userdata_get(), Err(_)));
    }

    #[test]
    fn out_of_order_drop() {
        let hello = "hello";
        let hello_ptr: *mut c_void = hello as *const _ as _;
        let guard = userdata_push(hello_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), hello_ptr);

        let yo = "yo";
        let yo_ptr: *mut c_void = yo as *const _ as _;
        let guard2 = userdata_push(yo_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), yo_ptr);

        assert!(matches!(guard.try_drop(), Err(UserdataError::WrongData)));
        assert!(matches!(guard2.try_drop(), Err(UserdataError::WrongData)));
    }

    #[test]
    fn userdata_multi_threads() {
        let hello = "hello";
        let hello_ptr: *mut c_void = hello as *const _ as _;
        let guard = userdata_push(hello_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), hello_ptr);

        let thread1 = thread::spawn(|| {
            let yo = "yo";
            let yo_ptr: *mut c_void = yo as *const _ as _;
            let guard2 = userdata_push(yo_ptr, None).unwrap();
            assert_eq!(userdata_get().unwrap(), yo_ptr);

            let greetz = "greetz";
            let greetz_ptr: *mut c_void = greetz as *const _ as _;

            let guard3 = userdata_push(greetz_ptr, None).unwrap();

            assert_eq!(userdata_get().unwrap(), greetz_ptr);
            guard3.try_drop().unwrap();

            assert_eq!(userdata_get().unwrap(), yo_ptr);
            guard2.try_drop().unwrap();
        });

        assert_eq!(userdata_get().unwrap(), hello_ptr);
        guard.try_drop().unwrap();
        thread1.join().unwrap();
    }
}

pub(crate) struct BoxCastPtrMarker;

pub(crate) struct ArcCastPtrMarker;

trait CastSourceMarker {}

impl CastSourceMarker for BoxCastPtrMarker {}

impl CastSourceMarker for ArcCastPtrMarker {}

pub(crate) trait Castable {
    type CastSource: CastSourceMarker;
    type RustType;
}

pub(crate) fn cast_const_ptr<C>(ptr: *const C) -> *const C::RustType
where
    C: Castable,
{
    ptr as *const _
}

pub(crate) fn to_arc_const_ptr<C>(src: C::RustType) -> *const C
where
    C: Castable,
{
    Arc::into_raw(Arc::new(src)) as *const _
}

pub(crate) fn to_arc<C>(ptr: *const C) -> Option<Arc<C::RustType>>
where
    C: Castable<CastSource = ArcCastPtrMarker>,
{
    if ptr.is_null() {
        return None;
    }
    let rs_typed = cast_const_ptr::<C>(ptr);
    let r = unsafe { Arc::from_raw(rs_typed) };
    let val = Arc::clone(&r);
    mem::forget(r);
    Some(val)
}

pub(crate) fn to_box<C>(ptr: *mut C) -> Option<Box<C::RustType>>
where
    C: Castable<CastSource = BoxCastPtrMarker>,
{
    if ptr.is_null() {
        return None;
    }
    let rs_typed = cast_mut_ptr(ptr);
    unsafe { Some(Box::from_raw(rs_typed)) }
}

pub(crate) fn free_arc<C>(ptr: *const C)
where
    C: Castable<CastSource = ArcCastPtrMarker>,
{
    if ptr.is_null() {
        return;
    }
    let rs_typed = cast_const_ptr(ptr);
    drop(unsafe { Arc::from_raw(rs_typed) });
}

pub(crate) fn free_box<C>(ptr: *mut C)
where
    C: Castable<CastSource = BoxCastPtrMarker>,
{
    to_box(ptr);
}

pub(crate) fn cast_mut_ptr<C>(ptr: *mut C) -> *mut C::RustType
where
    C: Castable<CastSource = BoxCastPtrMarker>,
{
    ptr as *mut _
}

pub(crate) fn to_boxed_mut_ptr<C>(src: C::RustType) -> *mut C
where
    C: Castable<CastSource = BoxCastPtrMarker>,
{
    Box::into_raw(Box::new(src)) as *mut _
}

pub(crate) fn set_boxed_mut_ptr<C>(dst: *mut *mut C, src: C::RustType)
where
    C: Castable<CastSource = BoxCastPtrMarker>,
{
    unsafe {
        *dst = to_boxed_mut_ptr(src);
    }
}

/// Turn a raw mut pointer into a mutable reference.
pub(crate) fn try_from_mut<'a, C>(from: *mut C) -> Option<&'a mut C::RustType>
where
    C: Castable<CastSource = BoxCastPtrMarker>,
{
    unsafe { cast_mut_ptr(from).as_mut() }
}

#[doc(hidden)]
#[macro_export]
macro_rules! try_mut_from_ptr {
    ( $var:ident ) => {
        match $crate::try_from_mut($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) fn try_from<'a, C, CS>(from: *const C) -> Option<&'a C::RustType>
where
    C: Castable<CastSource = CS>,
{
    unsafe { cast_const_ptr(from).as_ref() }
}

#[doc(hidden)]
#[macro_export]
macro_rules! try_ref_from_ptr {
    ( $var:ident ) => {
        match $crate::try_from($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) fn try_arc_from<C>(from: *const C) -> Option<Arc<C::RustType>>
where
    C: Castable<CastSource = ArcCastPtrMarker>,
{
    to_arc(from)
}

#[doc(hidden)]
#[macro_export]
macro_rules! try_arc_from_ptr {
    ( $var:ident ) => {
        match $crate::try_arc_from($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) fn try_box_from<C>(from: *mut C) -> Option<Box<C::RustType>>
where
    C: Castable<CastSource = BoxCastPtrMarker>,
{
    to_box(from)
}

#[doc(hidden)]
#[macro_export]
macro_rules! try_box_from_ptr {
    ( $var:ident ) => {
        match $crate::try_box_from($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! try_slice {
    ( $ptr:expr, $count:expr ) => {
        if $ptr.is_null() {
            return $crate::panic::NullParameterOrDefault::value();
        } else {
            unsafe { slice::from_raw_parts($ptr, $count as usize) }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! try_mut_slice {
    ( $ptr:expr, $count:expr ) => {
        if $ptr.is_null() {
            return $crate::panic::NullParameterOrDefault::value();
        } else {
            unsafe { slice::from_raw_parts_mut($ptr, $count as usize) }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! try_callback {
    ( $var:ident ) => {
        match $var {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}
/// Returns a static string containing the rustls-ffi version as well as the
/// rustls version. The string is alive for the lifetime of the program and does
/// not need to be freed.
#[no_mangle]
pub extern "C" fn rustls_version() -> rustls_str<'static> {
    rustls_str::from_str_unchecked(RUSTLS_FFI_VERSION)
}

#[test]
fn test_rustls_version() {
    // very rough check that the version number is being interpolated into the
    // variable
    assert!(RUSTLS_FFI_VERSION.contains("/0."));
    let vsn = rustls_version();
    assert!(vsn.len > 4)
}
