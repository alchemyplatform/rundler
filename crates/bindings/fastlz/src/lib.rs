// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

//! Raw FastLZ FFI bindings

// Credit to https://github.com/mvertescher/fastlz-rs/blob/master/src/lib.rs

use core::ffi::c_void;

// This is a generated binding of the fastlz C library at commit
// 344eb4025f9ae866ebf7a2ec48850f7113a97a42 as required by the fastlz implementation by
// solady's LibZip.sol here: https://github.com/Vectorized/solady/blob/8b0601e1573ed17a583fdab2b2ebfb895507ec15/src/utils/LibZip.sol#L19
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Compress a block of data in the input buffer and returns the size of
/// compressed block. The size of input buffer is specified by length. The
/// minimum input buffer size is 16.
///
/// The output buffer must be at least 5% larger than the input buffer
/// and can not be smaller than 66 bytes.
///
/// If the input is not compressible, the return value might be larger than
/// length (input buffer size).
///
/// The input buffer and the output buffer can not overlap.
///
/// MODIFICATION: Always use level 1 compression to match LibZip.sol
///
/// Original credit to https://github.com/mvertescher/fastlz-rs/blob/master/src/lib.rs
pub fn compress<'a>(input: &[u8], output: &'a mut [u8]) -> &'a mut [u8] {
    let in_ptr: *const c_void = input as *const _ as *const c_void;
    let out_ptr: *mut c_void = output as *mut _ as *mut c_void;
    let size = unsafe { fastlz_compress_level(1, in_ptr, input.len() as i32, out_ptr) };
    if size as usize > output.len() {
        panic!("Output buffer overflow!");
    }

    let ret: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(out_ptr as *mut _, size as usize) };
    ret
}
