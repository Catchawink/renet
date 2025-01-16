//! Renetcode is a simple connection based client/server protocol agnostic to the transport layer,
//! was developed be used in games with UDP in mind. Implements the Netcode 1.02 standard, available
//! [here][standard] and the original implementation in C++ is available in the [netcode][netcode]
//! repository.
//!
//! Has the following feature:
//! - Encrypted and signed packets
//! - Secure client connection with connect tokens
//! - Connection based protocol
//!
//! and protects the game server from the following attacks:
//! - Zombie clients
//! - Man in the middle
//! - DDoS amplification
//! - Packet replay attacks
//!
//! [standard]: https://github.com/networkprotocol/netcode/blob/master/STANDARD.md
//! [netcode]: https://github.com/networkprotocol/netcode
mod client;
mod crypto;
mod error;
mod packet;
mod replay_protection;
mod serialize;
#[cfg(not(feature = "static_alloc"))]
mod server;
mod token;

pub use client::{ClientAuthentication, DisconnectReason, NetcodeClient};
pub use crypto::generate_random_bytes;
pub use error::NetcodeError;
use octets::Octets;
#[cfg(not(feature = "static_alloc"))]
pub use server::{NetcodeServer, ServerAuthentication, ServerConfig, ServerResult};
pub use token::{ConnectToken, TokenGenerationError};

use std::time::Duration;

const NETCODE_VERSION_INFO: &[u8; 13] = b"NETCODE 1.02\0";
const NETCODE_MAX_CLIENTS: usize = 1024;
const NETCODE_MAX_PENDING_CLIENTS: usize = NETCODE_MAX_CLIENTS * 4;

const NETCODE_ADDRESS_NONE: u8 = 0;
const NETCODE_ADDRESS_IPV4: u8 = 1;
const NETCODE_ADDRESS_IPV6: u8 = 2;
#[cfg(target_arch = "xtensa")]
const NETCODE_CONNECT_TOKEN_PRIVATE_BYTES: usize = 1024;
#[cfg(not(target_arch = "xtensa"))]
const NETCODE_CONNECT_TOKEN_PRIVATE_BYTES: usize = 1024;
/// The maximum number of bytes that a netcode packet can contain.
#[cfg(target_arch = "xtensa")]
pub const NETCODE_MAX_PACKET_BYTES: usize = 1400;
#[cfg(not(target_arch = "xtensa"))]
pub const NETCODE_MAX_PACKET_BYTES: usize = 1400;
/// The maximum number of bytes that a payload can have when generating a payload packet.
pub const NETCODE_MAX_PAYLOAD_BYTES: usize = 1300;

/// The number of bytes in a private key;
pub const NETCODE_KEY_BYTES: usize = 32;
const NETCODE_MAC_BYTES: usize = 16;
/// The number of bytes that an user data can contain in the ConnectToken.
#[cfg(target_arch = "xtensa")]
pub const NETCODE_USER_DATA_BYTES: usize = 256;
#[cfg(not(target_arch = "xtensa"))]
pub const NETCODE_USER_DATA_BYTES: usize = 256;
#[cfg(target_arch = "xtensa")]
const NETCODE_CHALLENGE_TOKEN_BYTES: usize = 300;
#[cfg(not(target_arch = "xtensa"))]
const NETCODE_CHALLENGE_TOKEN_BYTES: usize = 300;
#[cfg(target_arch = "xtensa")]
const NETCODE_CONNECT_TOKEN_XNONCE_BYTES: usize = 24;
#[cfg(not(target_arch = "xtensa"))]
const NETCODE_CONNECT_TOKEN_XNONCE_BYTES: usize = 24;

const NETCODE_ADDITIONAL_DATA_SIZE: usize = 13 + 8 + 8;
const NETCODE_SEND_RATE: Duration = Duration::from_millis(250);

#[cfg(target_arch = "xtensa")]
pub const SERVER_ADDRESSES_COUNT: usize = 16;
#[cfg(not(target_arch = "xtensa"))]
pub const SERVER_ADDRESSES_COUNT: usize = 16;

#[cfg(feature = "static_alloc")]
use esp_idf_svc::sys::*;

#[cfg(feature = "static_alloc")]
pub fn allocate_psram_u8_slice(size: usize) -> &'static mut [u8] {
    use std::slice;

    unsafe {
        // Allocate memory with MALLOC_CAP_SPIRAM capability
        let ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM) as *mut u8;
        if ptr.is_null() {
            //None // Allocation failed
            panic!("Failed to allocate u8 array!")
        } else {
            // Convert the raw pointer into a mutable slice
            slice::from_raw_parts_mut(ptr, size)
        }
    }
}

pub trait ToVecFlexible {
    fn to_vec_flexible(&self) -> Vec<u8>;
}

impl ToVecFlexible for [u8] {
	#[cfg(feature = "static_alloc")]
    fn to_vec_flexible(&self) -> Vec<u8> {
        let len = self.len();

        // Allocate memory in PSRAM
        let psram_ptr = unsafe {
            heap_caps_malloc(len, MALLOC_CAP_SPIRAM as u32) as *mut u8
        };

        if psram_ptr.is_null() {
        	panic!("Failed to allocate memory in PSRAM")
        }

        // Copy data from the slice into PSRAM
        unsafe {
            std::ptr::copy_nonoverlapping(self.as_ptr(), psram_ptr, len);
        }

        // Convert the allocated memory into a Vec<u8>
        unsafe { Vec::from_raw_parts(psram_ptr, len, len) }
    }

	#[cfg(not(feature = "static_alloc"))]
	fn to_vec_flexible(&self) -> Vec<u8> {
		self.to_vec()
	}
}

impl ToVecFlexible for Octets<'_> {
	
	#[cfg(feature = "static_alloc")]
    fn to_vec_flexible(&self) -> Vec<u8> {
        let len = self.len();

        // Allocate memory in PSRAM
        let psram_ptr = unsafe {
            heap_caps_malloc(len, MALLOC_CAP_SPIRAM as u32) as *mut u8
        };

        if psram_ptr.is_null() {
            panic!("Failed to allocate memory in PSRAM")
        }

        // Copy data from the slice into PSRAM
        unsafe {
            std::ptr::copy_nonoverlapping(self.buf().as_ptr(), psram_ptr, len);
        }

        // Convert the allocated memory into a Vec<u8>
        unsafe { Vec::from_raw_parts(psram_ptr, len, len) }
    }

	#[cfg(not(feature = "static_alloc"))]
	fn to_vec_flexible(&self) -> Vec<u8> {
		self.to_vec()
	}
}