use super::*;
use std::slice;

#[repr(C)]
pub struct ConfigFFI {
    enable_forward_secrecy: u8,
    enable_post_compromise_security: u8,
    max_skipped_messages: size_t,
    key_rotation_interval: u64,
    handshake_timeout: u64,
    message_buffer_size: size_t,
}

impl From<ConfigFFI> for crate::Config {
    fn from(config: ConfigFFI) -> Self {
        Self {
            enable_forward_secrecy: config.enable_forward_secrecy != 0,
            enable_post_compromise_security: config.enable_post_compromise_security != 0,
            max_skipped_messages: config.max_skipped_messages,
            key_rotation_interval: config.key_rotation_interval,
            handshake_timeout: config.handshake_timeout,
            message_buffer_size: config.message_buffer_size,
        }
    }
}

#[no_mangle]
pub extern "C" fn secure_context_create(
    config: *const ConfigFFI,
    password: *const uint8_t,
    password_len: size_t,
) -> *mut SecureContextHandle {
    let result = panic::catch_unwind(|| {
        let rs_config = if config.is_null() {
            crate::Config::default()
        } else {
            unsafe { crate::Config::from(ptr::read(config)) }
        };
        
        let password_slice = if password.is_null() || password_len == 0 {
            None
        } else {
            Some(unsafe { slice::from_raw_parts(password, password_len) })
        };
        
        match SecureContext::new(rs_config, password_slice) {
            Ok(ctx) => {
                let handle = Box::new(SecureContextHandle {
                    context: Box::into_raw(Box::new(ctx)),
                });
                Box::into_raw(handle)
            }
            Err(_) => ptr::null_mut(),
        }
    });
    
    result.unwrap_or(ptr::null_mut())
}


#[no_mangle]
pub extern "C" fn secure_context_free(handle: *mut SecureContextHandle) -> u8 {
    if handle.is_null() {
        return FFIError::NullPointer.into();
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
    FFIError::Success.into()
}

#[no_mangle]
pub extern "C" fn secure_context_load_identity(
    handle: *mut SecureContextHandle,
    ed_pub_ptr: *const u8,
    x_pub_ptr: *const u8,
    seed_ptr: *const u8,
) -> FFIError {
    let result = panic::catch_unwind(|| {
        if handle.is_null() || ed_pub_ptr.is_null() || x_pub_ptr.is_null() || seed_ptr.is_null() {
            return FFIError::NullPointer;
        }

        let ctx_handle = unsafe { &mut *handle };
        let ctx = unsafe { &mut *ctx_handle.context };
        let ed_slice = unsafe { std::slice::from_raw_parts(ed_pub_ptr, 32) };
        let x_slice = unsafe { std::slice::from_raw_parts(x_pub_ptr, 32) };
        let seed_slice = unsafe { std::slice::from_raw_parts(seed_ptr, 32) };

        match ctx.load_identity(ed_slice, x_slice, seed_slice) {
            Ok(_) => FFIError::Success,
            Err(e) => FFIError::from(e),
        }
    });

    result.unwrap_or(FFIError::Panic)
}


#[no_mangle]
pub extern "C" fn secure_session_create(
    context: *mut SecureContextHandle,
    peer_id: *const uint8_t,
    peer_id_len: size_t,
) -> *mut SecureSessionHandle {
    if context.is_null() || peer_id.is_null() {
        return ptr::null_mut();
    }
    
    let result = panic::catch_unwind(|| {
        unsafe {
            let ctx_handle = &*context;
            let ctx = &*ctx_handle.context;
            
            let peer_id_slice = slice::from_raw_parts(peer_id, peer_id_len);
            
            match ctx.create_session(peer_id_slice) {
                Ok(session_handle) => {
                    let session_arc = session_handle.session();
                    let raw_arc = std::sync::Arc::into_raw(session_arc);
                    
                    Box::into_raw(Box::new(SecureSessionHandle {
                        session: raw_arc as *mut DoubleRatchetSession,
                    }))
                }
                Err(_) => ptr::null_mut(),
            }
        }
    });
    
    result.unwrap_or(ptr::null_mut())
}
#[no_mangle]
pub extern "C" fn secure_context_perform_handshake(
    handle: *mut SecureContextHandle,
    peer_id: *const uint8_t,
    peer_id_len: size_t,
    initiator: u8,
    peer_ik: *const uint8_t,
    peer_spk: *const uint8_t,
    peer_opk: *const uint8_t,
    shared_secret: *mut *mut uint8_t,
    shared_secret_len: *mut size_t,
) -> FFIError {
    if handle.is_null() || peer_id.is_null() || shared_secret.is_null() || shared_secret_len.is_null() {
        return FFIError::NullPointer;
    }

    let result = panic::catch_unwind(|| {
        unsafe {
            let ctx_handle = &*handle;
            let ctx = &*ctx_handle.context;
            
            let peer_id_slice = slice::from_raw_parts(peer_id, peer_id_len);
            let ik_slice = if peer_ik.is_null() { None } else { Some(slice::from_raw_parts(peer_ik, 32)) };
            let spk_slice = if peer_spk.is_null() { None } else { Some(slice::from_raw_parts(peer_spk, 32)) };
            let opk_slice = if peer_opk.is_null() { None } else { Some(slice::from_raw_parts(peer_opk, 32)) };

            match ctx.perform_handshake(
                peer_id_slice,
                initiator != 0,
                ik_slice,
                spk_slice,
                opk_slice,
                None, // prologue
            ) {
                Ok(ss) => {
                    let mut boxed = ss.into_boxed_slice();
                    let len = boxed.len();
                    let ptr = boxed.as_mut_ptr();
                    
                    *shared_secret = ptr;
                    *shared_secret_len = len;
                    
                    std::mem::forget(boxed);
                    FFIError::Success
                }
                Err(e) => FFIError::from(e),
            }
        }
    });

    result.unwrap_or(FFIError::Panic)
}

#[no_mangle]
pub extern "C" fn secure_context_encrypt_message(
    handle: *mut SecureContextHandle,
    session_id: *const uint8_t,
    session_id_len: size_t,
    plaintext: *const uint8_t,
    plaintext_len: size_t,
    ciphertext: *mut *mut uint8_t,
    ciphertext_len: *mut size_t,
) -> FFIError {
    if handle.is_null() || session_id.is_null() || plaintext.is_null() || ciphertext.is_null() || ciphertext_len.is_null() {
        return FFIError::NullPointer;
    }

    let result = panic::catch_unwind(|| {
        unsafe {
            let ctx_handle = &*handle;
            let ctx = &*ctx_handle.context;

            let session_slice = slice::from_raw_parts(session_id, session_id_len);
            let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);

            match ctx.encrypt_message(session_slice, plaintext_slice, None) {
                Ok(encrypted) => {
                    let mut boxed = encrypted.into_boxed_slice();
                    let len = boxed.len();
                    let ptr = boxed.as_mut_ptr();
                    
                    *ciphertext = ptr;
                    *ciphertext_len = len;
                    
                    std::mem::forget(boxed);
                    FFIError::Success
                }
                Err(e) => FFIError::from(e),
            }
        }
    });

    result.unwrap_or(FFIError::Panic)
}

#[no_mangle]
pub extern "C" fn secure_context_decrypt_message(
    handle: *mut SecureContextHandle,
    session_id: *const uint8_t,
    session_id_len: size_t,
    ciphertext: *const uint8_t,
    ciphertext_len: size_t,
    plaintext: *mut *mut uint8_t,
    plaintext_len: *mut size_t,
) -> FFIError {
    if handle.is_null() || session_id.is_null() || ciphertext.is_null() || plaintext.is_null() || plaintext_len.is_null() {
        return FFIError::NullPointer;
    }

    let result = panic::catch_unwind(|| {
        unsafe {
            let ctx_handle = &*handle;
            let ctx = &*ctx_handle.context;

            let session_slice = slice::from_raw_parts(session_id, session_id_len);
            let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);

            match ctx.decrypt_message(session_slice, ciphertext_slice, None) {
                Ok(decrypted) => {
                    let mut boxed = decrypted.into_boxed_slice();
                    let len = boxed.len();
                    let ptr = boxed.as_mut_ptr();
                    
                    *plaintext = ptr;
                    *plaintext_len = len;
                    
                    std::mem::forget(boxed);
                    FFIError::Success
                }
                Err(e) => FFIError::from(e),
            }
        }
    });

    result.unwrap_or(FFIError::Panic)
}
