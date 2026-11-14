/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use crate::ffi::*;

    macro_rules! offset_of {
        ($ty:ty, $field:ident) => {{
            let val = std::mem::MaybeUninit::<$ty>::uninit();
            let base = val.as_ptr() as *const u8;
            let field = unsafe { std::ptr::addr_of!((*val.as_ptr()).$field) as *const u8 };
            unsafe { field.offset_from(base) as usize }
        }};
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_struct_sizes_and_offsets_64() {
        // FwpByteBlob
        assert_eq!(size_of::<FwpByteBlob>(), 16);
        assert_eq!(offset_of!(FwpByteBlob, data), 8);

        // FwpmDisplayData0
        assert_eq!(size_of::<FwpmDisplayData0>(), 16);
        assert_eq!(offset_of!(FwpmDisplayData0, description), 8);

        // FwpmAction0
        assert_eq!(size_of::<FwpmAction0>(), 20);
        assert_eq!(offset_of!(FwpmAction0, filter_type), 4);

        // FwpValue0 / FwpConditionValue0
        assert_eq!(size_of::<FwpValue0>(), 16);
        assert_eq!(offset_of!(FwpValue0, value), 8);

        // FwpV4AddrAndMask
        assert_eq!(size_of::<FwpV4AddrAndMask>(), 8);
        assert_eq!(offset_of!(FwpV4AddrAndMask, mask), 4);

        // FwpV6AddrAndMask
        assert_eq!(offset_of!(FwpV6AddrAndMask, prefix_length), 16);

        // FwpmFilterCondition0
        assert_eq!(size_of::<FwpmFilterCondition0>(), 40);
        assert_eq!(offset_of!(FwpmFilterCondition0, match_type), 16);
        assert_eq!(offset_of!(FwpmFilterCondition0, condition_value), 24);

        // FwpmFilter0
        assert_eq!(size_of::<FwpmFilter0>(), 200);
        assert_eq!(offset_of!(FwpmFilter0, display_data), 16);
        assert_eq!(offset_of!(FwpmFilter0, flags), 32);
        assert_eq!(offset_of!(FwpmFilter0, provider_key), 40);
        assert_eq!(offset_of!(FwpmFilter0, provider_data), 48);
        assert_eq!(offset_of!(FwpmFilter0, layer_key), 64);
        assert_eq!(offset_of!(FwpmFilter0, sub_layer_key), 80);
        assert_eq!(offset_of!(FwpmFilter0, weight), 96);
        assert_eq!(offset_of!(FwpmFilter0, num_filter_conditions), 112);
        assert_eq!(offset_of!(FwpmFilter0, filter_condition), 120);
        assert_eq!(offset_of!(FwpmFilter0, action), 128);
        assert_eq!(offset_of!(FwpmFilter0, provider_context_key), 152);
        assert_eq!(offset_of!(FwpmFilter0, reserved), 168);
        assert_eq!(offset_of!(FwpmFilter0, filter_id), 176);
        assert_eq!(offset_of!(FwpmFilter0, effective_weight), 184);

        // FwpmProvider0
        assert_eq!(size_of::<FwpmProvider0>(), 64);
        assert_eq!(offset_of!(FwpmProvider0, display_data), 16);
        assert_eq!(offset_of!(FwpmProvider0, flags), 32);
        assert_eq!(offset_of!(FwpmProvider0, provider_data), 40);
        assert_eq!(offset_of!(FwpmProvider0, service_name), 56);

        // FwpmSession0
        assert_eq!(size_of::<FwpmSession0>(), 72);
        assert_eq!(offset_of!(FwpmSession0, display_data), 16);
        assert_eq!(offset_of!(FwpmSession0, flags), 32);
        assert_eq!(offset_of!(FwpmSession0, txn_wait_timeout_in_msec), 36);
        assert_eq!(offset_of!(FwpmSession0, process_id), 40);
        assert_eq!(offset_of!(FwpmSession0, sid), 48);
        assert_eq!(offset_of!(FwpmSession0, username), 56);
        assert_eq!(offset_of!(FwpmSession0, kernel_mode), 64);

        // FwpmSublayer0
        assert_eq!(size_of::<FwpmSublayer0>(), 72);
        assert_eq!(offset_of!(FwpmSublayer0, display_data), 16);
        assert_eq!(offset_of!(FwpmSublayer0, flags), 32);
        assert_eq!(offset_of!(FwpmSublayer0, provider_key), 40);
        assert_eq!(offset_of!(FwpmSublayer0, provider_data), 48);
        assert_eq!(offset_of!(FwpmSublayer0, weight), 64);
    }
}
