//! The helper's TPM operations (spec §5, "TPM, via aleph-tpmd").
//!
//! - **Parent:** new objects are sealed under aleph's own primary (ECC
//!   P-256, AES-256-CFB, `noDA`), re-created from a fixed template on each
//!   use, whose Name is therefore stable per TPM. When `ownerAuth` is set
//!   that is impossible, and the persistent TCG SRK at `0x81000001` is used
//!   instead. The parent's Name is recorded at seal time. To unseal, the
//!   helper uses whichever available parent has that Name (so an SRK slot
//!   keeps working if `ownerAuth` is cleared later), and fails with
//!   `ParentMismatch` if none does: a different TPM, or an interposer
//!   substituting a key. The Name compared is the one ESYS itself holds for
//!   the handle (`Esys_TR_GetName`), i.e. the key that will salt the
//!   session.
//! - **Sealed object:** a keyed hash holding `be32(uid) ‖ KEK`, authorized
//!   by `HKDF(secret, salt = auth_salt, info = "aleph tpm auth v1" ‖
//!   be32(uid))`. Unseal returns the KEK only to the uid it was sealed for.
//! - **Sessions:** HMAC sessions salted to the verified parent, with
//!   AES-256-CFB parameter encryption both ways. Every transient handle and
//!   session is flushed on success and on error.

use std::str::FromStr;

use aleph_tpm_proto::{Parent, SealedObject, Status};
use hkdf::Hkdf;
use sha2::Sha256;
use tss_esapi::Context;
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::{CapabilityType, PropertyTag};
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, CapabilityData, EccPoint, KeyedHashScheme, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use zeroize::Zeroizing;

/// The TCTI used when neither `ALEPH_TCTI` nor `TPM2TOOLS_TCTI` is set.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";
/// Where the TCG provisioning guidance puts the storage root key.
pub const SRK_HANDLE: u32 = 0x8100_0001;

const AUTH_INFO: &[u8] = b"aleph tpm auth v1";
const AUTH_SALT_LEN: usize = 16;
const KEK_LEN: usize = 32;
// TPMA_PERMANENT bits (TPM 2.0 Part 2, 8.6).
const PERMANENT_OWNER_AUTH_SET: u32 = 1 << 0;
const PERMANENT_LOCKOUT_AUTH_SET: u32 = 1 << 2;
const PERMANENT_IN_LOCKOUT: u32 = 1 << 9;

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("cannot open the TPM: {0}")]
    Unavailable(String),
    #[error("the TPM rejected the password")]
    AuthFailed,
    #[error("the TPM is in dictionary-attack lockout")]
    Lockout,
    #[error("sealed for another user")]
    WrongUser,
    #[error("parent key Name does not match the slot")]
    ParentMismatch,
    #[error("no usable parent key")]
    NoParent,
    #[error("malformed sealed object: {0}")]
    Malformed(String),
    #[error("TPM error: {0}")]
    Tpm(String),
}

pub type Result<T> = std::result::Result<T, TpmError>;

/// An open connection to a TPM.
pub struct Tpm {
    ctx: Context,
}

/// A parent key in use for one operation.
struct ParentKey {
    handle: KeyHandle,
    name: Vec<u8>,
    /// Transient (aleph's primary) keys are flushed; the persistent SRK is not.
    transient: bool,
}

impl Tpm {
    /// Connect using a TCTI string such as `device:/dev/tpmrm0` or
    /// `swtpm:host=127.0.0.1,port=2321`.
    pub fn open(tcti: &str) -> Result<Self> {
        let conf =
            TctiNameConf::from_str(tcti).map_err(|e| TpmError::Unavailable(e.to_string()))?;
        Ok(Self {
            ctx: Context::new(conf).map_err(|e| TpmError::Unavailable(e.to_string()))?,
        })
    }

    /// Connect using `ALEPH_TCTI`, then `TPM2TOOLS_TCTI`, then
    /// [`DEFAULT_TCTI`].
    pub fn open_default() -> Result<Self> {
        let tcti = std::env::var("ALEPH_TCTI")
            .or_else(|_| std::env::var("TPM2TOOLS_TCTI"))
            .unwrap_or_else(|_| DEFAULT_TCTI.to_string());
        Self::open(&tcti)
    }

    /// Generate a fresh KEK and seal it for `uid` under `secret`.
    pub fn seal(
        &mut self,
        uid: u32,
        secret: &[u8],
    ) -> Result<(SealedObject, Zeroizing<[u8; KEK_LEN]>)> {
        self.seal_inner(uid, uid, secret)
    }

    /// Test hook: seal with the auth value for `auth_uid` but the payload
    /// naming `payload_uid`, so the payload check is testable on its own.
    #[cfg(feature = "testing")]
    pub fn seal_with_payload_uid(
        &mut self,
        auth_uid: u32,
        payload_uid: u32,
        secret: &[u8],
    ) -> Result<(SealedObject, Zeroizing<[u8; KEK_LEN]>)> {
        self.seal_inner(auth_uid, payload_uid, secret)
    }

    fn seal_inner(
        &mut self,
        uid: u32,
        payload_uid: u32,
        secret: &[u8],
    ) -> Result<(SealedObject, Zeroizing<[u8; KEK_LEN]>)> {
        let mut kek = Zeroizing::new([0u8; KEK_LEN]);
        getrandom::fill(kek.as_mut()).map_err(|e| TpmError::Tpm(e.to_string()))?;
        let mut auth_salt = [0u8; AUTH_SALT_LEN];
        getrandom::fill(&mut auth_salt).map_err(|e| TpmError::Tpm(e.to_string()))?;
        let mut payload = Zeroizing::new(Vec::with_capacity(4 + KEK_LEN));
        payload.extend_from_slice(&payload_uid.to_be_bytes());
        payload.extend_from_slice(kek.as_slice());
        let data = SensitiveData::try_from(payload.to_vec()).map_err(tpm_err)?;
        let auth = auth_value(secret, &auth_salt, uid)?;
        let (public, private, srk_name) = self.with_parent(None, |ctx, parent, session| {
            let created = ctx
                .execute_with_session(Some(session), |ctx| {
                    ctx.create(
                        parent.handle,
                        sealed_template()?,
                        Some(auth),
                        Some(data),
                        None,
                        None,
                    )
                })
                .map_err(map_tss)?;
            Ok((created.out_public, created.out_private, parent.name.clone()))
        })?;
        Ok((
            SealedObject {
                public: public.marshall().map_err(tpm_err)?,
                private: private.value().to_vec(),
                auth_salt: auth_salt.to_vec(),
                srk_name,
            },
            kek,
        ))
    }

    /// Unseal a KEK sealed for `uid`.
    pub fn unseal(
        &mut self,
        uid: u32,
        object: &SealedObject,
        secret: &[u8],
    ) -> Result<Zeroizing<[u8; KEK_LEN]>> {
        let public =
            Public::unmarshall(&object.public).map_err(|e| TpmError::Malformed(e.to_string()))?;
        let private = Private::try_from(object.private.clone())
            .map_err(|e| TpmError::Malformed(e.to_string()))?;
        let auth_salt: [u8; AUTH_SALT_LEN] = object
            .auth_salt
            .as_slice()
            .try_into()
            .map_err(|_| TpmError::Malformed("auth_salt must be 16 bytes".into()))?;
        let auth = auth_value(secret, &auth_salt, uid)?;
        let data = self.with_parent(Some(&object.srk_name), |ctx, parent, session| {
            let loaded = ctx
                .execute_with_session(Some(session), |ctx| {
                    ctx.load(parent.handle, private, public)
                })
                .map_err(map_tss)?;
            let result = ctx
                .tr_set_auth(loaded.into(), auth)
                .map_err(map_tss)
                .and_then(|()| {
                    ctx.execute_with_session(Some(session), |ctx| ctx.unseal(loaded.into()))
                        .map_err(map_tss)
                });
            let _ = ctx.flush_context(loaded.into());
            result
        })?;
        let bytes = Zeroizing::new(data.value().to_vec());
        if bytes.len() != 4 + KEK_LEN {
            return Err(TpmError::Malformed(
                "sealed payload has the wrong length".into(),
            ));
        }
        if bytes[..4] != uid.to_be_bytes() {
            return Err(TpmError::WrongUser);
        }
        let mut kek = Zeroizing::new([0u8; KEK_LEN]);
        kek.copy_from_slice(&bytes[4..]);
        Ok(kek)
    }

    /// TPM state for `alephctl setup` (spec §5).
    pub fn status(&mut self) -> Result<Status> {
        let prop = |ctx: &mut Context, tag| property(ctx, tag);
        let permanent = prop(&mut self.ctx, PropertyTag::Permanent)?;
        let parent = match self.seal_parent() {
            Ok(p) => {
                let kind = if p.transient {
                    Parent::AlephPrimary
                } else {
                    Parent::PersistentSrk
                };
                self.release(p);
                kind
            }
            Err(TpmError::NoParent) => Parent::Unavailable,
            Err(e) => return Err(e),
        };
        let max_tries = prop(&mut self.ctx, PropertyTag::MaxAuthFail)?;
        let failed_tries = prop(&mut self.ctx, PropertyTag::LockoutCounter)?;
        Ok(Status {
            parent,
            owner_auth_set: permanent & PERMANENT_OWNER_AUTH_SET != 0,
            lockout_auth_set: permanent & PERMANENT_LOCKOUT_AUTH_SET != 0,
            // Not every TPM (swtpm, for one) sets the inLockout bit; the
            // counter reaching the maximum is the definition, and a maximum
            // of zero locks DA-protected authorization permanently.
            in_lockout: permanent & PERMANENT_IN_LOCKOUT != 0 || failed_tries >= max_tries,
            max_tries,
            recovery_time: prop(&mut self.ctx, PropertyTag::LockoutInterval)?,
            lockout_recovery: prop(&mut self.ctx, PropertyTag::LockoutRecovery)?,
            failed_tries,
        })
    }

    /// `(failed_tries, max_tries, recovery_time)`: the dictionary-attack
    /// counters the helper budgets against.
    pub fn da_counters(&mut self) -> Result<(u32, u32, u32)> {
        Ok((
            property(&mut self.ctx, PropertyTag::LockoutCounter)?,
            property(&mut self.ctx, PropertyTag::MaxAuthFail)?,
            property(&mut self.ctx, PropertyTag::LockoutInterval)?,
        ))
    }

    fn owner_auth_set(&mut self) -> Result<bool> {
        Ok(property(&mut self.ctx, PropertyTag::Permanent)? & PERMANENT_OWNER_AUTH_SET != 0)
    }

    /// aleph's own primary (possible only while `ownerAuth` is empty).
    fn aleph_primary(&mut self) -> Result<ParentKey> {
        let handle = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Owner,
                    primary_template()?,
                    None,
                    None,
                    None,
                    None,
                )
            })
            // Not map_tss: a BadAuth here means ownerAuth was set a moment
            // ago, which says nothing about the caller's password.
            .map_err(tpm_err)?
            .key_handle;
        self.named(handle, true)
    }

    /// The persistent SRK, if provisioned.
    fn persistent_srk(&mut self) -> Result<ParentKey> {
        let handle = PersistentTpmHandle::new(SRK_HANDLE).map_err(tpm_err)?;
        let object = self
            .ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(handle)))
            .map_err(|_| TpmError::NoParent)?;
        self.named(KeyHandle::from(object), false)
    }

    /// Wrap `handle` with the Name ESYS holds for it: the key that will
    /// salt sessions, whatever a later ReadPublic might claim.
    fn named(&mut self, handle: KeyHandle, transient: bool) -> Result<ParentKey> {
        match self.ctx.tr_get_name(handle.into()) {
            Ok(name) => Ok(ParentKey {
                handle,
                name: name.value().to_vec(),
                transient,
            }),
            Err(e) => {
                if transient {
                    let _ = self.ctx.flush_context(handle.into());
                }
                Err(map_tss(e))
            }
        }
    }

    /// The parent new objects are sealed under: aleph's primary unless
    /// `ownerAuth` is set, then the persistent SRK if present.
    fn seal_parent(&mut self) -> Result<ParentKey> {
        if self.owner_auth_set()? {
            self.persistent_srk()
        } else {
            self.aleph_primary()
        }
    }

    /// The available parent whose Name is `expected`, else
    /// `ParentMismatch`.
    fn parent_named(&mut self, expected: &[u8]) -> Result<ParentKey> {
        let owner_auth = self.owner_auth_set()?;
        if !owner_auth {
            let primary = self.aleph_primary()?;
            if primary.name == expected {
                return Ok(primary);
            }
            self.release(primary);
        }
        match self.persistent_srk() {
            Ok(srk) if srk.name == expected => Ok(srk),
            Ok(srk) => {
                self.release(srk);
                Err(TpmError::ParentMismatch)
            }
            // With ownerAuth set and no SRK there is no parent at all.
            Err(_) if owner_auth => Err(TpmError::NoParent),
            Err(_) => Err(TpmError::ParentMismatch),
        }
    }

    fn release(&mut self, parent: ParentKey) {
        if parent.transient {
            let _ = self.ctx.flush_context(parent.handle.into());
        }
    }

    /// Get the parent (the one named `expected`, or the seal parent), open a
    /// salted parameter-encrypting session bound to it, run `f`, and flush
    /// everything transient.
    fn with_parent<T>(
        &mut self,
        expected: Option<&[u8]>,
        f: impl FnOnce(&mut Context, &ParentKey, AuthSession) -> Result<T>,
    ) -> Result<T> {
        let parent = match expected {
            Some(name) => self.parent_named(name)?,
            None => self.seal_parent()?,
        };
        let result = start_session(&mut self.ctx, parent.handle).and_then(|session| {
            let out = f(&mut self.ctx, &parent, session);
            flush_session(&mut self.ctx, session);
            out
        });
        self.release(parent);
        result
    }
}

/// `HKDF-SHA-256(secret, salt = auth_salt, info = "aleph tpm auth v1" ‖ be32(uid))`.
fn auth_value(secret: &[u8], salt: &[u8; AUTH_SALT_LEN], uid: u32) -> Result<Auth> {
    let mut info = AUTH_INFO.to_vec();
    info.extend_from_slice(&uid.to_be_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(&info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 length");
    Auth::try_from(okm.to_vec()).map_err(tpm_err)
}

/// A TPM property, read fresh (0 if the TPM does not report it).
/// `Context::get_tpm_property` caches every value forever, which is wrong
/// for a long-lived helper: the DA counter and `ownerAuth` change.
fn property(ctx: &mut Context, tag: PropertyTag) -> Result<u32> {
    let (data, _) = ctx
        .execute_without_session(|ctx| {
            ctx.get_capability(CapabilityType::TpmProperties, tag.into(), 1)
        })
        .map_err(map_tss)?;
    let CapabilityData::TpmProperties(props) = data else {
        return Err(TpmError::Tpm("unexpected capability data".into()));
    };
    Ok(props
        .into_iter()
        .find(|p| p.property() == tag)
        .map_or(0, |p| p.value()))
}

/// ECC P-256 restricted decryption key protecting children with
/// AES-256-CFB. `noDA` (as in the TCG SRK template): using the parent
/// itself needs no secret, so it should keep working during lockout; the
/// sealed objects under it remain DA-protected.
fn primary_template() -> tss_esapi::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_256_CFB,
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// Keyed-hash sealed data object authorized by its auth value, with
/// dictionary-attack protection on.
fn sealed_template() -> tss_esapi::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
}

fn start_session(ctx: &mut Context, parent: KeyHandle) -> Result<AuthSession> {
    let session = ctx
        .execute_without_session(|ctx| {
            ctx.start_auth_session(
                Some(parent),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
        })
        .map_err(map_tss)?
        .ok_or_else(|| TpmError::Tpm("no session returned".into()))?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    if let Err(e) = ctx.tr_sess_set_attributes(session, attrs, mask) {
        flush_session(ctx, session);
        return Err(map_tss(e));
    }
    Ok(session)
}

fn flush_session(ctx: &mut Context, session: AuthSession) {
    if session != AuthSession::Password {
        let _ = ctx.flush_context(ObjectHandle::from(SessionHandle::from(session)));
    }
}

fn map_tss(e: tss_esapi::Error) -> TpmError {
    if let tss_esapi::Error::Tss2Error(rc) = e {
        match rc.kind() {
            Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => {
                return TpmError::AuthFailed;
            }
            Some(Tss2ResponseCodeKind::Lockout) => return TpmError::Lockout,
            _ => {}
        }
    }
    tpm_err(e)
}

fn tpm_err(e: impl std::fmt::Display) -> TpmError {
    TpmError::Tpm(e.to_string())
}
