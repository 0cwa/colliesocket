//! Protected v4 import requests. A pairing invitation authorizes a new receiver.
use crate::{
    config,
    enrollment::{self, Error},
    push,
    push_store::{self, EnrollmentResult, PushStore, Subscription},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiverEnrollment {
    pub enrollment_version: u32,
    pub request_id: String,
    pub import_seq: u64,
    pub account_id: String,
    pub device_id: u32,
    pub receiver_id: String,
    #[serde(
        default,
        deserialize_with = "push_store::present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub label: Option<String>,
    #[serde(
        default,
        deserialize_with = "push_store::present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<String>,
    pub control_key: String,
    pub subscription: Subscription,
}

pub(crate) fn valid_label(label: &str) -> bool {
    (1..=64).contains(&label.len()) && label.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

impl ReceiverEnrollment {
    pub fn validate(&self) -> push_store::Result<()> {
        use push_store::{canonical_uuid, StoreError, MAX_IMPORT_SEQUENCE};

        if self.enrollment_version != 4 || self.subscription.event_version() != 4 {
            return Err(StoreError::UnsupportedVersion);
        }
        if !canonical_uuid(&self.account_id, false)
            || !canonical_uuid(&self.request_id, true)
            || !canonical_uuid(&self.receiver_id, true)
            || !(1..=MAX_IMPORT_SEQUENCE).contains(&self.import_seq)
            || !(2..=2_147_483_647).contains(&self.device_id)
            || self
                .label
                .as_deref()
                .is_some_and(|label| !valid_label(label))
            || self.password.as_ref().is_some_and(|password| {
                !(16..=256).contains(&password.len())
                    || !password.bytes().all(|b| (0x20..=0x7e).contains(&b))
            })
        {
            return Err(StoreError::InvalidEnrollment);
        }
        push_store::key_bytes(&self.control_key, 32)?;
        self.subscription.validate()
    }

    pub fn parse(bytes: &[u8], bridge: bool) -> Result<Self, Error> {
        if bytes.len() as u64 > enrollment::MAX_IMPORT_BYTES {
            return Err(Error("input_too_large"));
        }
        let shape: Value = serde_json::from_slice(bytes).map_err(|_| Error("invalid_json"))?;
        if !shape.get("subscription").is_some_and(Value::is_object) {
            return Err(Error("invalid_enrollment"));
        }
        let enrollment: Self = enrollment::decode(bytes)?;
        enrollment.validate().map_err(|error| Error(error.code()))?;
        if bridge != enrollment.password.is_some() {
            return Err(Error("invalid_enrollment"));
        }
        Ok(enrollment)
    }

    pub fn response(&self, result: EnrollmentResult) -> Value {
        json!({
            "enrollment_version": 4,
            "selected_event_version": 4,
            "request_id": self.request_id,
            "receiver_id": self.receiver_id,
            "instance": self.subscription.instance,
            "subscription_epoch": result.subscription_epoch,
            "capabilities": ["wake", "test", "status"],
            "status": "accepted",
            "replayed": result.replayed,
        })
    }
}

pub(crate) async fn import(bytes: &[u8]) -> Result<Value, Error> {
    let enrollment = ReceiverEnrollment::parse(bytes, true)?;
    enrollment::authorize_account_id(&enrollment.account_id)?;
    let mut store = PushStore::open(config::get_db()).map_err(|error| Error(error.code()))?;
    let receipt = match store
        .receiver_receipt(&enrollment)
        .map_err(|error| Error(error.code()))?
    {
        Some(receipt) => receipt,
        None => {
            enrollment::authorize_endpoint(&enrollment.subscription.endpoint).await?;
            store
                .enroll_receiver(&enrollment, push::now())
                .map_err(|error| Error(error.code()))?
        }
    };
    Ok(enrollment.response(receipt))
}
