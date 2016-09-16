use std::collections::HashMap;
use std::io::Read;

use hyper::{self, header, Client};
use hyper::client::response::Response;
use rustc_serialize::{json, Decodable, Decoder};

use client::error::{Error, Result};

use std::time::Duration;
use chrono::{DateTime, FixedOffset, NaiveDateTime};

/// Errors
pub mod error;

/// Lease duration
///
/// Note: value returned from vault api is assumed to be in seconds
#[derive(Debug)]
pub struct VaultDuration(pub Duration);

impl Decodable for VaultDuration {
    fn decode<D: Decoder>(d: &mut D) -> ::std::result::Result<VaultDuration, D::Error> {
        let num = try!(d.read_u64());
        Ok(VaultDuration(Duration::from_secs(num)))
    }
}

/// Used for vault responses that return seconds since unix epoch
/// See: https://github.com/hashicorp/vault/issues/1654
#[derive(Debug)]
pub struct VaultNaiveDateTime(pub NaiveDateTime);
impl Decodable for VaultNaiveDateTime {
    fn decode<D: Decoder>(d: &mut D) -> ::std::result::Result<VaultNaiveDateTime, D::Error> {
        let seconds_since_epoch = try!(d.read_i64());
        let date_time = NaiveDateTime::from_timestamp_opt(seconds_since_epoch, 0);

        match date_time {
            Some(dt) => Ok(VaultNaiveDateTime(dt)),
            None => {
                Err(d.error(&format!("Could not parse: `{}` as a unix timestamp",
                                     seconds_since_epoch,
                                     )))
            }
        }
    }
}

/// Used for responses that return RFC 3339 timestamps
/// See: https://github.com/hashicorp/vault/issues/1654
#[derive(Debug)]
pub struct VaultDateTime(pub DateTime<FixedOffset>);
impl Decodable for VaultDateTime {
    fn decode<D: Decoder>(d: &mut D) -> ::std::result::Result<VaultDateTime, D::Error> {
        let ts = try!(d.read_str());
        let date_time = DateTime::parse_from_rfc3339(&ts);

        match date_time {
            Ok(dt) => Ok(VaultDateTime(dt)),
            Err(e) => {
                Err(d.error(&format!("Could not parse: `{}` as an RFC 3339 timestamp. Error: \
                                      `{:?}`",
                                     ts,
                                     e)))
            }
        }
    }
}

/// Vault client used to make API requests to the vault
#[derive(Debug)]
pub struct VaultClient<'a, T>
    where T: Decodable
{
    /// URL to vault instance
    pub host: &'a str,
    /// Token to access vault
    pub token: String,
    /// `hyper::Client`
    client: Client,
    /// Data
    pub data: Option<VaultResponse<T>>,
}

/// Token data, used in `VaultResponse`
#[derive(RustcDecodable, Debug)]
pub struct TokenData {
    /// Accessor token
    pub accessor: Option<String>,
    /// Creation time
    pub creation_time: VaultNaiveDateTime,
    /// Creation time-to-live
    pub creation_ttl: Option<VaultDuration>,
    /// Display name
    pub display_name: String,
    /// Max time-to-live
    pub explicit_max_ttl: Option<VaultDuration>,
    /// Token id
    pub id: String,
    /// Last renewal time
    pub last_renewal_time: Option<VaultDuration>,
    /// Meta
    pub meta: Option<HashMap<String, String>>,
    /// Number of uses (0: unlimited)
    pub num_uses: u64,
    /// true if token is an orphan
    pub orphan: bool,
    /// Path
    pub path: String,
    /// Policies for token
    pub policies: Vec<String>,
    /// True if renewable
    pub renewable: Option<bool>,
    /// Role
    pub role: Option<String>,
    /// Time-to-live
    pub ttl: VaultDuration,
}

/// Secret data, used in `VaultResponse`
#[derive(RustcDecodable, RustcEncodable, Debug)]
struct SecretData {
    value: String,
}

/// Vault auth
#[derive(RustcDecodable, Debug)]
pub struct Auth {
    /// Client token id
    pub client_token: String,
    /// Accessor
    pub accessor: String,
    /// Policies
    pub policies: Vec<String>,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// Lease duration
    pub lease_duration: Option<VaultDuration>,
    /// True if renewable
    pub renewable: bool,
}

/// Vault response. Different vault responses have different `data` types, so `D` is used to
/// represent this.
#[derive(RustcDecodable, Debug)]
pub struct VaultResponse<D>
    where D: Decodable
{
    /// Request id
    pub request_id: String,
    /// Lease id
    pub lease_id: Option<String>,
    /// True if renewable
    pub renewable: Option<bool>,
    /// Lease duration (in seconds)
    pub lease_duration: Option<VaultDuration>,
    /// Data
    pub data: Option<D>,
    /// Warnings
    pub warnings: Option<Vec<String>>,
    /// Auth
    pub auth: Option<Auth>,
    /// Wrap info, containing token to perform unwrapping
    pub wrap_info: Option<WrapInfo>,
}

/// Information provided to retrieve a wrapped response
#[derive(RustcDecodable, Debug)]
pub struct WrapInfo {
    /// Time-to-live
    pub ttl: VaultDuration,
    /// Token
    pub token: String,
    /// Creation time, note this returned in RFC 3339 format
    pub creation_time: VaultDateTime,
    /// Wrapped accessor
    pub wrapped_accessor: String,
}

/// Wrapped response is serialized json
#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct WrapData {
    /// Serialized json string of type `VaultResponse<HashMap<String, String>>`
    response: String,
}

/// AppRole properties
#[derive(RustcDecodable, Debug)]
pub struct AppRoleProperties {
    /// Require `secret_id` to be presented when logging in using this AppRole. Defaults to 'true'.
    pub bind_secret_id: bool,
    /// Comma-separated list of CIDR blocks; if set, specifies blocks of IP addresses which can perform the login operation.
    pub bound_cidr_list: String,
    /// If set, the token generated using this AppRole is a periodic token; so long as it is renewed
    /// it never expires, but the TTL set on the token at each renewal is fixed to the value
    /// specified here. If this value is modified, the token will pick up the new value at its next
    /// renewal.
    pub period: VaultDuration,
    /// List of policies set on tokens issued via this AppRole.
    pub policies: Vec<String>,
    /// Number of times any particular SecretID can be used to fetch a token from this AppRole, after which the SecretID will expire.
    pub secret_id_num_uses: u64,
    /// Duration after which any SecretID expires.
    pub secret_id_ttl: VaultDuration,
    /// Duration after which the issued token can no longer be renewed.
    pub token_max_ttl: VaultDuration,
}

/// Payload to send to vault when authenticating via app-id
#[derive(RustcDecodable, RustcEncodable, Debug)]
struct AppIdPayload {
    app_id: String,
    user_id: String,
}

/// Payload to send to vault when authenticating via AppRole
#[derive(RustcDecodable, RustcEncodable, Debug)]
struct AppRolePayload {
    role_id: String,
    secret_id: Option<String>,
}

/// Postgresql secret backend
#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct PostgresqlLogin {
    /// Password
    pub password: String,
    /// Username
    pub username: String,
}

header! {
    /// Token used to authenticate with the vault API
    (XVaultToken, "X-Vault-Token") => [String]
}
header! {
    /// The TTL for the token is set by the client using the X-Vault-Wrap-TTL header and can be
    /// either an integer number of seconds or a string duration of seconds (15s), minutes (20m),
    /// or hours (25h). When using the Vault CLI, you can set this via the -wrap-ttl parameter.
    /// Response wrapping is per-request; it is the presence of a value in this header that
    /// activates wrapping of the response.
    ///
    /// See: https://www.vaultproject.io/docs/secrets/cubbyhole/index.html
    (XVaultWrapTTL, "X-Vault-Wrap-TTL") => [String]
}

impl<'a> VaultClient<'a, TokenData> {
    /// Construct a `VaultClient` from an existing vault token
    pub fn new(host: &'a str, token: &'a str) -> Result<VaultClient<'a, TokenData>> {
        let client = Client::new();
        let mut res = try!(
            handle_hyper_response(client.get(&format!("{}/v1/auth/token/lookup-self", host)[..])
                                  .header(XVaultToken(token.to_string()))
                                  .send()));
        let decoded: VaultResponse<TokenData> = try!(parse_vault_response(&mut res));
        Ok(VaultClient {
            host: host,
            token: token.to_string(),
            client: client,
            data: Some(decoded),
        })
    }
}

impl<'a> VaultClient<'a, ()> {
    /// Construct a `VaultClient` via the `App ID`
    /// [auth backend](https://www.vaultproject.io/docs/auth/app-id.html)
    pub fn new_app_id(host: &'a str,
                      app_id: &'a str,
                      user_id: &'a str)
                      -> Result<VaultClient<'a, ()>> {
        let client = Client::new();
        let payload = try!(json::encode(&AppIdPayload {
            app_id: app_id.to_string(),
            user_id: user_id.to_string(),
        }));
        let mut res =
            try!(handle_hyper_response(client.post(&format!("{}/v1/auth/app-id/login", host)[..])
                .body(&payload)
                .send()));
        let decoded: VaultResponse<()> = try!(parse_vault_response(&mut res));
        let token = match decoded.auth {
            Some(ref auth) => auth.client_token.clone(),
            None => {
                return Err(Error::Vault(format!("No client token found in response: `{:?}`",
                                                &decoded.auth)))
            }
        };
        Ok(VaultClient {
            host: host,
            token: token,
            client: client,
            data: Some(decoded),
        })
    }

    /// Construct a `VaultClient` via the `AppRole`
    /// [auth backend](https://www.vaultproject.io/docs/auth/approle.html)
    pub fn new_app_role<S: Into<String>, R: AsRef<str>>(host: &'a R,
                                                        role_id: S,
                                                        secret_id: Option<S>)
                                                        -> Result<VaultClient<'a, ()>> {
        let client = Client::new();
        let secret_id = match secret_id {
            Some(s) => Some(s.into()),
            None => None,
        };
        let payload = try!(json::encode(&AppRolePayload {
            role_id: role_id.into(),
            secret_id: secret_id,
        }));
        let mut res =
            try!(handle_hyper_response(client.post(&format!("{}/v1/auth/approle/login", host.as_ref())[..])
                .body(&payload)
                .send()));
        let decoded: VaultResponse<()> = try!(parse_vault_response(&mut res));
        let token = match decoded.auth {
            Some(ref auth) => auth.client_token.clone(),
            None => {
                return Err(Error::Vault(format!("No client token found in response: `{:?}`",
                                                &decoded.auth)))
            }
        };
        Ok(VaultClient {
            host: host.as_ref(),
            token: token,
            client: client,
            data: Some(decoded),
        })
    }

    /// Construct a `VaultClient` where no lookup is done through vault since it is assumed that the
    /// provided token is a one use token.
    ///
    /// A common use case for this method is when a `wrapping_token` has been received and you want
    /// to query the `cubbyhole/response` endpoint.
    pub fn new_no_lookup(host: &'a str, token: &'a str) -> Result<VaultClient<'a, ()>> {
        let client = Client::new();
        Ok(VaultClient {
            host: host,
            token: token.to_string(),
            client: client,
            data: None,
        })
    }
}

impl<'a, T> VaultClient<'a, T>
    where T: Decodable
{
    /// Renew lease for `VaultClient`'s token and updates the `self.data.auth` based upon response
    pub fn renew(&mut self) -> Result<()> {
        let mut res = try!(self.post(&format!("{}/v1/auth/token/renew-self", self.host), None));
        let vault_res: VaultResponse<T> = try!(parse_vault_response(&mut res));
        if let Some(ref mut data) = self.data {
            data.auth = vault_res.auth;
        }
        Ok(())
    }

    /// Revoke `VaultClient`'s token. This token can no longer be used.
    pub fn revoke(&mut self) -> Result<()> {
        let _ = try!(self.post(&format!("{}/v1/auth/token/revoke-self", self.host), None));
        Ok(())
    }

    /// Renew a specific lease that your token controls
    /// https://www.vaultproject.io/docs/http/sys-renew.html
    pub fn renew_lease(&self, lease_id: &str, increment: Option<u64>) -> Result<VaultResponse<()>> {
        let body = match increment {
            Some(_) => Some(format!("{{\"increment\": {:?}}}", increment)),
            None => None,
        };
        let mut res = try!(self.put(&format!("{}/v1/sys/renew/{}", self.host, lease_id)[..],
                                    body.as_ref().map(String::as_ref)));
        let vault_res: VaultResponse<()> = try!(parse_vault_response(&mut res));
        Ok(vault_res)
    }

    /// Lookup token information
    pub fn lookup(&mut self) -> Result<VaultResponse<TokenData>> {
        let mut res = try!(self.get(&format!("{}/v1/auth/token/lookup-self", self.host), None));
        let vault_res: VaultResponse<TokenData> = try!(parse_vault_response(&mut res));
        Ok(vault_res)
    }

    ///
    /// Saves a secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// # fn main() {
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_set", "world");
    /// assert!(res.is_ok());
    /// # }
    /// ```
    pub fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let _ = try!(self.post(&format!("/v1/secret/{}", key)[..],
                               Some(&format!("{{\"value\": \"{}\"}}", self.escape(value))[..])));
        Ok(())
    }

    fn escape(&self, input: &str) -> String {
        input.replace("\n", "\\n")
    }

    ///
    /// Fetches a saved secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// # fn main() {
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_get", "world");
    /// assert!(res.is_ok());
    /// let res = client.get_secret("hello_get");
    /// assert!(res.is_ok());
    /// assert_eq!(res.unwrap(), "world");
    /// # }
    /// ```
    pub fn get_secret(&self, key: &str) -> Result<String> {
        let mut res = try!(self.get(&format!("/v1/secret/{}", key)[..], None));
        let decoded: VaultResponse<SecretData> = try!(parse_vault_response(&mut res));
        match decoded.data {
            Some(data) => Ok(data.value),
            _ => Err(Error::Vault(format!("No secret found in response: `{:#?}`", decoded))),
        }
    }

    /// Fetch a wrapped secret. Token (one-time use) to fetch secret will be in `wrap_info.token`
    /// https://www.vaultproject.io/docs/secrets/cubbyhole/index.html
    pub fn get_secret_wrapped(&self, key: &str, wrap_ttl: &str) -> Result<VaultResponse<()>> {
        let mut res = try!(self.get(&format!("/v1/secret/{}", key)[..], Some(wrap_ttl)));
        parse_vault_response(&mut res)
    }

    /// Fetch wrapped response from `cubbyhole/response`
    ///
    /// The original response (in the `response` key) is what is returned
    pub fn get_cubbyhole_response(&self) -> Result<VaultResponse<HashMap<String, String>>> {
        let mut res = try!(self.get("/v1/cubbyhole/response", None));
        let decoded: VaultResponse<WrapData> = try!(parse_vault_response(&mut res));
        Ok(try!(json::decode(&decoded.data.unwrap().response[..])))
    }

    /// Reads the properties of an existing AppRole.
    pub fn get_app_role_properties(&self,
                                   role_name: &str)
                                   -> Result<VaultResponse<AppRoleProperties>> {
        let mut res = try!(self.get(&format!("/v1/auth/approle/role/{}", role_name), None));
        parse_vault_response(&mut res)
    }

    ///
    /// Deletes a saved secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// # fn main() {
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_delete", "world");
    /// assert!(res.is_ok());
    /// let res = client.delete_secret("hello_delete");
    /// assert!(res.is_ok());
    /// # }
    /// ```
    pub fn delete_secret(&self, key: &str) -> Result<()> {
        let _ = try!(self.delete(&format!("/v1/secret/{}", key)[..]));
        Ok(())
    }

    /// Get postgresql secret backend
    /// https://www.vaultproject.io/docs/secrets/postgresql/index.html
    pub fn get_postgresql_backend(&self, name: &str) -> Result<VaultResponse<PostgresqlLogin>> {
        let mut res = try!(self.get(&format!("/v1/postgresql/creds/{}", name)[..], None));
        let decoded: VaultResponse<PostgresqlLogin> = try!(parse_vault_response(&mut res));
        Ok(decoded)
    }

    fn get(&self, endpoint: &str, wrap_ttl: Option<&str>) -> Result<Response> {
        let mut req = self.client
            .get(&format!("{}{}", self.host, endpoint)[..])
            .header(XVaultToken(self.token.to_string()))
            .header(header::ContentType::json());
        if wrap_ttl.is_some() {
            req = req.header(XVaultWrapTTL(wrap_ttl.unwrap().to_string()));
        }

        Ok(try!(handle_hyper_response(req.send())))
    }

    fn delete(&self, endpoint: &str) -> Result<Response> {
        Ok(try!(handle_hyper_response(self.client
            .delete(&format!("{}{}", self.host, endpoint)[..])
            .header(XVaultToken(self.token.to_string()))
            .header(header::ContentType::json())
            .send())))
    }

    fn post(&self, endpoint: &str, body: Option<&str>) -> Result<Response> {
        let mut req = self.client
            .post(&format!("{}{}", self.host, endpoint)[..])
            .header(XVaultToken(self.token.to_string()))
            .header(header::ContentType::json());
        if let Some(body) = body {
            req = req.body(body);
        }

        Ok(try!(handle_hyper_response(req.send())))
    }

    fn put(&self, endpoint: &str, body: Option<&str>) -> Result<Response> {
        let mut req = self.client
            .put(&format!("{}{}", self.host, endpoint)[..])
            .header(XVaultToken(self.token.to_string()))
            .header(header::ContentType::json());
        if body.is_some() {
            req = req.body(body.unwrap());
        }

        Ok(try!(handle_hyper_response(req.send())))
    }
}

/// helper fn to check `Response` for success
fn handle_hyper_response(res: ::std::result::Result<Response, hyper::Error>) -> Result<Response> {
    let mut res = try!(res);
    if res.status.is_success() {
        Ok(res)
    } else {
        let mut error_msg = String::new();
        let _ = res.read_to_string(&mut error_msg).unwrap_or({
            error_msg.push_str("Could not read vault response.");
            0
        });
        println!("Vault request failed: {:?}, error message: `{}`",
                 res,
                 error_msg);
        Err(Error::Vault(format!("Vault request failed: {:?}, error message: `{}`",
                                 res,
                                 error_msg)))
    }
}

fn parse_vault_response<T>(res: &mut Response) -> Result<VaultResponse<T>>
    where T: Decodable
{
    let mut body = String::new();
    let _ = try!(res.read_to_string(&mut body));
    println!("Response: {:?}", &body);
    let vault_res: VaultResponse<T> = try!(json::decode(&body));
    Ok(vault_res)
}
