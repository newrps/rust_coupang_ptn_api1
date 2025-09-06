// src/main.rs
use anyhow::Result;
use chrono::{DateTime, Utc};
use dotenv::dotenv;
use hex;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::Rng;
use reqwest;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::{fs, path::Path};
use regex::Regex;
type HmacSha256 = Hmac<Sha256>;
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

/// html_escape 사용 (Cargo.toml에 `html_escape = "0.2"` 추가 필요)
/// features: 없음
use html_escape;

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct MobileBannerItem {
    pub id: String,
    pub enabled: bool,
    pub maxWidth: u32,
    pub closeable: bool,
    pub snippet: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SideBannerJsonMulti {
    pub side: Vec<SideBannerItem>,         // 좌/우 여러 개
    pub mobile: Vec<MobileBannerItem>,     // 모바일 여러 개
}

// ---------------- 추천 컨텍스트(옵션적) ----------------
#[derive(Debug, Clone)]
pub struct SiteInfo {
    pub domain: String,         // 추천: 최상위 도메인
    pub id: String,             // 필수: 사이트 ID(고유)
    pub page: Option<String>,   // 추천: 실제 노출 페이지 URL
}

#[derive(Debug, Clone)]
pub struct AppInfo {
    pub bundle_id: String,      // 추천: 번들/패키지명(iOS/Android)
    pub domain: Option<String>, // 추천: 앱 도메인
    pub id: String,             // 필수: 앱 ID(고유)
}

#[derive(Debug, Clone)]
pub enum Inventory {
    Site(SiteInfo),
    App(AppInfo),
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub id: String,             // 필수: GAID/IDFA
    pub ip: Option<String>,     // 추천
    pub lmt: u8,                // 필수: 0 or 1
    pub ua: Option<String>,     // 추천: User-Agent
}

#[derive(Debug, Clone)]
pub struct ImpInfo {
    pub ad_type: Option<u8>,        // 선택: 1..=7
    pub image_size: String,         // 필수: "WxH" (예: "512x512")
    pub placement_id: Option<String>, // 추천
    pub pos: Option<u8>,            // 선택: 1,3,4,5,6,7
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub puid: String, // 필수: Publisher User ID
}

#[derive(Debug, Clone, Default)]
pub struct AffiliateInfo {
    pub sub_id: Option<String>,     // 선택: 등록된 채널 ID
    pub sub_param: Option<String>,  // 선택: 임의 파라미터
}

#[derive(Debug, Clone)]
pub struct RecoContext {
    pub inventory: Inventory,           // Site 또는 App 중 하나
    pub device: DeviceInfo,             // 필수들 포함
    pub imp: ImpInfo,                   // imageSize 필수
    pub user: UserInfo,                 // puid 필수
    pub affiliate: Option<AffiliateInfo>,
}

impl RecoContext {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.device.lmt != 0 && self.device.lmt != 1 {
            anyhow::bail!("Device.lmt는 0 또는 1이어야 합니다 (현재: {}).", self.device.lmt);
        }
        let len = self.device.id.len();
        if !(len == 32 || len == 36) {
            eprintln!("[WARN] Device.id 길이 비표준({}); GAID/IDFA가 맞는지 확인하세요.", len);
        }
        let re_img = Regex::new(r"^\d+x\d+$").unwrap();
        if !re_img.is_match(&self.imp.image_size) {
            anyhow::bail!("Imp.imageSize 형식 오류: \"{}\" (예: \"512x512\")", self.imp.image_size);
        }
        if let Some(t) = self.imp.ad_type {
            if !(1..=7).contains(&t) {
                anyhow::bail!("Imp.adType 허용 범위는 1..=7 입니다 (현재: {}).", t);
            }
        }
        if let Some(p) = self.imp.pos {
            match p { 1 | 3 | 4 | 5 | 6 | 7 => {}, _ => anyhow::bail!("Imp.pos 허용값: 1,3,4,5,6,7 (현재: {}).", p) }
        }
        if self.user.puid.trim().is_empty() {
            anyhow::bail!("User.puid는 필수입니다.");
        }
        match &self.inventory {
            Inventory::Site(s) => {
                if s.domain.trim().is_empty() { anyhow::bail!("Site.domain은 비어있을 수 없습니다."); }
                if s.id.trim().is_empty()     { anyhow::bail!("Site.id는 비어있을 수 없습니다."); }
            }
            Inventory::App(a) => {
                if a.bundle_id.trim().is_empty() { eprintln!("[WARN] App.bundleId가 비어있습니다."); }
                if a.id.trim().is_empty()        { anyhow::bail!("App.id는 비어있을 수 없습니다."); }
            }
        }
        Ok(())
    }

    pub fn into_query_map(self) -> HashMap<String, String> {
        let mut m = HashMap::new();

        match self.inventory {
            Inventory::Site(s) => {
                m.insert("siteDomain".into(), s.domain);
                m.insert("siteId".into(), s.id);
                if let Some(p) = s.page { m.insert("page".into(), p); }
            }
            Inventory::App(a) => {
                m.insert("bundleId".into(), a.bundle_id);
                if let Some(d) = a.domain { m.insert("domain".into(), d); }
                m.insert("appId".into(), a.id);
            }
        }

        m.insert("deviceId".into(), self.device.id);
        m.insert("lmt".into(), self.device.lmt.to_string());
        if let Some(ip) = self.device.ip { m.insert("ip".into(), ip); }
        if let Some(ua) = self.device.ua { m.insert("ua".into(), ua); }

        if let Some(t) = self.imp.ad_type { m.insert("adType".into(), t.to_string()); }
        m.insert("imageSize".into(), self.imp.image_size);
        if let Some(pid) = self.imp.placement_id { m.insert("placementId".into(), pid); }
        if let Some(pos) = self.imp.pos { m.insert("pos".into(), pos.to_string()); }

        m.insert("puid".into(), self.user.puid);

        if let Some(aff) = self.affiliate {
            if let Some(s)  = aff.sub_id     { m.insert("subId".into(), s); }
            if let Some(sp) = aff.sub_param  { m.insert("subParam".into(), sp); }
        }

        m
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ProductRecoData {
    #[serde(rename = "landingUrl")]
    pub landing_url: Option<String>,
    #[serde(rename = "productData")]
    pub product_data: Vec<ProductItem>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ProductRecoResponse {
    #[serde(rename = "rCode")]
    pub r_code: String,
    #[serde(rename = "rMessage")]
    pub r_message: String,
    pub data: Option<ProductRecoData>,
}

// ---------------- 딥링크 요청/응답 ----------------

#[derive(serde::Serialize, serde::Deserialize)]
struct DeepLinkRequest {
    #[serde(rename = "coupangUrls")]
    coupang_urls: Vec<String>,
}

pub struct CoupangApiClient {
    access_key: String,
    secret_key: String,
    domain: String,
    client: reqwest::Client,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DeeplinkItem {
    #[serde(rename = "originalUrl")]
    pub original_url: String,
    #[serde(rename = "shortenUrl")]
    pub shorten_url: String,
    #[serde(rename = "landingUrl")]
    pub landing_url: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DeeplinkResponse {
    #[serde(rename = "rCode")]
    pub r_code: String,
    #[serde(rename = "rMessage")]
    pub r_message: String,
    pub data: Option<Vec<DeeplinkItem>>,
}

// ---------------- 쿠팡 상품 검색 응답 ----------------

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ProductItem {
    #[serde(rename = "productId")]
    pub product_id: Option<u64>,
    #[serde(rename = "productName")]
    pub product_name: Option<String>,
    #[serde(rename = "productUrl")]
    pub product_url: Option<String>,
    #[serde(rename = "productImage")]
    pub product_image: Option<String>,
    #[serde(rename = "productPrice")]
    pub product_price: Option<u64>,
    #[serde(rename = "originalPrice")]
    pub original_price: Option<u64>,
    #[serde(rename = "discountRate")]
    pub discount_rate: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ProductSearchData {
    #[serde(rename = "landingUrl")]
    pub landing_url: Option<String>,
    #[serde(rename = "productData")]
    pub product_data: Vec<ProductItem>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ProductSearchResponse {
    #[serde(rename = "rCode")]
    pub r_code: String,
    #[serde(rename = "rMessage")]
    pub r_message: String,
    pub data: Option<ProductSearchData>,
}

// ---------------- 여기부터: JSON 스키마 ----------------

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SideBannerItem {
    pub id: String,
    pub enabled: bool,
    pub position: String,
    pub width: u32,
    pub minWidth: u32,
    pub snippet: String,
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct MobileBanner {
    pub enabled: bool,
    pub maxWidth: u32,
    pub closeable: bool,
    pub snippet: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SideBannerJson {
    pub side: Vec<SideBannerItem>,
    pub mobile: MobileBanner,
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TextAdItem {
    #[serde(rename = "type")]
    pub kind: String, // "text"
    pub url: String,  // 트래킹 URL(= 파트너스 링크)
    pub content: String,
    pub backgroundColor: String, // linear-gradient(...) 등
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct TextAdsJson {
    pub ads: Vec<TextAdItem>,
}

// ---------------- 공통 헬퍼: 숫자/URL/바디 빌드 ----------------

fn value_num_to_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(u) = v.as_u64() { return Some(u); }
    if let Some(f) = v.as_f64() { if f.is_finite() { return Some(f.round() as u64); } }
    if let Some(s) = v.as_str() {
        let t = s.trim().replace(",", "");
        if let Ok(u) = t.parse::<u64>() { return Some(u); }
        if let Ok(f) = t.parse::<f64>() { if f.is_finite() { return Some(f.round() as u64); } }
    }
    None
}

fn build_reco_body_from_map(mut m: HashMap<String, String>) -> Value {
    let mut root = json!({});

    // --- device ---
    let mut device = json!({});
    if let Some(id) = m.remove("deviceId") { device["id"] = Value::String(id); }
    if let Some(lmt_s) = m.remove("lmt") {
        if let Ok(n) = lmt_s.parse::<u8>() { device["lmt"] = Value::Number(n.into()); }
        else { device["lmt"] = Value::String(lmt_s); }
    }
    if let Some(ip) = m.remove("ip")  { device["ip"]  = Value::String(ip); }
    if let Some(ua) = m.remove("ua")  { device["ua"]  = Value::String(ua); }
    if device.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        root["device"] = device;
    }

    // --- imp ---
    let mut imp = json!({});
    if let Some(s) = m.remove("imageSize")    { imp["imageSize"] = Value::String(s); }
    if let Some(s) = m.remove("adType")       { if let Ok(n)=s.parse::<u8>() { imp["adType"]=Value::Number(n.into()); } }
    if let Some(s) = m.remove("placementId")  { imp["placementId"] = Value::String(s); }
    if let Some(s) = m.remove("pos")          { if let Ok(n)=s.parse::<u8>() { imp["pos"]=Value::Number(n.into()); } }
    if imp.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        root["imp"] = imp;
    }

    // --- user ---
    if let Some(puid) = m.remove("puid") {
        root["user"] = json!({ "puid": puid });
    }

    // --- affiliate ---
    let mut affiliate = json!({});
    if let Some(s) = m.remove("subId")    { affiliate["subId"]    = Value::String(s); }
    if let Some(s) = m.remove("subParam") { affiliate["subParam"] = Value::String(s); }
    if affiliate.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        root["affiliate"] = affiliate;
    }

    // --- site / app ---
    let mut site = json!({});
    if let Some(s) = m.remove("siteDomain") { site["domain"] = Value::String(s); }
    if let Some(s) = m.remove("siteId")     { site["id"]     = Value::String(s); }
    if let Some(s) = m.remove("page")       { site["page"]   = Value::String(s); }
    if site.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        root["site"] = site;
    }

    let mut app = json!({});
    if let Some(s) = m.remove("bundleId") { app["bundleId"] = Value::String(s); }
    if let Some(s) = m.remove("appDomain").or_else(|| m.remove("domain")) {
        app["domain"] = Value::String(s);
    }
    if let Some(s) = m.remove("appId") { app["id"] = Value::String(s); }
    if app.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        root["app"] = app;
    }

    // --- top-level ---
    if let Some(pid) = m.remove("productId") {
        if let Ok(n) = pid.parse::<u64>() { root["productId"] = json!(n); }
        else { root["productId"] = json!(pid); }
    }
    if let Some(lim) = m.remove("limit") {
        if let Ok(n) = lim.parse::<u32>() { root["limit"] = json!(n); }
        else { root["limit"] = json!(lim); }
    }
    if let Some(t) = m.remove("recoType") { root["recoType"] = json!(t); }

    root
}

// ---------------- 광고 생성 유틸 ----------------

fn is_affiliate_link(u: &str) -> bool {
    u.contains("://link.coupang.com/")
}

fn is_detail_url(u: &str) -> bool {
    u.contains("/vp/products/")
}

// “상세로 간주”: 상세 URL 또는 이미 파트너스 링크
fn is_detailish(u: &str) -> bool {
    is_detail_url(u) || is_affiliate_link(u)
}

fn truncate_title(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max { break; }
        out.push(ch);
    }
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

/// 랜덤 그라데이션 배경 생성
pub fn generate_random_gradient() -> String {
    let gradients = vec![
        "linear-gradient(135deg, #ff6b6b, #ee5a24)",
        "linear-gradient(135deg, #4ecdc4, #44a08d)",
        "linear-gradient(135deg, #667eea, #764ba2)",
        "linear-gradient(135deg, #f093fb, #f5576c)",
        "linear-gradient(135deg, #4facfe, #00f2fe)",
        "linear-gradient(135deg, #43e97b, #38f9d7)",
        "linear-gradient(135deg, #fa709a, #fee140)",
        "linear-gradient(135deg, #a8edea, #fed6e3)",
        "linear-gradient(135deg, #ffecd2, #fcb69f)",
        "linear-gradient(135deg, #ff9a9e, #fecfef)",
    ];
    let mut rng = rand::thread_rng();
    gradients[rng.gen_range(0..gradients.len())].to_string()
}

/// 상품명을 기반으로 광고 텍스트 생성
pub fn generate_ad_content(product_name: &str) -> String {
    let templates = vec![
        "{} 구매하기",
        "{} 특가 할인!",
        "{} 지금 주문하세요",
        "{} 베스트 상품",
        "인기 {} 추천",
        "{} 최저가 도전",
    ];
    let mut rng = rand::thread_rng();
    let template = templates[rng.gen_range(0..templates.len())];
    template.replace("{}", product_name)
}

/// 이미 딥링크면 그대로, 아니면 딥링크 생성 시도(실패 시 원본 URL 유지)
// ★ to_affiliate 적용: 모든 출력 URL에 사용
async fn to_affiliate(client: &CoupangApiClient, url: &str) -> String {
    if is_affiliate_link(url) {
        return url.to_string();
    }
    match client.create_deeplink_one(url).await {
        Ok(d) => d.shorten_url,
        Err(_) => url.to_string(),
    }
}

// ---------------- CoupangApiClient 구현 ----------------

impl CoupangApiClient {
    /// 추천 상품 조회 (POST)
    pub async fn recommend_products(
        &self,
        mut query_params: HashMap<String, String>,
    ) -> Result<Vec<ProductItem>> {
        query_params.entry("limit".into()).or_insert_with(|| "10".into());

        let body = build_reco_body_from_map(query_params);
        eprintln!("[RECO] (POST) body = {}", body);

        let resp_text = self
            .call_api(
                "POST",
                "/v2/providers/affiliate_open_api/apis/openapi/v2/products/reco",
                Some(body),
                None,
            )
            .await?;

        let v: Value = match serde_json::from_str(&resp_text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[RECO][ERR] non-JSON ({}) head: {}", e, resp_text.chars().take(220).collect::<String>());
                return Err(anyhow::anyhow!("recommend_products: invalid JSON"));
            }
        };

        let r_code = v.get("rCode").and_then(|x| x.as_str()).unwrap_or("");
        let r_msg  = v.get("rMessage").and_then(|x| x.as_str()).unwrap_or("");
        if !r_code.is_empty() || !r_msg.is_empty() {
            eprintln!("[RECO] rCode={}, rMessage={}", r_code, r_msg);
        }

        // data.productData / productData / data.products / data.result
        let arrays = [
            v.get("data").and_then(|d| d.get("productData")).and_then(|a| a.as_array()),
            v.get("productData").and_then(|a| a.as_array()),
            v.get("data").and_then(|d| d.get("products")).and_then(|a| a.as_array()),
            v.get("data").and_then(|d| d.get("result")).and_then(|a| a.as_array()),
        ];

        let mut items = Vec::<ProductItem>::new();
        if let Some(arr) = arrays.into_iter().flatten().next() {
            for it in arr {
                let item = ProductItem {
                    product_id: it.get("productId").and_then(|x| x.as_u64()),
                    product_name: it.get("productName").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    product_url: it.get("productUrl").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    product_image: it
                        .get("productImage")
                        .or_else(|| it.get("imageUrl"))
                        .and_then(|x| x.as_str()).map(|s| s.to_string()),
                    product_price: it.get("productPrice").and_then(|x| value_num_to_u64(x)),
                    original_price: it.get("originalPrice").and_then(|x| value_num_to_u64(x)),
                    discount_rate: it.get("discountRate").map(|x| match x {
                        Value::String(s) => Some(s.clone()),
                        Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    }).flatten(),
                };
                items.push(item);
            }
        } else {
            eprintln!("[RECO] no product array found. head: {}", resp_text.chars().take(220).collect::<String>());
        }

        eprintln!("[RECO] parsed {} items", items.len());
        Ok(items)
    }

    pub fn new(access_key: String, secret_key: String) -> Self {
        Self {
            access_key,
            secret_key,
            domain: "https://api-gateway.coupang.com".to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub fn from_env() -> Result<Self> {
        let access_key = env::var("ACCESSKEY")
            .map_err(|_| anyhow::anyhow!("ACCESSKEY environment variable not found"))?;
        let secret_key = env::var("SECRETKEY")
            .map_err(|_| anyhow::anyhow!("SECRETKEY environment variable not found"))?;
        Ok(Self::new(access_key, secret_key))
    }

    /// CEA 시그니처 (쉼표 뒤 공백 없음!)
    fn generate_hmac_signature(&self, method: &str, uri: &str) -> Result<String> {
        let parts: Vec<&str> = uri.split('?').collect();
        if parts.len() > 2 {
            return Err(anyhow::anyhow!("Incorrect URI format"));
        }
        let path = parts[0];
        let query = if parts.len() == 2 { parts[1] } else { "" };

        let now: DateTime<Utc> = Utc::now();
        let datetime = now.format("%y%m%dT%H%M%SZ").to_string();
        let message = format!("{}{}{}{}", datetime, method, path, query);

        let mut mac = HmacSha256::new_from_slice(self.secret_key.as_bytes())
            .map_err(|e| anyhow::anyhow!("Invalid secret key: {}", e))?;
        mac.update(message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        Ok(format!(
            "CEA algorithm=HmacSHA256,access-key={},signed-date={},signature={}",
            self.access_key, datetime, signature
        ))
    }

    pub async fn create_deeplinks(&self, urls: Vec<String>) -> Result<String> {
        let path = "/v2/providers/affiliate_open_api/apis/openapi/v1/deeplink";
        let full_url = format!("{}{}", self.domain, path);
        let authorization = self.generate_hmac_signature("POST", path)?;

        let request_body = DeepLinkRequest { coupang_urls: urls };
        let resp = self
            .client
            .post(&full_url)
            .header("Authorization", authorization)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow::anyhow!("HTTP {} | {}", status, text));
        }
        Ok(text)
    }

    pub async fn create_deeplink_one(&self, url: &str) -> Result<DeeplinkItem> {
        if is_affiliate_link(url) {
            return Ok(DeeplinkItem {
                original_url: url.to_string(),
                shorten_url: url.to_string(),
                landing_url: url.to_string(),
            });
        }

        let raw = self.create_deeplinks(vec![url.to_string()]).await?;
        let parsed: DeeplinkResponse = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("deeplink parse error: {} | raw={}", e, raw))?;

        let item = parsed
            .data
            .and_then(|mut v| v.pop())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "deeplink not returned (rCode={}, rMessage={}) | raw={}",
                    parsed.r_code,
                    parsed.r_message,
                    raw
                )
            })?;
        Ok(item)
    }

    fn canonical_query(params: &HashMap<String, String>) -> String {
        let mut items: Vec<(String, String)> =
            params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items
            .into_iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    utf8_percent_encode(&k, NON_ALPHANUMERIC),
                    utf8_percent_encode(&v, NON_ALPHANUMERIC)
                )
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    pub async fn call_api(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        query_params: Option<HashMap<String, String>>,
    ) -> Result<String> {
        let (signed_uri, full_url) = if let Some(params) = &query_params {
            let qs = Self::canonical_query(params);
            (format!("{}?{}", path, qs), format!("{}{}?{}", self.domain, path, qs))
        } else {
            (path.to_string(), format!("{}{}", self.domain, path))
        };

        let authorization = self.generate_hmac_signature(method, &signed_uri)?;

        let req = match method.to_uppercase().as_str() {
            "GET" => self.client.get(&full_url),
            "POST" => self.client.post(&full_url),
            "PUT" => self.client.put(&full_url),
            "DELETE" => self.client.delete(&full_url),
            _ => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
        }
        .header("Authorization", authorization)
        .header("Content-Type", "application/json");

        let req = if let Some(body_data) = body {
            req.json(&body_data)
        } else {
            req
        };
        let resp = req.send().await?;
        Ok(resp.text().await?)
    }

    /// 상품 검색: data.productData를 파싱
    pub async fn search_products(&self, keyword: &str, limit: u32) -> Result<Vec<ProductItem>> {
        let mut query_params = HashMap::new();
        query_params.insert("keyword".to_string(), keyword.to_string());
        query_params.insert("limit".to_string(), limit.to_string());

        let response_text = self
            .call_api(
                "GET",
                "/v2/providers/affiliate_open_api/apis/openapi/products/search",
                None,
                Some(query_params),
            )
            .await?;

        let parsed: ProductSearchResponse = serde_json::from_str(&response_text)
            .map_err(|e| anyhow::anyhow!("product search parse error: {} | raw={}", e, response_text))?;

        let items = parsed.data.map(|d| d.product_data).unwrap_or_default();

        Ok(items)
    }
}

// ---------------- 빌더들 ----------------

/// 고정 배너/스니펫을 사용해 (A) 형태의 JSON을 생성
pub fn build_side_banner_json(
    left_aff_link: &str,
    left_img_src: &str,
    left_img_alt: &str,
    right_unit_id: &str,
    right_link_unit_id: &str,
    mobile_unit_id: &str,
    mobile_link_unit_id: &str,
) -> SideBannerJson {
    let left_snippet = format!(
        "<a href=\"{}\" target=\"_blank\" referrerpolicy=\"unsafe-url\"><img src=\"{}\" alt=\"{}\" width=\"120\" height=\"240\"></a>",
        left_aff_link, left_img_src, html_escape::encode_text(left_img_alt)
    );

    let right_snippet = format!(
        "<ins class='adsbycoupang' data-ad-type='banner' data-ad-img='img_160x600' data-ad-unit='{}' data-ad-link-unit-id='{}' data-ad-order='5' data-ad-border='false'></ins>",
        right_unit_id, right_link_unit_id
    );

    let mobile_snippet = format!(
        "<ins class='adsbycoupang' data-ad-type='banner' data-ad-img='img_320x100' data-ad-unit='{}' data-ad-link-unit-id='{}' data-ad-order='5' data-ad-border='false'></ins>",
        mobile_unit_id, mobile_link_unit_id
    );

    SideBannerJson {
        side: vec![
            SideBannerItem {
                id: "left-160x600".to_string(),
                enabled: true,
                position: "left".to_string(),
                width: 160,
                minWidth: 1280,
                snippet: left_snippet,
            },
            SideBannerItem {
                id: "right-160x600".to_string(),
                enabled: true,
                position: "right".to_string(),
                width: 160,
                minWidth: 1280,
                snippet: right_snippet,
            },
        ],
        mobile: MobileBanner {
            enabled: true,
            maxWidth: 768,
            closeable: true,
            snippet: mobile_snippet,
        },
    }
}

/// (B) 형태의 텍스트 광고 JSON을 생성
pub fn build_text_ads_json(items: Vec<TextAdItem>) -> TextAdsJson {
    TextAdsJson { ads: items }
}

/// 여러 개의 좌/우 배너와 여러 개의 모바일 배너를 한 번에 생성
pub fn build_side_banner_json_multi(
    left_blocks: Vec<(String, String, String)>, // (aff_link, img_src, img_alt)
    right_units: Vec<(String, String)>,         // (unit_id, link_unit_id)
    mobile_units: Vec<(String, String)>,        // (unit_id, link_unit_id)
) -> SideBannerJsonMulti {
    let mut side_items: Vec<SideBannerItem> = Vec::new();
    for (idx, (aff_link, img_src, img_alt)) in left_blocks.into_iter().enumerate() {
        let id = format!("left-160x600-{}", idx + 1);
        let snippet = format!(
            "<a href=\"{}\" target=\"_blank\" referrerpolicy=\"unsafe-url\">\
             <img src=\"{}\" alt=\"{}\" width=\"120\" height=\"240\"></a>",
            aff_link,
            img_src,
            html_escape::encode_text(&img_alt)
        );
        side_items.push(SideBannerItem {
            id,
            enabled: true,
            position: "left".to_string(),
            width: 160,
            minWidth: 1280,
            snippet,
        });
    }

    for (idx, (unit_id, link_unit_id)) in right_units.into_iter().enumerate() {
        let id = format!("right-160x600-{}", idx + 1);
        let snippet = format!(
            "<ins class='adsbycoupang' data-ad-type='banner' data-ad-img='img_160x600' \
             data-ad-unit='{}' data-ad-link-unit-id='{}' data-ad-order='5' data-ad-border='false'></ins>",
            unit_id, link_unit_id
        );
        side_items.push(SideBannerItem {
            id,
            enabled: true,
            position: "right".to_string(),
            width: 160,
            minWidth: 1280,
            snippet,
        });
    }

    let mut mobile_items: Vec<MobileBannerItem> = Vec::new();
    for (idx, (unit_id, link_unit_id)) in mobile_units.into_iter().enumerate() {
        let id = format!("mobile-320x100-{}", idx + 1);
        let snippet = format!(
            "<ins class='adsbycoupang' data-ad-type='banner' data-ad-img='img_320x100' \
             data-ad-unit='{}' data-ad-link-unit-id='{}' data-ad-order='5' data-ad-border='false'></ins>",
            unit_id, link_unit_id
        );
        mobile_items.push(MobileBannerItem {
            id,
            enabled: true,
            maxWidth: 768,
            closeable: true,
            snippet,
        });
    }

    SideBannerJsonMulti { side: side_items, mobile: mobile_items }
}

// ---------------- 로직: 배너/텍스트 생성 ----------------

/// 검색 결과 → 사이드/모바일 배너 JSON (좌측 링크 딥링크 강제)
async fn build_side_banner_from_products(
    client: &CoupangApiClient,
    products: &[ProductItem],
    right_unit_id: &str,
    right_link_unit_id: &str,
    mobile_unit_id: &str,
    mobile_link_unit_id: &str,
) -> Result<SideBannerJson> {
    let pick = products.iter().find(|p| {
        p.product_url
            .as_deref()
            .map(|u| is_detailish(u))
            .unwrap_or(false)
    });
    let p = pick.ok_or_else(|| anyhow::anyhow!("상세 상품 URL이 포함된 검색 결과가 없습니다."))?;

    let title = truncate_title(p.product_name.as_deref().unwrap_or("상품"), 40);
    let img = p.product_image.as_deref().unwrap_or("");
    let url = p.product_url.as_deref().unwrap_or("");

    // ★ to_affiliate 적용
    let left_link = to_affiliate(client, url).await;

    Ok(build_side_banner_json(
        &left_link,
        img,
        &title,
        right_unit_id,
        right_link_unit_id,
        mobile_unit_id,
        mobile_link_unit_id,
    ))
}

/// 검색/추천 결과 → 텍스트 광고 JSON (모든 URL 딥링크 강제)
pub async fn products_to_text_ads_json(
    client: &CoupangApiClient,
    products: Vec<ProductItem>,
) -> Result<TextAdsJson> {
    let mut text_ads = Vec::new();
    for product in products {
        if let (Some(name), Some(url)) = (product.product_name.clone(), product.product_url.clone()) {
            // ★ to_affiliate 적용
            let final_url = to_affiliate(client, &url).await;

            text_ads.push(TextAdItem {
                kind: "text".to_string(),
                url: final_url,
                content: generate_ad_content(&name),
                backgroundColor: generate_random_gradient(),
            });
        }
    }
    Ok(TextAdsJson { ads: text_ads })
}

/// JSON 저장
pub fn save_json_to_file<T: serde::Serialize>(data: &T, filename: &str) -> Result<()> {
    if let Some(parent) = Path::new(filename).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let json_string = serde_json::to_string_pretty(data)?;
    fs::write(filename, json_string)?;
    println!("JSON 저장: {}", filename);
    Ok(())
}

// ---------------- 실행부 ----------------

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let client = CoupangApiClient::from_env()?;

    println!("Coupang API Client initialized successfully!");

    // === 설정값 ===
    let keyword_for_banners = "계란";   // 사이드 배너 좌측에 들어갈 대표 상품 키워드
    let keyword_for_textads = "선물";   // 텍스트 광고 생성 키워드
    let textads_limit = 20;

    // 우측/모바일 고정 유닛 ID
    let right_unit_id = "UNIT_ID";
    let right_link_unit_id = "LINK_ID";
    let mobile_unit_id = "UNIT_ID_M";
    let mobile_link_unit_id = "LINK_ID_M";

    // 출력 경로
    let out_dir = Path::new("./json");
    fs::create_dir_all(out_dir)?;

    // === 검색 → 사이드/모바일 배너 JSON ===
    let products_for_banner = client.search_products(keyword_for_banners, 10).await?;
    if products_for_banner.is_empty() {
        eprintln!("배너용 검색 결과가 없습니다. 키워드를 변경해보세요: {}", keyword_for_banners);
    } else {
        let side_json = build_side_banner_from_products(
            &client,
            &products_for_banner,
            right_unit_id,
            right_link_unit_id,
            mobile_unit_id,
            mobile_link_unit_id,
        )
        .await?;

        save_json_to_file(&side_json, out_dir.join("side_mobile.json").to_str().unwrap())?;
    }

    // === 검색 → 텍스트 광고 JSON ===
    let products_for_text = client.search_products(keyword_for_textads, 10).await?;
    if products_for_text.is_empty() {
        eprintln!("텍스트 광고용 검색 결과가 없습니다. 키워드를 변경해보세요: {}", keyword_for_textads);
    } else {
        let items = products_for_text
            .into_iter()
            .take(textads_limit as usize)
            .collect::<Vec<_>>();
        let text_ads = products_to_text_ads_json(&client, items).await?;
        save_json_to_file(&text_ads, out_dir.join("text_ads.json").to_str().unwrap())?;
    }

    println!("완료! ./json 폴더에 생성되었습니다.");

    // === 추천 → 텍스트 광고 & 멀티 배너 JSON ===
    if let Some(base_product) = products_for_banner.iter().find(|p| p.product_id.is_some()) {
        let base_id = base_product.product_id.unwrap();
        eprintln!("[BASE] (for RECO) id={}, name={:?}", base_id, base_product.product_name);

        let device_id = std::env::var("RECO_DEVICE_ID").unwrap_or_else(|_| "38400000-8cf0-11bd-b23e-10b96e40000d".to_string());
        let lmt       = std::env::var("RECO_LMT").unwrap_or_else(|_| "1".to_string());
        let image_sz  = std::env::var("RECO_IMAGE_SIZE").unwrap_or_else(|_| "320x320".to_string());
        let puid      = std::env::var("RECO_PUID").unwrap_or_else(|_| "user-123456".to_string());
        let sub_id    = std::env::var("RECO_SUB_ID").ok();

        let mut reco_params = HashMap::new();
        reco_params.insert("productId".to_string(), base_id.to_string());
        reco_params.insert("limit".to_string(), "16".to_string());
        reco_params.insert("deviceId".to_string(), device_id);
        reco_params.insert("lmt".to_string(), lmt);
        reco_params.insert("imageSize".to_string(), image_sz);
        reco_params.insert("puid".to_string(), puid);
        if let Some(sid) = sub_id { reco_params.insert("subId".to_string(), sid); }

        let mut reco_items = client.recommend_products(reco_params.clone()).await?;
        if reco_items.is_empty() {
            let mut p = reco_params.clone();
            p.insert("recoType".to_string(), "SIMILAR".to_string());
            reco_items = client.recommend_products(p).await?;
        }
        if reco_items.is_empty() {
            let mut p = reco_params.clone();
            p.insert("recoType".to_string(), "RELATION".to_string());
            reco_items = client.recommend_products(p).await?;
        }

        if reco_items.is_empty() {
            eprintln!("[RECO] 추천 결과 없음(필수 파라미터/카테고리 영향 가능). 멀티 배너/텍스트 생성 스킵");
        } else {
            // 텍스트 광고 (딥링크 강제)
            let textads_limit = 8;
            let reco_top = reco_items.clone().into_iter().take(textads_limit).collect::<Vec<_>>();
            let reco_text_ads = products_to_text_ads_json(&client, reco_top).await?;
            save_json_to_file(&reco_text_ads, out_dir.join("text_ads_reco.json").to_str().unwrap())?;

            // 좌측 배너용 블록 (상위 2개 예시) — 딥링크 강제
            let mut left_blocks: Vec<(String, String, String)> = Vec::new();
            for p in reco_items
                .iter()
                .filter(|p| p.product_url.is_some())
                .take(2)
            {
                let title = truncate_title(p.product_name.as_deref().unwrap_or("상품"), 40);
                let img = p.product_image.as_deref().unwrap_or("").to_string();
                let url = p.product_url.as_deref().unwrap_or("");
                // ★ to_affiliate 적용
                let aff = to_affiliate(&client, url).await;
                left_blocks.push((aff, img, title));
            }

            // 우측/모바일 유닛 여러 개 예시
            let right_units = vec![
                (right_unit_id.to_string(), right_link_unit_id.to_string()),
                ("UNIT_ID_2".to_string(), "LINK_ID_2".to_string()),
            ];
            let mobile_units = vec![
                (mobile_unit_id.to_string(), mobile_link_unit_id.to_string()),
                ("UNIT_ID_M_2".to_string(), "LINK_ID_M_2".to_string()),
            ];

            if !left_blocks.is_empty() {
                let side_multi = build_side_banner_json_multi(left_blocks, right_units, mobile_units);
                save_json_to_file(
                    &side_multi,
                    out_dir.join("side_mobile_multi_reco.json").to_str().unwrap(),
                )?;
                eprintln!("JSON 저장: {}", out_dir.join("side_mobile_multi_reco.json").display());
            } else {
                eprintln!("[RECO] 좌측 배너에 쓸 추천 상품이 부족합니다(이미지/URL 확인).");
            }
        }
    } else {
        eprintln!("[RECO] 기준 product_id 없음 → 추천 패스");
    }

    Ok(())
}

// ---------------- 테스트 (선택) ----------------
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hmac_generation() {
        let client = CoupangApiClient::new(
            "test-access-key".to_string(),
            "test-secret-key".to_string(),
        );
        let result = client.generate_hmac_signature(
            "POST",
            "/v2/providers/affiliate_open_api/apis/openapi/v1/deeplink",
        );
        assert!(result.is_ok());
        let auth_header = result.unwrap();
        assert!(auth_header.contains("CEA algorithm=HmacSHA256"));
        assert!(auth_header.contains("access-key=test-access-key"));
        assert!(auth_header.contains("algorithm=HmacSHA256,access-key=")); // 쉼표 뒤 공백 없음
    }

    #[test]
    fn test_uri_parsing() {
        let client = CoupangApiClient::new("test".to_string(), "test".to_string());
        let ok1 = client.generate_hmac_signature("GET", "/api/test?param=value");
        assert!(ok1.is_ok());
        let ok2 = client.generate_hmac_signature("GET", "/api/test");
        assert!(ok2.is_ok());
        let bad = client.generate_hmac_signature("GET", "/api/test?param1=value1?param2=value2");
        assert!(bad.is_err());
    }

    #[test]
    fn test_json_structures() {
        let text_ads = TextAdsJson {
            ads: vec![TextAdItem {
                kind: "text".to_string(),
                url: "https://link.coupang.com/a/test".to_string(),
                content: "테스트 상품 구매하기".to_string(),
                backgroundColor: "linear-gradient(135deg, #ff6b6b, #ee5a24)".to_string(),
            }],
        };
        let json_str = serde_json::to_string(&text_ads).unwrap();
        assert!(json_str.contains("\"type\":\"text\""));
        assert!(json_str.contains("테스트 상품 구매하기"));
    }

    #[tokio::test]
    async fn test_recommend_products_signature_only() {
        let client = CoupangApiClient::new("test-ak".into(), "test-sk".into());
        let sig = client.generate_hmac_signature(
            "GET",
            "/v2/providers/affiliate_open_api/apis/openapi/v2/products/reco?productId=1&limit=10",
        );
        assert!(sig.is_ok());
    }
}
