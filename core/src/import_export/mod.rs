pub mod exporters;
pub mod formats;
pub mod parsers;

pub fn detect_vault_format(content: &str) -> &'static str {
    let lower = content.to_lowercase();

    if content.contains("<KeePassFile>") || content.contains("<Group>") || content.contains("<pwentry>") {
        "KeePass"
    } else if content.contains("<safeincloud") || content.contains("<database") {
        "SafeInCloud"
    } else if content.contains("\"db\":") && content.contains("\"entries\":") {
        "Aegis"
    } else if content.contains("\"services\":") && (content.contains("\"secret\":") || content.contains("\"otp\":")) {
        "2FAS"
    } else if content.contains("secret_name,user_name,password") || lower.contains("zohovault") {
        "Zoho"
    } else if content.contains("title,username,password,url,note") || lower.contains("nordpass") {
        "NordPass"
    } else if content.contains("title,login,password,url") || lower.contains("keeperaccount") {
        "Keeper"
    } else if content.contains("secondaryLogin") || lower.contains("dashlane") {
        "Dashlane"
    } else if content.contains("match,login,pwd") || lower.contains("roboform") {
        "RoboForm"
    } else if content.contains("passbolt") {
        "Passbolt"
    } else if content.contains("buttercup") {
        "Buttercup"
    } else if content.contains("api_gateway_secret") || content.contains("tfvars") {
        "Terraform"
    } else if content.contains("DB_CONNECTION_STRING") || content.contains("vault.azure.net") {
        "AzureKV"
    } else if content.contains("otpauth") || content.contains("Proton") {
        "ProtonPass"
    } else if content.contains("Title,URL,Username,Password") {
        "Apple"
    } else if content.contains("name,url,username,password") {
        "Chrome"
    } else if content.contains("url,username,password,totp") {
        "LastPass"
    } else if content.contains("title,username,password") {
        "CSV"
    } else if content.contains("encryptedFor")
        || content.contains("ciphers")
        || content.contains("\"items\":")
    {
        "Bitwarden"
    } else {
        "Orvpass JSON"
    }
}
