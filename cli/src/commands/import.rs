use crate::vault::database;
use orvpass_core::import_export::detect_vault_format;
use orvpass_core::import_export::parsers::{
    aegis::parse_aegis_json, apple::parse_apple_csv, aws_sm::parse_aws_secrets_json,
    azure_kv::parse_azure_kv_json, bitwarden::parse_bitwarden_json, brave::parse_brave_csv,
    buttercup::parse_buttercup_json, chrome::parse_chrome_csv, dashlane::parse_dashlane_csv,
    doppler::parse_doppler_json, dotenv::parse_dotenv_content, edge::parse_edge_csv,
    enpass::parse_enpass_json, firefox::parse_firefox_csv, gcp_sm::parse_gcp_secrets_json,
    infisical::parse_infisical_json, k8s_secret::parse_k8s_secret_json, keepass::parse_keepass_csv,
    keeper::parse_keeper_csv, lastpass::parse_lastpass_csv, nordpass::parse_nordpass_csv,
    onepassword::parse_1password_csv, opera::parse_opera_csv, otpauth::parse_otpauth_uris,
    passbolt::parse_passbolt_json, proton::parse_proton_json, roboform::parse_roboform_csv,
    safeincloud::parse_safeincloud_xml, terraform::parse_tfvars_json, twofas::parse_2fas_json,
    vault_hcl::parse_hashicorp_vault_json, vivaldi::parse_vivaldi_csv, zoho::parse_zoho_csv,
};
use std::fs;

pub fn execute(file: &str) {
    if let Ok(content) = fs::read_to_string(file) {
        let fmt = detect_vault_format(&content);
        println!("📥 Auto-detected format: \x1b[1;38;2;129;140;248m{}\x1b[0m", fmt);

        let mut new_items = match fmt {
            "Bitwarden" => parse_bitwarden_json(&content).unwrap_or_default(),
            "Chrome" => parse_chrome_csv(&content),
            "Apple" => parse_apple_csv(&content),
            "LastPass" => parse_lastpass_csv(&content),
            "1Password" => parse_1password_csv(&content),
            "KeePass" => parse_keepass_csv(&content),
            "NordPass" => parse_nordpass_csv(&content),
            "Keeper" => parse_keeper_csv(&content),
            "Zoho" => parse_zoho_csv(&content),
            "Aegis" => parse_aegis_json(&content),
            "2FAS" => parse_2fas_json(&content),
            "AzureKV" => parse_azure_kv_json(&content),
            "Terraform" => parse_tfvars_json(&content),
            "Dashlane" => parse_dashlane_csv(&content),
            "RoboForm" => parse_roboform_csv(&content),
            "Passbolt" => parse_passbolt_json(&content),
            "Buttercup" => parse_buttercup_json(&content),
            "Enpass" => parse_enpass_json(&content),
            "SafeInCloud" => parse_safeincloud_xml(&content),
            "ProtonPass" => parse_proton_json(&content).unwrap_or_default(),
            "DotEnv" => parse_dotenv_content(&content),
            "Firefox" => parse_firefox_csv(&content),
            "Edge" => parse_edge_csv(&content),
            "Brave" => parse_brave_csv(&content),
            "Opera" => parse_opera_csv(&content),
            "Vivaldi" => parse_vivaldi_csv(&content),
            "AwsSecrets" => parse_aws_secrets_json(&content),
            "GcpSecrets" => parse_gcp_secrets_json(&content),
            "K8sSecret" => parse_k8s_secret_json(&content),
            "VaultHcl" => parse_hashicorp_vault_json(&content),
            "Infisical" => parse_infisical_json(&content),
            "Doppler" => parse_doppler_json(&content),
            "OtpAuth" => parse_otpauth_uris(&content),
            _ => {
                // Try JSON deserialization as native Orvpass vault
                serde_json::from_str(&content).unwrap_or_default()
            }
        };

        let count = new_items.len();
        if count > 0 {
            let mut existing = database::load_items();
            existing.append(&mut new_items);
            let _ = database::save_items(&existing);
            println!(
                "\x1b[1;38;2;52;211;153m✔ Successfully imported {} items from '{}' into encrypted vault.\x1b[0m",
                count, file
            );
        } else {
            println!(
                "\x1b[38;2;251;191;36mℹ️  File '{}' read successfully (0 valid credentials found).\x1b[0m",
                file
            );
        }
    } else {
        println!("\x1b[1;38;2;248;113;113m✖ Error:\x1b[0m Unable to read file '{}'.", file);
    }
}
