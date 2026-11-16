use crate::vault::database;
use orvpass_core::import_export::exporters::{
    aegis::export_aegis_json, aws_sm::export_aws_secrets_json, azure_kv::export_azure_kv_json,
    bitwarden::export_bitwarden_json, buttercup::export_buttercup_json, csv::export_standard_csv,
    dashlane::export_dashlane_json, dotenv::export_dotenv, enpass::export_enpass_json,
    gcp_sm::export_gcp_secrets_json, html::export_standalone_html, k8s::export_k8s_secret,
    keepass_xml::export_keepass_xml, keeper::export_keeper_json, lastpass::export_lastpass_csv,
    nordpass::export_nordpass_csv, onepassword::export_1password_csv, otpauth::export_otpauth_uris,
    passbolt::export_passbolt_csv, proton::export_proton_pass_json,
    roboform::export_roboform_csv, safeincloud::export_safeincloud_xml,
    terraform::export_tfvars_json, twofas::export_2fas_json, vault_hcl::export_vault_kv_json,
    zoho::export_zoho_csv,
};
use std::fs;

pub fn execute(file: &str) {
    execute_category(file, None);
}

pub fn execute_category(file: &str, _category: Option<&str>) {
    let items = database::load_items();
    let lower = file.to_lowercase();

    let (content, format_name) = if lower.ends_with(".html") {
        (export_standalone_html(&items), "Standalone Offline HTML")
    } else if lower.ends_with("1password.csv") {
        (export_1password_csv(&items), "1Password CSV")
    } else if lower.ends_with("lastpass.csv") {
        (export_lastpass_csv(&items), "LastPass CSV")
    } else if lower.ends_with("nordpass.csv") {
        (export_nordpass_csv(&items), "NordPass CSV")
    } else if lower.ends_with("zoho.csv") {
        (export_zoho_csv(&items), "Zoho Vault CSV")
    } else if lower.ends_with("roboform.csv") {
        (export_roboform_csv(&items), "RoboForm CSV")
    } else if lower.ends_with("passbolt.csv") {
        (export_passbolt_csv(&items), "Passbolt CSV")
    } else if lower.ends_with(".csv") {
        (export_standard_csv(&items), "Universal CSV")
    } else if lower.ends_with("bitwarden.json") {
        (export_bitwarden_json(&items), "Bitwarden JSON")
    } else if lower.ends_with("keeper.json") {
        (export_keeper_json(&items), "Keeper JSON")
    } else if lower.ends_with("aegis.json") {
        (export_aegis_json(&items), "Aegis 2FA JSON")
    } else if lower.ends_with("2fas.json") {
        (export_2fas_json(&items), "2FAS JSON")
    } else if lower.ends_with("azure.json") {
        (export_azure_kv_json(&items), "Azure Key Vault JSON")
    } else if lower.ends_with("tfvars.json") {
        (export_tfvars_json(&items), "Terraform JSON")
    } else if lower.ends_with("proton.json") {
        (export_proton_pass_json(&items), "Proton Pass JSON")
    } else if lower.ends_with("dashlane.json") {
        (export_dashlane_json(&items), "Dashlane JSON")
    } else if lower.ends_with("enpass.json") {
        (export_enpass_json(&items), "Enpass JSON")
    } else if lower.ends_with("buttercup.json") {
        (export_buttercup_json(&items), "Buttercup JSON")
    } else if lower.ends_with("aws.json") {
        (export_aws_secrets_json(&items), "AWS Secrets Manager JSON")
    } else if lower.ends_with("gcp.json") {
        (export_gcp_secrets_json(&items), "GCP Secrets Manager JSON")
    } else if lower.ends_with("safeincloud.xml") {
        (export_safeincloud_xml(&items), "SafeInCloud XML")
    } else if lower.ends_with(".xml") {
        (export_keepass_xml(&items), "KeePass XML")
    } else if lower.ends_with(".env") {
        (export_dotenv(&items), "DotEnv")
    } else if lower.ends_with(".yaml") || lower.ends_with(".yml") || lower.contains("k8s") {
        (export_k8s_secret(&items, "orvpass-secrets"), "Kubernetes Secret")
    } else if lower.ends_with(".hcl") {
        (export_vault_kv_json(&items), "HashiCorp Vault HCL")
    } else if lower.ends_with(".txt") {
        (export_otpauth_uris(&items), "OTPAuth URIs")
    } else {
        (
            serde_json::to_string_pretty(&items).unwrap_or_default(),
            "Orvpass Native JSON",
        )
    };

    match fs::write(file, &content) {
        Ok(_) => {
            println!(
                "\x1b[1;38;2;52;211;153m✔ Exported {} vault to '{}' ({} items).\x1b[0m",
                format_name,
                file,
                items.len()
            );
        }
        Err(e) => {
            println!("\x1b[1;38;2;248;113;113m✖ Failed to write export file:\x1b[0m {}", e);
        }
    }
}
