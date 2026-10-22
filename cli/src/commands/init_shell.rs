pub fn generate_shell_init() {
    #[cfg(windows)]
    {
        println!(r#"# Orvpass Windows PowerShell Fast Shortcuts
Set-Alias op orvpass
function opg { orvpass get $args }
function opc { orvpass cp $args }
function opcu { orvpass cpu $args }
function opct { orvpass cpt $args }
function opl { orvpass list $args }
function opgen { orvpass generate $args }
"#);
    }
    #[cfg(not(windows))]
    {
        println!(r#"# Orvpass Shell Fast Shortcuts
alias op='orvpass'
alias opg='orvpass get'
alias opc='orvpass cp'
alias opcu='orvpass cpu'
alias opct='orvpass cpt'
alias opl='orvpass list'
alias opgen='orvpass generate'
"#);
    }
}
