use std::io;
use std::path::Path;
use tokio::process::Command;
use std::process::Stdio;

const REMOTE_BIN_DIR: &str = "/usr/bin";
const REMOTE_CONFIG_DIR: &str = "/etc/m_server";
const REMOTE_DATA_DIR: &str = "/var/lib/m_server";
const REMOTE_LOGS_DIR: &str = "/var/log/m_server";

const REMOTE_DB_PATH: &str = "/var/lib/m_server/server.redb";
const REMOTE_BINARY_PATH: &str = "/usr/bin/m_server";
const REMOTE_CONFIG_PATH: &str = "/etc/m_server/m_server.toml";

fn local_binary_path() -> String {
    format!(
        "{}/.local/share/m/deploy/m_server",
        std::env::var("HOME").expect("HOME not set")
    )
}

fn local_template_path() -> String {
    format!(
        "{}/.local/share/m/deploy/m_server.template.toml",
        std::env::var("HOME").expect("HOME not set")
    )
}


pub struct SshCredentials {
    username: String,
    ip: String,
    password: String,
}

impl SshCredentials {
    pub fn new(username: String, ip: String, password: String) -> Self {
        Self {
            username,
            ip,
            password,
        }
    }
}

async fn run_ssh_command(creds: &SshCredentials, remote_cmd: &str) -> io::Result<()> {
    let target = format!("{}@{}", creds.username, creds.ip);

    let status = Command::new("sshpass")
        .arg("-p")
        .arg(&creds.password)
        .arg("ssh")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg(target)
        .arg(remote_cmd)
        .stdin(Stdio::null())
        .status()
        .await?;

    if !status.success() {
        m_core::log_error!("Error running ssh command: {}", remote_cmd);
        return Err(io::Error::new(io::ErrorKind::Other, "Command failed"));
    }

    Ok(())
}

async fn upload_config(creds: &SshCredentials, user_key: &str, admin_key: &str) -> io::Result<()> {
    let template = tokio::fs::read_to_string(local_template_path()).await?;

    let config_content = template
        .replace("{{DB_PATH}}", REMOTE_DB_PATH)
        .replace("{{LOGS_DIR}}", REMOTE_LOGS_DIR)
        .replace("{{USER_KEY}}", user_key)
        .replace("{{ADMIN_KEY}}", admin_key);

    let escaped = config_content.replace("'", "'\\''");
    let cmd = format!("echo '{}' > {}", escaped, REMOTE_CONFIG_PATH);
    run_ssh_command(creds, &cmd).await?;

    m_core::log_info!("Config successfully created at {}", REMOTE_CONFIG_PATH);
    Ok(())
}

async fn upload_file_scp(
    creds: &SshCredentials,
    local_path: &str,
    remote_path: &str,
) -> io::Result<()> {
    let output = Command::new("sshpass")
        .arg("-p")
        .arg(&creds.password)
        .arg("scp")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg(local_path)
        .arg(format!("{}@{}:{}", creds.username, creds.ip, remote_path))
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error uploading file {}: {}", local_path, stderr),
        ));
    }

    m_core::log_info!("File {} successfully uploaded to {}", local_path, remote_path);
    Ok(())
}

pub async fn remove_server(creds: &SshCredentials) -> io::Result<()> {
    let stop_cmd = format!("pkill -f {} || true", REMOTE_BINARY_PATH);
    run_ssh_command(creds, &stop_cmd).await?;

    let remove_binary_cmd = format!("rm -f {}", REMOTE_BINARY_PATH);

    let remove_dirs_cmd = format!(
        "rm -rf {}/* {}/* {}/*",
        REMOTE_CONFIG_DIR, REMOTE_DATA_DIR, REMOTE_LOGS_DIR
    );

    let (binary_result, dirs_result) = tokio::join!(
        run_ssh_command(creds, &remove_binary_cmd),
        run_ssh_command(creds, &remove_dirs_cmd),
    );
    binary_result?;
    dirs_result?;

    m_core::log_info!("Server and all data successfully removed");
    Ok(())
}

async fn upload_files(creds: &SshCredentials, user_key: &str, admin_key: &str) -> io::Result<()> {
    let local_bin = local_binary_path();
    let local_tmpl = local_template_path();

    if !Path::new(&local_bin).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Binary not found: {}", local_bin),
        ));
    }

    if !Path::new(&local_tmpl).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Config template not found: {}", local_tmpl),
        ));
    }

    let mkdir_config_cmd = format!("mkdir -p {}", REMOTE_CONFIG_DIR);
    run_ssh_command(creds, &mkdir_config_cmd).await?;

    let (binary_result, config_result) = tokio::join!(
        upload_file_scp(creds, &local_bin, REMOTE_BINARY_PATH),
        upload_config(creds, user_key, admin_key),
    );
    binary_result?;
    config_result?;

    let chmod_cmd = format!("chmod +x {}", REMOTE_BINARY_PATH);
    run_ssh_command(creds, &chmod_cmd).await?;

    m_core::log_info!("Files successfully uploaded to server");
    Ok(())
}

pub async fn setup_server(creds: &SshCredentials, user_key: &str, admin_key: &str) -> io::Result<()> {
    let mkdir_cmd = format!(
        "mkdir -p {} {} {} {}",
        REMOTE_BIN_DIR, REMOTE_CONFIG_DIR, REMOTE_DATA_DIR, REMOTE_LOGS_DIR
    );
    run_ssh_command(creds, &mkdir_cmd).await?;

    remove_server(creds).await?;

    run_ssh_command(creds, &mkdir_cmd).await?;

    upload_files(creds, user_key, admin_key).await?;

    let ldd_cmd = format!("ldd {}", REMOTE_BINARY_PATH);
    run_ssh_command(creds, &ldd_cmd).await?;

    let run_command = format!("nohup {}", REMOTE_BINARY_PATH);
    run_ssh_command(creds, &run_command).await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let ps_cmd = format!("ps aux | grep {} | grep -v grep", REMOTE_BINARY_PATH);
    run_ssh_command(creds, &ps_cmd).await?;

    m_core::log_info!("Server successfully setup and started");
    Ok(())
}
