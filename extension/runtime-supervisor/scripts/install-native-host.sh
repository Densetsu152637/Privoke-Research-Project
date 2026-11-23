#!/bin/sh
set -eu

browser="${1:-auto}"
case "$browser" in
  auto|opera|chrome|chromium|edge|firefox|all) ;;
  *)
    echo "Usage: sh install-native-host.sh [auto|opera|chrome|chromium|edge|firefox|all]" >&2
    exit 2
    ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
supervisor_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
repository_root=$(CDPATH= cd -- "$supervisor_root/../.." && pwd)
extension_root="$repository_root/extension"
identity_path="$extension_root/extension-identities.json"
python_path="$extension_root/client-runtime/.venv/bin/python"
source_host_path="$supervisor_root/src/native_messaging_host.py"
# The Rust controller (rust/services/runtime-supervisor) is the native host when PRIVOKE_SUPERVISOR_BINARY names its
# executable. Unset, the Python host stays the registered one.
supervisor_binary="${PRIVOKE_SUPERVISOR_BINARY:-}"
if [ -n "$supervisor_binary" ]; then
  python_path="$supervisor_binary"
  source_host_path="$supervisor_binary"
fi

# The frozen backbone and tokenizer of the pretrained contextual encoder (the runtime's PRIVOKE_PRETRAINED_CONTEXT_DIR).
# The browser starts the host with a clean environment, so the value in effect when this installer runs is stored in the
# launcher, which both the Rust controller (it passes it to the Rust worker as --pretrained-context-dir) and the Python
# runtime read. Unset, the launcher carries none and the encoder stays unavailable, as before.
pretrained_context_dir="${PRIVOKE_PRETRAINED_CONTEXT_DIR:-}"
if [ -n "$pretrained_context_dir" ]; then
  case "$pretrained_context_dir" in
    /*) ;;
    *)
      echo "PRIVOKE_PRETRAINED_CONTEXT_DIR must be an absolute path: $pretrained_context_dir" >&2
      exit 1
      ;;
  esac
  if [ ! -d "$pretrained_context_dir" ]; then
    echo "PRIVOKE_PRETRAINED_CONTEXT_DIR is not a directory: $pretrained_context_dir" >&2
    exit 1
  fi
fi

for required_file in "$identity_path" "$python_path" "$source_host_path"; do
  if [ ! -f "$required_file" ]; then
    echo "Required PriVoke file is missing: $required_file" >&2
    exit 1
  fi
done

chromium_extension_id=$(sed -n 's/.*"chromium_extension_id": "\([a-p]*\)".*/\1/p' "$identity_path")
firefox_extension_id=$(sed -n 's/.*"firefox_extension_id": "\([^"]*\)".*/\1/p' "$identity_path")
if [ "${#chromium_extension_id}" -ne 32 ] || [ -z "$firefox_extension_id" ]; then
  echo "PriVoke extension identities are invalid: $identity_path" >&2
  exit 1
fi

system_name=$(uname -s)
case "$system_name" in
  Linux)
    config_root="${XDG_CONFIG_HOME:-$HOME/.config}"
    install_root="${XDG_DATA_HOME:-$HOME/.local/share}/privoke/native-host"
    chrome_dir="$config_root/google-chrome/NativeMessagingHosts"
    chromium_dir="$config_root/chromium/NativeMessagingHosts"
    edge_dir="$config_root/microsoft-edge/NativeMessagingHosts"
    opera_dir="$config_root/opera/NativeMessagingHosts"
    firefox_dir="$HOME/.mozilla/native-messaging-hosts"
    ;;
  Darwin)
    install_root="$HOME/Library/Application Support/PriVoke/NativeHost"
    chrome_dir="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    chromium_dir="$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
    edge_dir="$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
    opera_dir="$HOME/Library/Application Support/com.operasoftware.Opera/NativeMessagingHosts"
    firefox_dir="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
    ;;
  *)
    echo "Unsupported operating system: $system_name" >&2
    exit 1
    ;;
esac

if [ "$browser" = auto ]; then
  if [ -d "${XDG_CONFIG_HOME:-$HOME/.config}/opera" ] || [ -d "$HOME/Library/Application Support/com.operasoftware.Opera" ]; then
    browser=opera
  elif [ -d "$firefox_dir" ]; then
    browser=firefox
  elif [ -d "$chrome_dir" ]; then
    browser=chrome
  else
    browser=all
  fi
fi

# The Rust controller has its own host name so it can be registered beside the Python launcher.
if [ -n "$supervisor_binary" ]; then
  host_name=org.privoke.runtime_controller
else
  host_name=org.privoke.runtime_launcher
fi
mkdir -p "$install_root"
installed_host_path="$install_root/native_messaging_host.py"
launcher_path="$install_root/privoke-native-host"
chromium_manifest_path="$install_root/$host_name.chromium.json"
firefox_manifest_path="$install_root/$host_name.firefox.json"
if [ -z "$supervisor_binary" ]; then
  cp "$source_host_path" "$installed_host_path"
fi

# Writes the text with every single quote as quote, backslash, quote, quote, so that it can sit inside single quotes.
# (Inside the double quotes the shell halves the backslashes, and sed then reads two as one literal backslash.)
escape_shell_single_quotes() {
  printf '%s' "$1" | sed "s/'/'\\\\''/g"
}

escaped_python=$(escape_shell_single_quotes "$python_path")
escaped_host=$(escape_shell_single_quotes "$installed_host_path")
escaped_root=$(escape_shell_single_quotes "$repository_root")
{
  echo '#!/bin/sh'
  printf "export PRIVOKE_REPOSITORY_ROOT='%s'\n" "$escaped_root"
  if [ -n "$pretrained_context_dir" ]; then
    printf "export PRIVOKE_PRETRAINED_CONTEXT_DIR='%s'\n" "$(escape_shell_single_quotes "$pretrained_context_dir")"
  fi
  if [ -n "$supervisor_binary" ]; then
    printf "exec '%s' native-host\n" "$escaped_python"
  else
    printf "exec '%s' '%s'\n" "$escaped_python" "$escaped_host"
  fi
} > "$launcher_path"
chmod 700 "$launcher_path"

cat > "$chromium_manifest_path" <<EOF
{
  "name": "$host_name",
  "description": "Starts the workstation-local PriVoke runtime supervisor.",
  "path": "$launcher_path",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$chromium_extension_id/"]
}
EOF

cat > "$firefox_manifest_path" <<EOF
{
  "name": "$host_name",
  "description": "Starts the workstation-local PriVoke runtime supervisor.",
  "path": "$launcher_path",
  "type": "stdio",
  "allowed_extensions": ["$firefox_extension_id"]
}
EOF

register_manifest() {
  browser_name=$1
  target_dir=$2
  source_manifest=$3
  mkdir -p "$target_dir"
  cp "$source_manifest" "$target_dir/$host_name.json"
  echo "Registered $host_name for $browser_name."
}

register_opera_manifest() {
  register_manifest "Opera" "$opera_dir" "$chromium_manifest_path"
  if [ "$opera_dir" != "$chrome_dir" ]; then
    # Opera documents Chrome's native-host directory as a compatibility lookup.
    register_manifest "Opera compatibility lookup" "$chrome_dir" "$chromium_manifest_path"
  fi
}

case "$browser" in
  opera) register_opera_manifest ;;
  chrome) register_manifest "Chrome" "$chrome_dir" "$chromium_manifest_path" ;;
  chromium) register_manifest "Chromium" "$chromium_dir" "$chromium_manifest_path" ;;
  edge) register_manifest "Microsoft Edge" "$edge_dir" "$chromium_manifest_path" ;;
  firefox) register_manifest "Firefox" "$firefox_dir" "$firefox_manifest_path" ;;
  all)
    register_opera_manifest
    register_manifest "Chrome" "$chrome_dir" "$chromium_manifest_path"
    register_manifest "Chromium" "$chromium_dir" "$chromium_manifest_path"
    register_manifest "Microsoft Edge" "$edge_dir" "$chromium_manifest_path"
    register_manifest "Firefox" "$firefox_dir" "$firefox_manifest_path"
    ;;
esac

echo "Browser selection: $browser"
echo "Chromium-family extension ID: $chromium_extension_id"
echo "Firefox extension ID: $firefox_extension_id"
echo "Fully exit and restart the browser, then reload the unpacked extension."
