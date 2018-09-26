#!/usr/bin/env bash

exec > /var/log/01_start_concourse_web.log 2>&1
set -x

sudo modprobe tcp_bbr
sudo modprobe sch_fq
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

DD_API_KEY=244fc329b0286054289f94c8e03f147a bash -c "$(curl -L https://raw.githubusercontent.com/DataDog/datadog-agent/master/cmd/agent/install_script.sh)"

CONCOURSE_PATH=/var/lib/concourse

mkdir -p $CONCOURSE_PATH

echo "${session_signing_key}" > $CONCOURSE_PATH/session_signing_key
echo "${tsa_host_key}" > $CONCOURSE_PATH/tsa_host_key
echo "${tsa_authorized_keys}" > $CONCOURSE_PATH/tsa_authorized_keys
echo "${postgres_data_source}" > $CONCOURSE_PATH/postgres_data_source
echo "${external_url}" > $CONCOURSE_PATH/external_url
echo "${github_auth_organizations}" > $CONCOURSE_PATH/github_auth_organizations
echo "${github_auth_teams}" > $CONCOURSE_PATH/github_auth_teams
echo "${github_auth_users}" > $CONCOURSE_PATH/github_auth_users
echo "${vault_url}" > $CONCOURSE_PATH/vault_url
echo "${vault_ca_cert}" > $CONCOURSE_PATH/vault_ca_cert
echo "${vault_client_token}" > $CONCOURSE_PATH/vault_client_token

curl http://169.254.169.254/latest/meta-data/local-ipv4 > $CONCOURSE_PATH/peer_ip

if [ "z${basic_auth_username}" != "z" ]; then
  BASIC_AUTH_OPTS="--basic-auth-username ${basic_auth_username} --basic-auth-password ${basic_auth_password}"
fi

VAULT_OPTS=()
if [ "z${vault_url}" != "z" ]; then
  VAULT_OPTS+=("--vault-url")
  VAULT_OPTS+=("${vault_url}")
fi
if [ "z${vault_ca_cert}" != "z" ]; then
  VAULT_OPTS+=("--vault-ca-cert")
  VAULT_OPTS+=("${vault_ca_cert}")
fi
if [ "z${vault_client_token}" != "z" ]; then
  VAULT_OPTS+=("--vault-client-token")
  VAULT_OPTS+=("${vault_client_token}")
fi

GITHUB_AUTH_OPTS=()
if [ "z${github_auth_client_id}" != "z" ]; then
  GITHUB_AUTH_OPTS+=("--github-client-id")
  GITHUB_AUTH_OPTS+=("${github_auth_client_id}")
  GITHUB_AUTH_OPTS+=("--github-client-secret")
  GITHUB_AUTH_OPTS+=("${github_auth_client_secret}")

  if [ "z${github_auth_organizations}" != "z" ]; then
    str="${github_auth_organizations}"
    IFS_ORIGINAL="$$IFS"
    IFS=,
    arr=($$str)
    IFS="$$IFS_ORIGINAL"
    for o in "$${arr[@]}"; do
      GITHUB_AUTH_OPTS+=("--main-team-github-org")
      GITHUB_AUTH_OPTS+=("$$o")
    done
  fi
  if [ "z${github_auth_teams}" != "z" ]; then
    str="${github_auth_teams}"
    IFS_ORIGINAL="$$IFS"
    IFS=,
    arr=($$str)
    IFS="$$IFS_ORIGINAL"
    for t in "$${arr[@]}"; do
      GITHUB_AUTH_OPTS+=("--main-team-github-team")
      GITHUB_AUTH_OPTS+=("$$t")
    done
  fi
  if [ "z${github_auth_users}" != "z" ]; then
    str="${github_auth_users}"
    IFS_ORIGINAL="$$IFS"
    IFS=,
    arr=($$str)
    IFS="$$IFS_ORIGINAL"
    for u in "$${arr[@]}"; do
      GITHUB_AUTH_OPTS+=("--main-team-github-user")
      GITHUB_AUTH_OPTS+=("$$u")
    done
  fi
fi

cd $CONCOURSE_PATH

concourse web --session-signing-key session_signing_key \
  --tsa-host-key tsa_host_key --tsa-authorized-keys tsa_authorized_keys \
  --external-url $(cat external_url) \
  --postgres-data-source $(cat postgres_data_source) \
  --default-build-logs-to-retain 50 \
  --datadog-agent-host=127.0.0.1 \
  --datadog-agent-port=8125 \
  --datadog-prefix=concourse \
  $BASIC_AUTH_OPTS \
  "$${GITHUB_AUTH_OPTS[@]}" \
  "$${VAULT_OPTS[@]}" \
  2>&1 > $CONCOURSE_PATH/concourse_web.log &

echo $! > $CONCOURSE_PATH/pid
