BULK_CLIENT_MHOST="vma-nolo05"
BULK_SERVER_MHOST=vma-nolo06
BULK_SERVER_DHOST=1.1.63.112

BULK_TYPE="rps"
BULK_PROTOS="http https"
BULK_THREADS="20"
BULK_PAYLOADS="0B 100B 1KB 10KB 100KB 1MB 10MB 100MB"
BULK_CONNECTIONS="2400"
export BULK_STEP_DURATION="300"

# BULK_ENV_LIST as multiline string
read -r -d '' BULK_ENV_LIST << 'EOF' || true
# mode  proto   payload threads connections host       env
*       *       *       *       *           vma-nolo05 default-x86
*       *       *       *       *           vma-nolo06 default-x86
EOF
