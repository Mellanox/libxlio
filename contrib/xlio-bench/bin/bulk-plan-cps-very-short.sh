BULK_CLIENT_MHOST="vma-nolo05"
BULK_SERVER_MHOST=vma-nolo06
BULK_SERVER_DHOST=1.1.63.112

BULK_TYPE="cps"
BULK_PROTOS="http"
BULK_THREADS="20"
BULK_PAYLOADS="0B"
BULK_CONNECTIONS="2400"

# BULK_ENV_LIST as multiline string
read -r -d '' BULK_ENV_LIST << 'EOF' || true
# mode  proto   payload threads connections host       env
*       *       *       *       *           vma-nolo05 default-x86
*       *       *       *       *           vma-nolo06 default-x86
EOF
