# helper functions to generate data files for nginx

data_generate()
{
    local dir="$1"
    dd if=/dev/urandom of="$dir/0B.bin"    count=0
    dd if=/dev/urandom of="$dir/100B.bin"  count=1 bs=100
    dd if=/dev/urandom of="$dir/200B.bin"  count=1 bs=200
    dd if=/dev/urandom of="$dir/1KB.bin"   count=1 bs=1KB
    dd if=/dev/urandom of="$dir/10KB.bin"  count=1 bs=10KB
    dd if=/dev/urandom of="$dir/100KB.bin" count=1 bs=100KB
    dd if=/dev/urandom of="$dir/200KB.bin" count=1 bs=200KB
    dd if=/dev/urandom of="$dir/500KB.bin" count=1 bs=500KB
    dd if=/dev/urandom of="$dir/1MB.bin"   count=1 bs=1MB
    dd if=/dev/urandom of="$dir/10MB.bin"  count=1 bs=10MB
    dd if=/dev/urandom of="$dir/100MB.bin" count=1 bs=100MB
}

data_on_tmpfs()
{
    local dir="$1"
    [ -d "$dir" ] && return
    mkdir -p "$dir"
    sudo mount -t tmpfs -o size=512m,noatime tmpfs "$dir"
    data_generate "$dir"
}

data_on_disk()
{
    local dir="$1"
    [ -d "$dir" ] && return
    mkdir -p "$dir"
    data_generate "$dir"
}
