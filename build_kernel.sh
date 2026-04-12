#!/bin/bash
# simple build scripts for compiling kernel on this repo
# note:
# change telegram CHATID to yours
# change OUTDIR if needed, by default its using /root directory

##------------------------------------------------------##

Help()
{
  echo "Usage: [--help|-h|-?] [--clone|-c] [--lto] [--img]"
  echo "$0 <defconfig> <token> [Other Args]"
  echo -e "\t--clone: Clone compiler"
  echo -e "\t--lto: Enable Clang LTO"
  echo -e "\t--img: Build boot.img instead of zip flasher"
  echo -e "\t--help: To show this info"
}

##------------------------------------------------------##

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
  --clone|-c)
  CLONE=true
  shift
  ;;
  --lto)
  LTO=true
  shift
  ;;
  --img)
  IMG=true
  shift
  ;;
  --help|-h|-?)
  Help
  exit
  ;;
  *)
  POSITIONAL+=("$1")
  shift
  ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [[ ! -n $2 ]]; then
  echo "ERROR: Enter all needed parameters"
  usage
  exit
fi

CONFIG=$1
TOKEN=$2

echo "This is your setup config"
echo
echo "Using defconfig: ""$CONFIG""_defconfig"
echo "Clone dependencies: $([[ ! -z "$CLONE" ]] && echo "true" || echo "false")"
echo "Enable LTO Clang: $([[ ! -z "$LTO" ]] && echo "true" || echo "false")"
echo "Build boot.img instead of zip: $([[ ! -z "$IMG" ]] && echo "true" || echo "false")"
echo
read -p "Are you sure? " -n 1 -r
! [[ $REPLY =~ ^[Yy]$ ]] && exit
echo

##------------------------------------------------------##

tg_post_msg() {
  curl -s -X POST "$BOT_MSG_URL" -d chat_id="$CHATID" \
       -d "disable_web_page_preview=true" \
       -d "parse_mode=html" \
       -d text="$1"
}

##----------------------------------------------------------------##

tg_post_build() {
  curl --progress-bar -F document=@"$1" "$BOT_BUILD_URL" \
                      -F chat_id="$CHATID"  \
                      -F "disable_web_page_preview=true" \
                      -F "parse_mode=html" \
                      -F caption="$2"
}
##----------------------------------------------------------------##

repack() {
  cd "$KERNEL_DIR/ramdisk" || exit 1
  rm Image.gz
  cp "$OUTDIR"/arch/arm64/boot/Image.gz .
  bash bootimg.sh
  mv *.img "$KNAME"-"${DATE}".img
  cd - || exit
}

setup_ksu_files() {
  local AK_DIR="$OUTDIR/AnyKernel"
  local KSU_BINS="$KERNEL_DIR/KernelSU-Next/userspace/ksud_magic/bin/aarch64"
  local KSUD_URL="https://github.com/KernelSU-Next/KernelSU-Next/releases/download/v3.1.0/aarch64-ksud"

  # Create ksu directory inside AnyKernel
  mkdir -p "$AK_DIR/ksu"

  # Download ksud if not already present
  if [[ ! -f "$AK_DIR/ksu/ksud" ]]; then
    echo "Downloading ksud binary..."
    curl -L -o "$AK_DIR/ksu/ksud" "$KSUD_URL"
  fi

  # Copy pre-built binaries from KernelSU-Next source tree
  for bin in busybox resetprop bootctl; do
    if [[ -f "$KSU_BINS/$bin" ]]; then
      cp "$KSU_BINS/$bin" "$AK_DIR/ksu/$bin"
      echo "Copied $bin"
    else
      echo "WARNING: $bin not found at $KSU_BINS/$bin"
    fi
  done

  chmod 755 "$AK_DIR"/ksu/*

  # Create post-install script to deploy KSU userspace
  cat > "$AK_DIR/ksu_install.sh" << 'KSUSCRIPT'
#!/sbin/sh
# Deploy KernelSU-Next userspace components

OUTFD=$1
ZIPFILE=$2
TMPDIR=/tmp/ksu_install

ui_print() {
  echo "ui_print $1" >> /proc/self/fd/$OUTFD
  echo "ui_print" >> /proc/self/fd/$OUTFD
}

# Extract ksu files from zip
mkdir -p $TMPDIR
unzip -o "$ZIPFILE" "ksu/*" -d $TMPDIR 2>/dev/null

KSU_SRC="$TMPDIR/ksu"

if [ ! -d "$KSU_SRC" ]; then
  ui_print "! WARNING: ksu directory not found in zip"
  rm -rf $TMPDIR
  return 1
fi

# Create directory structure
mkdir -p /data/adb/ksu/bin
mkdir -p /data/adb/ksu/log
mkdir -p /data/adb/ksu/profile/selinux
mkdir -p /data/adb/ksu/profile/templates
mkdir -p /data/adb/modules
mkdir -p /data/adb/modules_update

# Deploy ksud daemon
if [ -f "$KSU_SRC/ksud" ]; then
  cp "$KSU_SRC/ksud" /data/adb/ksud
  chmod 755 /data/adb/ksud
  chown 0:0 /data/adb/ksud
  ln -sf /data/adb/ksud /data/adb/ksu/bin/ksud 2>/dev/null
  ui_print "- Deployed ksud"
else
  ui_print "! WARNING: ksud not found"
fi

# Deploy support binaries
for bin in busybox resetprop bootctl; do
  if [ -f "$KSU_SRC/$bin" ]; then
    cp "$KSU_SRC/$bin" /data/adb/ksu/bin/$bin
    chmod 755 /data/adb/ksu/bin/$bin
    chown 0:0 /data/adb/ksu/bin/$bin
    ui_print "- Deployed $bin"
  fi
done

rm -rf $TMPDIR
KSUSCRIPT
  chmod 755 "$AK_DIR/ksu_install.sh"
}

patch_anykernel_sh() {
  local AK_SCRIPT="$OUTDIR/AnyKernel/anykernel.sh"

  # Check if already patched
  if grep -q "ksu_install.sh" "$AK_SCRIPT" 2>/dev/null; then
    return
  fi

  # Append ksud deployment at end of anykernel.sh
  cat >> "$AK_SCRIPT" << 'PATCH'

## KernelSU-Next: deploy ksud ##
if [ -f "$AKHOME/ksu_install.sh" ]; then
  . "$AKHOME/ksu_install.sh" "$OUTFD" "$ZIPFILE"
fi
PATCH
  echo "Patched anykernel.sh to deploy ksud"
}

zipping() {
  cd "$OUTDIR"/AnyKernel || exit 1
  rm -- *.zip *.gz
  cp "$OUTDIR"/arch/arm64/boot/Image.gz .
  setup_ksu_files
  patch_anykernel_sh
  zip -r9 "[$ZDATE][$CONFIG]$KERVER-$ZIPNAME-$HASH_HEAD.zip" -- *
  cd - || exit
}

##----------------------------------------------------------------##

build_kernel() {
  find "$OUTDIR" -name *.gz *.gz-dtb -delete
  [[ $LTO == true ]] && echo "CONFIG_LTO_CLANG=y" >> arch/arm64/configs/"$DEFCONFIG"
#  [[ $LTO == true ]] && echo "CONFIG_THINLTO=n" >> arch/arm64/configs/"$DEFCONFIG"
  echo "-Genom-R$NAMELTO-$CONFIG" > localversion
  make O="$OUTDIR" ARCH=arm64 "$DEFCONFIG"
  make -j"$PROCS" O="$OUTDIR" \
                  ARCH=arm64 \
                  CC=clang \
                  CROSS_COMPILE=aarch64-linux-gnu- \
                  CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
                  LD=ld.lld \
                  NM=llvm-nm \
                  AR=llvm-ar \
                  OBJCOPY=llvm-objcopy \
                  OBJDUMP=llvm-objdump
}

##----------------------------------------------------------------##

export OUTDIR=/root

if [[ $CLONE == true ]]
then
  echo "Cloning dependencies"
  git clone https://github.com/rama982/clang --depth=1 "$OUTDIR"/clang-llvm
  git clone https://github.com/rama982/AnyKernel3 -b rosemary "$OUTDIR"/AnyKernel
fi

#telegram env
CHATID=-1001459070028
BOT_MSG_URL="https://api.telegram.org/bot$TOKEN/sendMessage"
BOT_BUILD_URL="https://api.telegram.org/bot$TOKEN/sendDocument"

# env
export DEFCONFIG=$CONFIG"_defconfig"
export TZ="Asia/Jakarta"
export KERNEL_DIR=$(pwd)
[[ $LTO == true ]] && export NAMELTO="-LTO"
export ZIPNAME="Genom-R$NAMELTO-BETA"
export ZDATE=$(date "+%m%d")
export KNAME="Genom-R$NAMELTO-$CONFIG-BETA"
export IMAGE="${OUTDIR}/arch/arm64/boot/Image.gz"
export DATE=$(date "+%Y%m%d-%H%M")
export BRANCH="$(git rev-parse --abbrev-ref HEAD)"
export PATH="${OUTDIR}/clang-llvm/bin:${PATH}"
export KBUILD_COMPILER_STRING="$(${OUTDIR}/clang-llvm/bin/clang --version | head -n 1 | perl -pe 's/\(http.*?\)//gs' | sed -e 's/  */ /g')"
export ARCH=arm64
export KBUILD_BUILD_USER=rama982
export HASH_HEAD=$(git rev-parse --short HEAD)
export COMMIT_HEAD=$(git log --oneline -1)
export PROCS=$(nproc --all)
export DISTRO=$(cat /etc/issue)
export KERVER=$(make kernelversion)

# start build
tg_post_msg "
Build is started
<b>OS: </b>$DISTRO
<b>Date : </b>$(date)
<b>Device : </b>$CONFIG
<b>Core Count : </b>$PROCS cores
<b>Branch : </b>$BRANCH
<b>Top Commit : </b>$COMMIT_HEAD
"

BUILD_START=$(date +"%s")

build_kernel

BUILD_END=$(date +"%s")
DIFF=$((BUILD_END - BUILD_START))

if [[ -f $IMAGE ]]
then
  if [[ $IMG == true ]]
  then
    repack
    FILE=$(ls "$KERNEL_DIR"/ramdisk/*.img)
  else
    zipping
    FILE=$(ls "$OUTDIR"/AnyKernel/*.zip)
fi
  tg_post_build "$FILE" "
<b>Build took : </b>$((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)
<b>Kernel Version : </b>$KERVER
<b>Compiler: </b>$(grep LINUX_COMPILER ${OUTDIR}/include/generated/compile.h  |  sed -e 's/.*LINUX_COMPILER "//' -e 's/"$//')
<b>Enable LTO Clang: </b>$([[ ! -z "$LTO" ]] && echo "true" || echo "false")
"
else
  tg_post_msg "<b>Build took : </b>$((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s) but error"
  exit 1
fi

# reset git
git reset --hard HEAD

##----------------*****-----------------------------##
