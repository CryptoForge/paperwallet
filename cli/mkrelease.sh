#!/bin/bash
# This script depends on a docker image already being built
# To build it, 
# cd docker
# docker build --tag rustbuild:latest .

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -v|--version)
    APP_VERSION="$2"
    shift # past argument
    shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [ -z $APP_VERSION ]; then echo "APP_VERSION is not set"; exit 1; fi

# Clean everything first
cargo clean

# Compile for mac directly
cargo build --release 

# macOS
rm -rf target/macOS-zeropaperwallet-v$APP_VERSION
mkdir -p target/macOS-zeropaperwallet-v$APP_VERSION
cp target/release/zeropaperwallet target/macOS-zeropaperwallet-v$APP_VERSION/

# For Windows and Linux, build via docker
docker run --rm -v $(pwd)/..:/opt/zeropaperwallet rustbuild:latest bash -c "cd /opt/zeropaperwallet/cli && cargo build --release && cargo build --release --target x86_64-pc-windows-gnu && cargo build --release --target aarch64-unknown-linux-gnu"

# Now sign and zip the binaries
gpg --batch --output target/macOS-zeropaperwallet-v$APP_VERSION/zeropaperwallet.sig --detach-sig target/macOS-zeropaperwallet-v$APP_VERSION/zeropaperwallet 
cd target
cd macOS-zeropaperwallet-v$APP_VERSION
gsha256sum zeropaperwallet > sha256sum.txt
cd ..
zip -r macOS-zeropaperwallet-v$APP_VERSION.zip macOS-zeropaperwallet-v$APP_VERSION 
cd ..


#Linux
rm -rf target/linux-zeropaperwallet-v$APP_VERSION
mkdir -p target/linux-zeropaperwallet-v$APP_VERSION
cp target/release/zeropaperwallet target/linux-zeropaperwallet-v$APP_VERSION/
gpg --batch --output target/linux-zeropaperwallet-v$APP_VERSION/zeropaperwallet.sig --detach-sig target/linux-zeropaperwallet-v$APP_VERSION/zeropaperwallet
cd target
cd linux-zeropaperwallet-v$APP_VERSION
gsha256sum zeropaperwallet > sha256sum.txt
cd ..
zip -r linux-zeropaperwallet-v$APP_VERSION.zip linux-zeropaperwallet-v$APP_VERSION 
cd ..


#Windows
rm -rf target/Windows-zeropaperwallet-v$APP_VERSION
mkdir -p target/Windows-zeropaperwallet-v$APP_VERSION
cp target/x86_64-pc-windows-gnu/release/zeropaperwallet.exe target/Windows-zeropaperwallet-v$APP_VERSION/
gpg --batch --output target/Windows-zeropaperwallet-v$APP_VERSION/zeropaperwallet.sig --detach-sig target/Windows-zeropaperwallet-v$APP_VERSION/zeropaperwallet.exe
cd target
cd Windows-zeropaperwallet-v$APP_VERSION
gsha256sum zeropaperwallet.exe > sha256sum.txt
cd ..
zip -r Windows-zeropaperwallet-v$APP_VERSION.zip Windows-zeropaperwallet-v$APP_VERSION 
cd ..


# aarch64 (armv8)
rm -rf target/aarch64-zeropaperwallet-v$APP_VERSION
mkdir -p target/aarch64-zeropaperwallet-v$APP_VERSION
cp target/aarch64-unknown-linux-gnu/release/zeropaperwallet target/aarch64-zeropaperwallet-v$APP_VERSION/
gpg --batch --output target/aarch64-zeropaperwallet-v$APP_VERSION/zeropaperwallet.sig --detach-sig target/aarch64-zeropaperwallet-v$APP_VERSION/zeropaperwallet
cd target
cd aarch64-zeropaperwallet-v$APP_VERSION
gsha256sum zeropaperwallet > sha256sum.txt
cd ..
zip -r aarch64-zeropaperwallet-v$APP_VERSION.zip aarch64-zeropaperwallet-v$APP_VERSION 
cd ..

