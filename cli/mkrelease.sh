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
rm -rf target/macOS-arrowpaperwallet-v$APP_VERSION
mkdir -p target/macOS-arrowpaperwallet-v$APP_VERSION
cp target/release/arrowpaperwallet target/macOS-arrowpaperwallet-v$APP_VERSION/

# For Windows and Linux, build via docker
docker run --rm -v $(pwd)/..:/opt/arrowpaperwallet rustbuild:latest bash -c "cd /opt/arrowpaperwallet/cli && cargo build --release && cargo build --release --target x86_64-pc-windows-gnu && cargo build --release --target aarch64-unknown-linux-gnu"

# Now sign and zip the binaries
gpg --batch --output target/macOS-arrowpaperwallet-v$APP_VERSION/arrowpaperwallet.sig --detach-sig target/macOS-arrowpaperwallet-v$APP_VERSION/arrowpaperwallet 
cd target
cd macOS-arrowpaperwallet-v$APP_VERSION
gsha256sum arrowpaperwallet > sha256sum.txt
cd ..
zip -r macOS-arrowpaperwallet-v$APP_VERSION.zip macOS-arrowpaperwallet-v$APP_VERSION 
cd ..


#Linux
rm -rf target/linux-arrowpaperwallet-v$APP_VERSION
mkdir -p target/linux-arrowpaperwallet-v$APP_VERSION
cp target/release/arrowpaperwallet target/linux-arrowpaperwallet-v$APP_VERSION/
gpg --batch --output target/linux-arrowpaperwallet-v$APP_VERSION/arrowpaperwallet.sig --detach-sig target/linux-arrowpaperwallet-v$APP_VERSION/arrowpaperwallet
cd target
cd linux-arrowpaperwallet-v$APP_VERSION
gsha256sum arrowpaperwallet > sha256sum.txt
cd ..
zip -r linux-arrowpaperwallet-v$APP_VERSION.zip linux-arrowpaperwallet-v$APP_VERSION 
cd ..


#Windows
rm -rf target/Windows-arrowpaperwallet-v$APP_VERSION
mkdir -p target/Windows-arrowpaperwallet-v$APP_VERSION
cp target/x86_64-pc-windows-gnu/release/arrowpaperwallet.exe target/Windows-arrowpaperwallet-v$APP_VERSION/
gpg --batch --output target/Windows-arrowpaperwallet-v$APP_VERSION/arrowpaperwallet.sig --detach-sig target/Windows-arrowpaperwallet-v$APP_VERSION/arrowpaperwallet.exe
cd target
cd Windows-arrowpaperwallet-v$APP_VERSION
gsha256sum arrowpaperwallet.exe > sha256sum.txt
cd ..
zip -r Windows-arrowpaperwallet-v$APP_VERSION.zip Windows-arrowpaperwallet-v$APP_VERSION 
cd ..


# aarch64 (armv8)
rm -rf target/aarch64-arrowpaperwallet-v$APP_VERSION
mkdir -p target/aarch64-arrowpaperwallet-v$APP_VERSION
cp target/aarch64-unknown-linux-gnu/release/arrowpaperwallet target/aarch64-arrowpaperwallet-v$APP_VERSION/
gpg --batch --output target/aarch64-arrowpaperwallet-v$APP_VERSION/arrowpaperwallet.sig --detach-sig target/aarch64-arrowpaperwallet-v$APP_VERSION/arrowpaperwallet
cd target
cd aarch64-arrowpaperwallet-v$APP_VERSION
gsha256sum arrowpaperwallet > sha256sum.txt
cd ..
zip -r aarch64-arrowpaperwallet-v$APP_VERSION.zip aarch64-arrowpaperwallet-v$APP_VERSION 
cd ..

