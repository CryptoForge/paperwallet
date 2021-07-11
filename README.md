# zeropaperwallet
zeropaperwallet is a Zero paper wallet generator that can run completely offline. You can run it on an air-gapped computer to generate your shielded z-addresses, which will allow you to keep your keys completely offline.

# Download
zeropaperwallet is available as pre-built binaries from our [release page](https://github.com/cryptoforge/paperwallet/releases). Download the zip file for your platform, extract it and run the `./zeropaperwallet` binary.

# Generating wallets
To generate a zero paper wallet, simply run `./zeropaperwallet`

You'll be asked to type some random characters that will add entropy to the random number generator. Run with `--help` to see all options

# Recovering wallets
To recover addresses from 24 word seed phrase run `./zeropaperwallet -p <seed phrase>`

To recover addresses from an HDSeed run `./zeropaperwallet -s <HDSeed>`

## Saving as PDFs
To generate a zero paper wallet and save it as a PDF, run
`./zeropaperwallet -z 3 --format pdf zeropaper-output.pdf`

This will generate 3 shielded z-addresses and their corresponding private keys, and save them in a PDF file called `zeropaper-output.pdf`

## Vanity Addresses
You can generate a "vanity address" (that is, an address starting with a given prefix) by specifying a `--vanity` argument with the prefix you want.

Note that generating vanity addresses with a prefix longer than 4-5 characters is computationally expensive. You can run it on multiple CPUs on your computer by specifying the `--threads` option.

# Compiling from Source
zeropaperwallet is built with rust. To compile from source, you [install Rust](https://www.rust-lang.org/tools/install). Basically, you need to:
```
curl https://sh.rustup.rs -sSf | sh
```
Checkout the zeropaperwallet repository and build the CLI
```
git clone https://github.com/cryptoforge/paperwallet.git
cd paperwallet/cli
cargo build --release
```

The binary is available in the `zeropaperwallet/cli/target/release` folder.

## Run without network
If you are running a newish version of Linux, you can be doubly sure that the process is not contacting the network by running zeropaperwallet without the network namespace.

```
sudo unshare -n ./target/release/zeropaperwallet
```
`unshare -n` runs the process without a network interface which means you can be sure that your data is not being sent across the network.


## Help options
```
zeropaperwallet 0.4
A command line Zero paper wallet generator

USAGE:
    zeropaperwallet [FLAGS] [OPTIONS] [output]

FLAGS:
    -h, --help       Prints help information
    -b, --nobip39    Disable creating and using a 64-byte Bip39seed and 24 word seed phrase
    -n, --nohd       Don't reuse HD keys. Normally, zeropaperwallet will use the same HD key to derive multiple
                     addresses. This flag will use a new seed for each address
    -V, --version    Prints version information

OPTIONS:
    -c, --cointype <BIP44CoinType>    The Bip44 coin type used in the derivation path [default: 323]
    -e, --entropy <entropy>           Provide additional entropy to the random number generator. Any random string,
                                      containing 32-64 characters
    -f, --format <FORMAT>             What format to generate the output in: json or pdf [default: json]  [possible
                                      values: pdf, json]
    -s, --hdseed <hdseed>             Generate Wallet from 32 byte hex HDSeed
    -p, --phrase <phrase>             Generate Wallet from 24 word seed phrase
    -t, --taddrs <t_addresses>        Number of t addresses to generate [default: 0]
        --threads <threads>           Number of threads to use for the vanity address generator. Set this to the number
                                      of CPUs you have [default: 1]
        --vanity <vanity_prefix>      Generate a vanity address with the given prefix
    -z, --zaddrs <z_addresses>        Number of Z addresses (Sapling) to generate [default: 1]

ARGS:
    <output>    Name of output file.
```
