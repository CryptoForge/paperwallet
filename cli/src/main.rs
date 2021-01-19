extern crate clap;
extern crate piratepaperlib;

use clap::{Arg, App};
use piratepaperlib::paper::*;
use piratepaperlib::pdf;
use std::io;
use std::io::prelude::*;

fn main() { 
    let matches = App::new("piratepaperwallet")
       .version("1.1")
       .about("A command line Pirate Sapling paper wallet generator")
       .arg(Arg::with_name("format")
                .short("f")
                .long("format")
                .help("What format to generate the output in: json or pdf")
                .takes_value(true)
                .value_name("FORMAT")
                .possible_values(&["pdf", "json"])
                .default_value("json"))
       .arg(Arg::with_name("nohd")
                .short("n")
                .long("nohd")
                .help("Don't reuse HD keys. Normally, piratepaperwallet will use the same HD key to derive multiple addresses. This flag will use a new seed for each address"))
       .arg(Arg::with_name("output")
                .short("o")
                .long("output")
                .index(1)
                .help("Name of output file."))
       .arg(Arg::with_name("entropy")
                .short("e")
                .long("entropy")
                .takes_value(true)
                .help("Provide additional entropy to the random number generator. Any random string, containing 32-64 characters"))
       .arg(Arg::with_name("z_addresses")
                .short("z")
                .long("zaddrs")
                .help("Number of Z addresses (Sapling) to generate")
                .takes_value(true)
                .default_value("1")                
                .validator(|i:String| match i.parse::<i32>() {
                        Ok(_)   => return Ok(()),
                        Err(_)  => return Err(format!("Number of addresses '{}' is not a number", i))
                }))
       .get_matches();  
    
    let nohd: bool    = matches.is_present("nohd");

    // Get user entropy. 
    let mut entropy: Vec<u8> = Vec::new();
    // If the user hasn't specified any, read from the stdin
    if matches.value_of("entropy").is_none() {
        // Read from stdin
        println!("Provide additional entropy for generating random numbers. Type in a string of random characters (longer the better), press [ENTER] when done");
        let mut buffer = String::new();
        let stdin = io::stdin();
        stdin.lock().read_line(&mut buffer).unwrap();

        entropy.extend_from_slice(buffer.as_bytes());
    } else {
        // Use provided entropy. 
        entropy.extend(matches.value_of("entropy").unwrap().as_bytes());
    }

    // Get the filename and output format
    let filename = matches.value_of("output");
    let format   = matches.value_of("format").unwrap();

    // Writing to PDF requires a filename
    if format == "pdf" && filename.is_none() {
        eprintln!("Need an output file name when writing to PDF");
        return;
    }

    // Number of z addresses to generate
    let num_addresses = matches.value_of("z_addresses").unwrap().parse::<u32>().unwrap();    

    print!("Generating {} Sapling addresses.........", num_addresses);
    io::stdout().flush().ok();
    let addresses = generate_wallet(nohd, num_addresses, &entropy); 
    println!("[OK]");
    
    // If the default format is present, write to the console if the filename is absent
    if format == "json" {
        if filename.is_none() {
            println!("{}", addresses);
        } else {
            std::fs::write(filename.unwrap(), addresses).expect("Couldn't write to file!");
            println!("Wrote {:?} as a plaintext file", filename);
        }
    } else if format == "pdf" {
        // We already know the output file name was specified
        print!("Writing {:?} as a PDF file...", filename.unwrap());
        io::stdout().flush().ok();
        pdf::save_to_pdf(&addresses, filename.unwrap());
        println!("[OK]");
    }    
}
