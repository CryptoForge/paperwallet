extern crate printpdf;

use qrcode::QrCode;
use qrcode::types::Color;

use std::io::BufWriter;
use std::convert::From;
use std::f64;
use std::fs::File;
use printpdf::*;

/**
 * Save the list of wallets (address + private keys) to the given PDF file name.
 */
pub fn save_to_pdf(addresses: &str, filename: &str) -> Result<(), String> {
    let (doc, page1, layer1) = PdfDocument::new("Arrow Sapling Paper Wallet", Mm(210.0), Mm(297.0), "Layer 1");

    let font  = doc.add_builtin_font(BuiltinFont::Courier).unwrap();
    let font_bold = doc.add_builtin_font(BuiltinFont::CourierBold).unwrap();

    let keys = json::parse(&addresses).unwrap();

    // Position on the PDF page.
    let mut pos = 0;

    let mut current_layer = doc.get_page(page1).get_layer(layer1);

    let total_pages      = f64::ceil(keys.len() as f64 / 1.0);   // 1 per page
    let mut current_page = 1;

    for kv in keys.members() {
        // Add next page when moving to the next position.
        if pos >= 1 {
            pos = 0;
            current_page = current_page + 1;

            // Add a page
            let (page2, _) = doc.add_page(Mm(210.0), Mm(297.0),"Page 2, Layer 1");
            current_layer = doc.get_page(page2).add_layer("Layer 3");
        }

        // Add address + full viewing key + private key
        add_address_to_page(&current_layer, &font, &font_bold
            , kv["address"].as_str().unwrap()
            , kv["diversified"]["d1"].as_str().unwrap()
            , kv["diversified"]["d2"].as_str().unwrap()
            , kv["diversified"]["d3"].as_str().unwrap()
            , kv["diversified"]["d4"].as_str().unwrap()
            , kv["diversified"]["d5"].as_str().unwrap()
            , pos);
        add_fvk_to_page(&current_layer, &font, &font_bold, kv["viewing_key"].as_str().unwrap(), pos);

        add_pk_to_page(&current_layer, &font, &font_bold
            , kv["private_key"].as_str().unwrap()
            , kv["seed"]["HDSeed"].as_str().unwrap()
            , kv["seed"]["path"].as_str().unwrap()
            , kv["seed"]["Bip39Seed"].as_str().unwrap()
            , kv["seed"]["Phrase"].as_str().unwrap()
            , pos);

        // Is the shape stroked? Is the shape closed? Is the shape filled?
    let line1 = Line {
            points: vec![(Point::new(Mm(5.0), Mm(99.0)), false), (Point::new(Mm(205.0), Mm(99.0)), false)],
            is_closed: true,
            has_fill: false,
            has_stroke: true,
            is_clipping_path: false,
        };

	let line2 = Line {
            points: vec![(Point::new(Mm(5.0), Mm(213.0)), false), (Point::new(Mm(205.0), Mm(213.0)), false)],
            is_closed: true,
            has_fill: false,
            has_stroke: true,
            is_clipping_path: false,
        };

    let line3 = Line {
            points: vec![(Point::new(Mm(5.0), Mm(133.0)), false), (Point::new(Mm(205.0), Mm(133.0)), false)],
            is_closed: true,
            has_fill: false,
            has_stroke: true,
            is_clipping_path: false,
        };

        let outline_color = printpdf::Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None));

        current_layer.set_outline_color(outline_color);
        current_layer.set_outline_thickness(2.0);

	// Set title
	current_layer.use_text("Arrow Paper Waller", 32.0, Mm(37.0), Mm(277.0), &font_bold);

        // Draw lines
        current_layer.add_shape(line1);
        current_layer.add_shape(line2);
        current_layer.add_shape(line3);

        // Add footer of page, only once for each pair of addresses
        if pos == 0 {
            add_footer_to_page(&current_layer, &font, &format!("Page {} of {}", current_page, total_pages));
        }

        // Add to the position to move to the next set, but remember to add a new page every 2 wallets
        // We'll add a new page at the start of the loop, so we add it to the PDF only if required.
        pos = pos + 1;
    };

    let file = match File::create(filename) {
        Ok(f)  => f,
        Err(e) => {
            return Err(format!("Couldn't open {} for writing. Aborting. {}", filename, e));
        }
    };

    match doc.save(&mut BufWriter::new(file)) {
        Ok(_)   => (),
        Err(e)  => {
            return Err(format!("Couldn't save {}. Aborting. {}", filename, e));
        }
    };

    return Ok(());
}

/**
 * Generate a qrcode. The outout is a vector of RGB values of size (qrcode_modules * scalefactor) + padding
 */
fn qrcode_scaled(data: &str, scalefactor: usize) -> (Vec<u8>, usize) {
    let code = QrCode::new(data.as_bytes()).unwrap();
    let output_size = code.width();

    let imgdata = code.to_colors();

    // Add padding around the QR code, otherwise some scanners can't seem to read it.
    let padding     = 10;
    let scaledsize  = output_size * scalefactor;
    let finalsize   = scaledsize + (2 * padding);

    // Build a scaled image
    let scaledimg: Vec<u8> = (0..(finalsize*finalsize)).flat_map( |i| {
        let x = i / finalsize;
        let y = i % finalsize;
        if x < padding || y < padding || x >= (padding+scaledsize) || y >= (padding+scaledsize) {
            vec![255u8; 3]
        } else {
            if imgdata[(x - padding)/scalefactor * output_size + (y - padding)/scalefactor] != Color::Light {vec![0u8; 3] } else { vec![255u8; 3] }
        }
    }).collect();

    return (scaledimg, finalsize);
}

/**
 * Add a footer at the bottom of the page
 */
fn add_footer_to_page(current_layer: &PdfLayerReference, font: &IndirectFontRef, footer: &str) {
    current_layer.use_text(footer, 10.0, Mm(5.0), Mm(5.0), &font);
}


/**
 * Add the address section to the PDF at `pos`. Note that each page can fit only 2 wallets, so pos has to effectively be either 0 or 1.
 */
fn add_address_to_page(current_layer: &PdfLayerReference, font: &IndirectFontRef, font_bold: &IndirectFontRef, address: &str, d1: &str, d2: &str, d3: &str, d4: &str, d5: &str, pos: u32) {
    let (scaledimg, finalsize) = qrcode_scaled(address, 10);

    //         page_height  top_margin  vertical_padding  position
    let ypos = 297.0        - 5.0       - 57.0            - (140.0 * pos as f64);
    add_qrcode_image_to_page(current_layer, scaledimg, finalsize, Mm(10.0), Mm(ypos));

    current_layer.use_text("ARW Receiving Address (Sapling)", 14.0, Mm(55.0), Mm(ypos+27.5), &font_bold);

    let strs = split_to_max(&address, 39, 39);  // No spaces, so user can copy the address
    for i in 0..strs.len() {
        current_layer.use_text(strs[i].clone(), 12.0, Mm(55.0), Mm(ypos+20.0-((i*5) as f64)), &font);
    }

    current_layer.use_text("ARW Diversified Addresses (Sapling)", 12.0, Mm(55.0), Mm(ypos+6.0), &font_bold);
    current_layer.use_text(d1, 8.5, Mm(55.0), Mm(ypos+1.5), &font);
    current_layer.use_text(d2, 8.5, Mm(55.0), Mm(ypos-2.0), &font);
    current_layer.use_text(d3, 8.5, Mm(55.0), Mm(ypos-5.5), &font);
    current_layer.use_text(d4, 8.5, Mm(55.0), Mm(ypos-9.0), &font);
    current_layer.use_text(d5, 8.5, Mm(55.0), Mm(ypos-12.5), &font);
}

/**
 * Add the full viewing key (aka viewing key) section to the PDF.
 */
fn add_fvk_to_page(current_layer: &PdfLayerReference, font: &IndirectFontRef, font_bold: &IndirectFontRef, fvk: &str, pos: u32) {
    let (scaledimg, finalsize) = qrcode_scaled(fvk, 10);

    //         page_height  top_margin  vertical_padding  position
    let ypos = 297.0        - 5.0       - 150.0            - (140.0 * pos as f64);
    add_qrcode_image_to_page(current_layer, scaledimg, finalsize, Mm(10.0), Mm(ypos));

    current_layer.use_text("Viewing Key (for view-only wallet)", 14.0, Mm(75.0), Mm(ypos+51.0), &font_bold);
    current_layer.use_text("Keep private!", 14.0, Mm(75.0), Mm(ypos+45.0), &font_bold);

    let strs = split_to_max(&fvk, 45, 45);  // No spaces, so user can copy the fvk
    for i in 0..strs.len() {
        current_layer.use_text(strs[i].clone(), 12.0, Mm(75.0), Mm(ypos+35.0-((i*5) as f64)), &font);
    }
}

/**
 * Add the private key section to the PDF at `pos`, which can effectively be only 0 or 1.
 */
fn add_pk_to_page(current_layer: &PdfLayerReference, font: &IndirectFontRef, font_bold: &IndirectFontRef, pk: &str, seed: &str, path: &str, bip39: &str, phrase: &str, pos: u32) {
    let (scaledimg, finalsize) = qrcode_scaled(pk, 10);

    //         page_height  top_margin  vertical_padding  position
    let ypos = 297.0        - 5.0       - 242.0           - (140.0 * pos as f64);
    add_qrcode_image_to_page(current_layer, scaledimg, finalsize, Mm(138.0), Mm(ypos-17.5));

    current_layer.use_text("Seed Phrase", 14.0, Mm(10.0), Mm(ypos+75.5), &font_bold);
    let words: Vec<&str> = phrase.split_whitespace().collect();

    if words.len() == 24 {
        let words_line1 = format!("{} {} {} {} {} {} {} {}", words[0], words[1], words[2], words[3], words[4], words[5],words[6], words[7]);
        let words_line2 = format!("{} {} {} {} {} {} {} {}", words[8], words[9], words[10], words[11], words[12], words[13], words[14], words[15]);
        let words_line3 = format!("{} {} {} {} {} {} {} {}", words[16], words[17], words[18], words[19], words[20], words[21], words[22], words[23]);

        current_layer.use_text(words_line1.clone(), 12.0, Mm(10.0), Mm(ypos+65.0-((0*5) as f64)), &font);
        current_layer.use_text(words_line2.clone(), 12.0, Mm(10.0), Mm(ypos+65.0-((1*5) as f64)), &font);
        current_layer.use_text(words_line3.clone(), 12.0, Mm(10.0), Mm(ypos+65.0-((2*5) as f64)), &font);
    } else {
        current_layer.use_text(phrase.clone(), 12.0, Mm(10.0), Mm(ypos+65.0-((0*5) as f64)), &font);
    }

    current_layer.use_text("Private Key", 14.0, Mm(10.0), Mm(ypos+32.5), &font_bold);
    let strs = split_to_max(&pk, 45, 45);   // No spaces, so user can copy the private key
    for i in 0..strs.len() {
        current_layer.use_text(strs[i].clone(), 12.0, Mm(10.0), Mm(ypos+25.0-((i*5) as f64)), &font);
    }

    // And add the seed too.

    current_layer.use_text(format!("HDSeed: {}, Path: {}", seed, path).as_str(), 8.0, Mm(10.0), Mm(ypos-25.0), &font);

    current_layer.use_text(format!("Bip39Seed:").as_str(), 8.0, Mm(10.0), Mm(ypos-29.0), &font);
    let strs = split_to_max(&bip39, 64, 64);   // No spaces, so user can copy the private key
    for i in 0..strs.len() {
        current_layer.use_text(strs[i].clone(), 8.0, Mm(29.0), Mm(ypos-29.0-((i*3) as f64)), &font);
    }
}

/**
 * Insert the given QRCode into the PDF at the given x,y co-ordinates. The qr code is a vector of RGB values.
 */
fn add_qrcode_image_to_page(current_layer: &PdfLayerReference, qr: Vec<u8>, qrsize: usize, x: Mm, y: Mm) {
    // you can also construct images manually from your data:
    let image_file_2 = ImageXObject {
            width: Px(qrsize),
            height: Px(qrsize),
            color_space: ColorSpace::Rgb,
            bits_per_component: ColorBits::Bit8,
            interpolate: true,
            /* put your bytes here. Make sure the total number of bytes =
            width * height * (bytes per component * number of components)
            (e.g. 2 (bytes) x 3 (colors) for RGB 16bit) */
            image_data: qr,
            image_filter: None, /* does not work yet */
            clipping_bbox: None, /* doesn't work either, untested */
    };

    let image2 = Image::from(image_file_2);
    image2.add_to_layer(current_layer.clone(), Some(x), Some(y), None, None, None, None);
}

/**
 * Split a string into multiple lines, each with a `max` length and add spaces in each line at `blocksize` intervals
 */
fn split_to_max(s: &str, max: usize, blocksize: usize) -> Vec<String> {
    let mut ans: Vec<String> = Vec::new();

    // Split into lines.
    for i in 0..((s.len() / max)+1) {
        let start = i * max;
        let end   = if start + max > s.len() { s.len() } else { start + max };

        let line = &s[start..end];

        // Now, add whitespace into the individual lines to better readability.
        let mut spaced_line = String::default();
        for j in 0..((line.len() / blocksize)+1) {
            let start = j * blocksize;
            let end   = if start + blocksize > line.len() {line.len()} else {start + blocksize};

            spaced_line.push_str(" ");
            spaced_line.push_str(&line[start..end]);
        }

        // If there was nothing to split in the blocks, just add the whole line
        if spaced_line.is_empty() {
            spaced_line = line.to_string();
        }

        ans.push(spaced_line.trim().to_string());
    }

    // Add spaces
    return ans;
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_split() {
        use crate::pdf::split_to_max;
        assert_eq!(split_to_max("a", 1, 1).join("\n"), "a\n");

        // Test the address splitting using max/blocksize we'll know we use
        let addr = "ztestsapling1w00pdjthkzmzgut4c3y7hu6q6c8ferjczyvc03xwu0rvdgtre8a25em5w3w6jxghvcar5jzehnn";
        assert_eq!(split_to_max(addr, 44, 8).join("\n"), "ztestsap ling1w00 pdjthkzm zgut4c3y 7hu6q6c8 ferj\nczyvc03x wu0rvdgt re8a25em 5w3w6jxg hvcar5jz ehnn\n");
        assert_eq!(split_to_max(addr, 44, 8).join(" ").replace(" ", ""), addr);
        assert_eq!(split_to_max(addr, 42, 8).join(" ").replace(" ", ""), addr);
        assert_eq!(split_to_max(addr, 39, 39).join(" ").replace(" ", ""), addr);

        // Test the PK splitting using max/blocksize we'll know we use
        let pk = "secret-extended-key-test1qj7vst8eqqqqqqpu2w6r0p2ykewm95h3d28k7r7y87e9p4v5zhzd4hj2y57clsprjveg997vqk7ak9tr2pnyyxmfzyzs6dhtuflt3aea9srp08teskpqfy2dtm07n08z3dyra407xumf3fk9ds4x06rzur7mgfyu39krj2g28lsxsxtv7swzu0j9vw4qf8rn5z72ztgeqj6u5zehylqm75c7d3um9ds9zvek4tdyta7qhln5fkc0dks6qwmkvr48fvgucpc3542kmdc97uqzt";
        assert_eq!(split_to_max(pk, 44, 8).join(" ").replace(" ", ""),  pk);
        assert_eq!(split_to_max(pk, 45, 10).join(" ").replace(" ", ""), pk);
        assert_eq!(split_to_max(pk, 45, 45).join(" ").replace(" ", ""), pk);

        // Test random combinations of block size and spaces to ensure that
        // the string is always preserved
        for m in 1..100 {
            for b in 1..40 {
                assert_eq!(split_to_max(addr, m, b).join(" ").replace(" ", ""), addr);
                assert_eq!(split_to_max(pk, m, b).join(" ").replace(" ", ""), pk);
            }
        }
    }
}
