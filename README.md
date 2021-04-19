This code accompanies the paper "Fast Privacy-Preserving Punch Cards" (https://eprint.iacr.org/2020/741.pdf)

`data.txt` contains the evaluation results that appear in the paper. The performance numbers labeled  "computer" were taken on a laptop with an intel i5-8265U processer @ 1.60 GHz running Ubuntu Linux. The "Google Pixel" numbers were measured on the Google Pixel (first generation) phone. Measurements were taken in spring 2020 with both devices running up to date versions of their respective operating systems. 

If you want to run the code on Android, add NDK according to directions at https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html. Then uncomment the commented lines in `build.sh`

To test the code locally, simply run `./build.sh` and then `./cargo/target/release/mybin`. You will need Rust installed. 

The source code is set to run the standard version of our scheme that uses curve25519. To run the mergeable scheme that uses pairings, you will need to change line 45 of `/cargo/src/lib.rs` from `test_type: Tests::Group,` to `test_type: Tests::Pairing,`. 
