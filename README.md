This code accompanies the paper "Fast Privacy-Preserving Punch Cards" (https://eprint.iacr.org/2020/741.pdf)

`data.txt` contains the evaluation results that appear in the paper. 

If you want to run the code on Android, add NDK according to directions at https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html

To test the code locally, simply run `./build.sh` and then `./cargo/target/release/mybin`. You will need Rust installed. 

The source code is set to run the standard version of our scheme that uses curve25519. To run the mergeable scheme that uses pairings, you will need to change line 45 of `/cargo/src/lib.rs` from `test_type: Tests::Group,` to `test_type: Tests::Pairing,`. 
