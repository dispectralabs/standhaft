//! Faz 0 boru-hatti kaniti: SP1 guest programi.
//! ml-dsa'ya hic dokunmadan kutunun ucu-ucuna calistigini gosterir.
//! Ileride bu dosyanin yerine ML-DSA-65 dogrulamasi gelecek.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let n = sp1_zkvm::io::read::<u32>();
    sp1_zkvm::io::commit(&n);

    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919;
        a = b;
        b = c;
    }

    sp1_zkvm::io::commit(&a);
    sp1_zkvm::io::commit(&b);
}
