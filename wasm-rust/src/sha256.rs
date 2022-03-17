pub struct SHA256 {
    hash: [u32; 8],
    k: [u32; 64],
    binary_msg: String,
}

impl SHA256 {
    pub fn new() -> SHA256 {
        let sha256 = SHA256 {
            hash: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            k: [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
            binary_msg: String::new(),
        };

        return sha256;
    }

    fn input_pre_processing(&self, text: &str) -> String {
        let mut binary = String::new();
        for ch in text.chars() {
            binary += &format!("{:0>8b}", ch as u8)[..];
        }
        let binary_len = format!("{:b}", binary.len());
        binary += "1";


        let trail_zeros = 448 - (binary.len() % 512);
        binary += &format!("{z:0<pr$}", z = 0, pr = trail_zeros)[..];

        binary += &format!("{len:0>pl$}", len = binary_len, pl = 64);

        return binary;
    }

    fn process_chunks(&self, chunk: &str) -> [u32; 64] {
        let mut start = 0;
        let chunk_size = 32;

        let mut w: [u32; 64] = [0; 64];

        let mut i = 0;
        while i != 16 {
            let mut small_chunk = "";
            match self.get_binary_chunk(&chunk, chunk_size, start) {
                (ch, idx) => {
                    small_chunk = ch;
                    start = idx;
                }
            };
            let data = u32::from_str_radix(small_chunk, 2).unwrap();
            w[i] = data as u32;
            i += 1;
        }
        while i != w.len() {
            let s1 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ ((w[i - 15] as u32) >> 3) as u32;
            let s0 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ ((w[i - 2] as u32) >> 10) as u32;
            w[i] = match w[i - 16].overflowing_add(s0) {
                (num, _) => match num.overflowing_add(w[i - 7]) {
                    (num, _) => match num.overflowing_add(s1) {
                        (num, _) => num
                    }
                }
            };
            i += 1;
        }

        return w;
    }

    fn compression(&mut self, w: &[u32; 64]) {
        let mut a = self.hash[0];
        let mut b = self.hash[1];
        let mut c = self.hash[2];
        let mut d = self.hash[3];
        let mut e = self.hash[4];
        let mut f = self.hash[5];
        let mut g = self.hash[6];
        let mut h = self.hash[7];

        let mut i = 0;
        while i != w.len() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            // fix overflow add
            let temp1 = match h.overflowing_add(s1) {
                (num, _) => match num.overflowing_add(ch) {
                    (num, _) => match num.overflowing_add(self.k[i]) {
                        (num, _) => match num.overflowing_add(w[i]) {
                            (num, _) => num
                        }
                    }
                }
            };
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let (temp2, _) = s0.overflowing_add(maj);

            h = g;
            g = f;
            f = e;
            e = match d.overflowing_add(temp1) {
                (num, _) => num
            };
            d = c;
            c = b;
            b = a;
            a = match temp1.overflowing_add(temp2) {
                (num, _) => num
            };

            i += 1;
        }

        self.hash[0] = match self.hash[0].overflowing_add(a) {
            (num, _) => num
        };
        self.hash[1] = match self.hash[1].overflowing_add(b) {
            (num, _) => num
        };
        self.hash[2] = match self.hash[2].overflowing_add(c) {
            (num, _) => num
        };
        self.hash[3] = match self.hash[3].overflowing_add(d) {
            (num, _) => num
        };
        self.hash[4] = match self.hash[4].overflowing_add(e) {
            (num, _) => num
        };
        self.hash[5] = match self.hash[5].overflowing_add(f) {
            (num, _) => num
        };
        self.hash[6] = match self.hash[6].overflowing_add(g) {
            (num, _) => num
        };
        self.hash[7] = match self.hash[7].overflowing_add(h) {
            (num, _) => num
        };
    }

    fn get_binary_chunk<'bin>(&self, msg: &'bin str, chunk_size: usize, start: usize) -> (&'bin str, usize) {
        let end = start + chunk_size;
        return (&msg[start..end], end);
    }

    pub fn generate_hash(&mut self, text: &str) -> String {
        self.binary_msg = self.input_pre_processing(text);

        let chunk_size: usize = 512;
        let mut start = 0;
        let mut i = 0;
        while self.binary_msg.len() / chunk_size != i {
            let mut chunk = "";
            match self.get_binary_chunk(&self.binary_msg, chunk_size, start) {
                (ch, idx) => {
                    chunk = ch;
                    start = idx;
                }
            };

            let w = self.process_chunks(chunk);
            self.compression(&w);
            i += 1;
        };

        let mut digest = String::new();
        for hash in self.hash {
            digest += &format!("{hs:0>pl$x}", hs = hash, pl = 8);
        }

        return digest;
    }
}
