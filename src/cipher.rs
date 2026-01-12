pub mod aes_cbc256 {
    use aes::{
        Aes256,
        cipher::{BlockDecryptMut, KeyIvInit},
    };
    use block_padding::{NoPadding, Iso10126};
    use cbc::Decryptor;

    type Aes256CbcDec = Decryptor<Aes256>;

    pub fn decrypt_aes_256_cbc(
        ciphertext: &[u8],
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>, String> {
        let decryptor = Aes256CbcDec::new(key.into(), iv.into());

        let mut buf = ciphertext.to_vec();
        let decrypted_data = decryptor
            .decrypt_padded_mut::<Iso10126>(&mut buf)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        Ok(decrypted_data.to_vec())
    }
}
