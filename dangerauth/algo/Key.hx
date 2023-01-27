package dangerauth;

#if (crypto && trandom)
import trandom.TargetRandom;
import haxe.crypto.Sha256;
import haxe.crypto.TwoFish;
import haxe.io.Bytes;
import haxe.crypto.mode.Mode;
import haxe.crypto.padding.Padding;

class Key {
    private static final KEY_LEN = 512;
    private static final NONCE_LEN = 16;

    private static function randomBytes(len: Int): Bytes {
        final bytes = Bytes.alloc(len);
        for (i in 0..(len >> 2)) {
            bytes.setInt32(i<<2, TargetRandom.random());
        }
        return bytes;
    }

    public static function generateKey(): Bytes
        return randomBytes(KEY_LEN);

    public static function encryptKey(key: Bytes, password: String): Bytes {
        final nonce = randomBytes(NONCE_LEN);

        final tf = new TwoFish();
        tf.init(Sha256.make(Bytes.ofString(password)), nonce);
        return tf.encrypt(Mode.CBC, key, Padding.PKCS7);
    }

    public static function decryptKey(encrypted: Bytes, password: String): Bytes {
        final nonce = encrypted.sub(0, NONCE_LEN);
        final key = encrypted.sub(NONCE_LEN, key.length - NONCE_LEN);

        final tf = new TwoFish();
        tf.init(Sha256.make(Bytes.ofString(password)), nonce);
        return tf.decrypt(Mode.CBC, key, Padding.PKCS7);
    }
}

#else
class Key {}
#end
