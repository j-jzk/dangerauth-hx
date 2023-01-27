package dangerauth;

import haxe.io.Bytes;
import haxe.crypto.Hmac;

class Code {
    public static function generateFromTimestamp(key: Bytes, ?datetime: Date): Bytes {
        if (datetime == null) datetime = Date.now();
        final timecode = Std.int(datetime.getTime() / 30000); // a resolution of 30 seconds
        return generate(key, Bytes.ofString(Std.string(timecode)));
    }

    public static function verifyTimestamp(key: Bytes, code: Bytes): Bool {
        return code.compare(generateFromTimestamp(key)) == 0;
    }

    public static function generate(key: Bytes, data: Bytes): Bytes {
        final hmac = new Hmac(SHA256);
        return hmac.make(key, data);
    }
}
