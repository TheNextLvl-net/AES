# Advanced Encryption Standard

## How to implement this into your own project

## Gradle example

### Repository Configuration

```gradle
repositories {
    maven("https://repo.thenextlvl.net/releases")
}
```

### Dependencies

```gradle
dependencies {
    implementation("net.thenextlvl.crypto:aes:VERSION")
}
```

Be sure to replace `VERSION` with the latest/desired version from
[our repository](https://repo.thenextlvl.net/#/releases/net/thenextlvl/crypto/aes)

## Usage Example

```java
import net.thenextlvl.crypto.aes.AES;

public class Example {
    public static void main(String[] args) {
        try {
            var secret = new Random().nextBytes(new byte[256 / 8]);
            var aes = new AES(secret);
            var test = aes.encrypt("test");
            System.out.printf("Encrypted: %s", test);
            System.out.printf("Decrypted: %s", aes.decrypt(test));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
