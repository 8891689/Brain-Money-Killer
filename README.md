# Brain Money Killer

Note that this is a forked modification and reimplementation https://github.com/vladkens/ecloop

A high-performance, CPU-optimized tool with the ability to search compressed and uncompressed addresses, 
as well as customizable puzzle-based searches for private keys and brainwallet searches.


# Features
1. 🍏 Fixed 256-bit modulo operations, fixed a private key partitioning issue, fixed the secp256k1 core, improved speed, and used AVX2 sha256 and ripemd160 2. for high-speed computation.
3. 🔄 Group inversion of point addition
4. 🍇 Precomputed tables for integral multiplication
5. 🔍 Search for compressed and uncompressed public keys (hash160)
6. 🌟 Optimized sha256 and ripemd160 using SIMD and AVX2 (using SHA extensions for ARM and Intel)
7. 🍎 Runs seamlessly on macOS and Linux
8. 🔧 Customizable search range and number of threads for flexible usage


Build
```
make
```
Clean and rebuild
```
make clean
```
Note: This has been tested with clang but has not been thoroughly tested.

# usage
```
./Brainmk -h
Usage: ./Brainmk -m <mode> [options]
v8891689, developed by 8891689

Modes (-m):
  puzzle          Puzzle solving mode. Searches for keys in a given range.
  brain           Brainwallet mode. Reads keys or passphrases from standard input.
  bloom           Generate a bloom filter from stdin.

Common Options:
  -b <file>       Bloom filter file for quick checks.
  -f <file>       Hash list file for final confirmation.
  -o <file>       Output file for found keys (default: stdout).
  -t <threads>    Number of threads to use (default: 1).
  -a <addr_type>  Address type: 'c' (compressed), 'u' (uncompressed), 'cu' (both). Default: c.
  -q              Quiet mode (no status updates to stdout).

Puzzle Mode Options:
  -r <start:end>  Search range in hexadecimal format (required for puzzle mode).
  -R              Enable random mode. Jump to a new random key after approximately 100 million checks. P.S.: Now jump to a new random key after 1 million private keys.

Brain Mode Options:
  -sha            Treat stdin lines as passphrases, hash them with SHA256 to get private keys.




Other commands:

  bloom         - create bloom filter from list of hex-encoded hash160
```
# Instructions: Brainmk <command> [-t <number of threads>] [-f <file path>] [-a <addr type>] [-r <range>]

Calculation command:

0. Modes (-m):
  puzzle          Puzzle solving mode. Searches for keys in a given range.
  brain           Brainwallet mode. Reads keys or passphrases from standard input.
  bloom           Generate a bloom filter from stdin.

1. puzzle: Performs an efficient search within a given range, suitable for puzzle games.

2. brain: Searches from standard input. Defaults to a hexadecimal private key; brainwallet attacks require the -sha flag.

Calculation options:

1. -f <file>: Hash list file for second confirmation.
2. -b <file>: Bloom filter file.
3. -o <file>: Specifies the output file to save the found key (defaults to standard output).
4. -t <threads>: Sets the number of threads to run (default: 1).
5. -a <addr_type>: Sets the address type to search: c - addr33, u - addr65 (default: c).
6. -r <range>: Specifies the search range, in hexadecimal format (e.g., 8000:ffff, defaults to searching all).
7. -q: Silent mode (no output to standard output; you must specify an output file with -o).
8. -sha: (For brainwallet mode) Treats the standard input line as a raw text password and encrypts the computed private key using SHA256.


Other commands:

9. bloom: Creates a Bloom filter from a list of hexadecimal-encoded hash160 values.

# Example 1: Check for keys in a given range (append sequentially)

1. -f is the filter file with hash160 to search. This can be a list of hex-encoded hashes (one per line) or a bloom filter (must have a .blf extension). 
2. -t uses 4 threads. 
3. –r is the start:end of the search range. 
4. -o is the file where the found keys should be saved (if not provided, stdout is padded). 
No 
5. -a option is provided, so c will check the (compressed) hash160. 
6. Test platform: Linux/Debian, Intel® Xeon® processor E5-2697 v4  45MB cache, 2.30 GHz single-threaded
```
./Brainmk -m puzzle -b target.blf -t 1 -r 1:ffffff

command: puzzle | threads: 1 | addr33: 1 | addr65: 0
filter: bloom
range_s: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
range_e: 0000000000000000 0000000000000000 0000000000000000 0000000000ffffff
----------------------------------------
addr33: 410dc4e0aeb772f30269b3c016811ce3db3fb774 <- 0000000000000000000000000000000000000000000000000000000000001001
addr33: d27d7223ee3fcc3f8826773fae0e49f20c0b0cc5 <- 0000000000000000000000000000000000000000000000000000000000010001
9.28s ~ 1.81M it/s ~ 2 / 16,777,214
```

# Example 2: Check a given list of private keys (multiplication)

cat privkeys.txt – The source of HEX-encoded private keys to search for (can be a file or a generator program).
-b Use hash160 as a bloom filter to search for. 
-a Which type of hash160 to search for (c – compressed, u – uncompressed, cu checks for both). 
-t Use 1 thread.
```
cat privkeys.txt | ./Brainmk -m brain -b target.blf -t 1 -a uc
```
Alternatively, send him the hexadecimal private key generated by the script for processing.
```
./wandian | ./Brainmk -m brain -f target.txt -b target.blf -a cu -t 1
command: brain | threads: 1 | addr33: 1 | addr65: 1
filter: bloom + list (10)
----------------------------------------
addr33: 751e76e8199196d454941c45d1b3a323f1433bd6 <- 0000000000000000000000000000000000000000000000000000000000000001
addr65: 91b24bf9f5288532960ac687abb035127b1d28a5 <- 0000000000000000000000000000000000000000000000000000000000000001
addr33: 751e76e8199196d454941c45d1b3a323f1433bd6 <- 0000000000000000000000000000000000000000000000000000000000000001
addr65: 91b24bf9f5288532960ac687abb035127b1d28a5 <- 0000000000000000000000000000000000000000000000000000000000000001
18.76s ~ 0.82M it/s ~ 0 / 15,472,640^C
```

# Example 3: Check the encrypted password, this is wallet mode -sha
```
cat privkeys.txt | ./Brainmk -m brain -b target.blf  -a cu -t 1 -sha
```
Or, send the password generated by the program script to him for processing.
```
./wandian | ./Brainmk -m brain -f target.txt -b target.blf -a cu -t 1 -sha

command: brain | threads: 1 | addr33: 1 | addr65: 0
Mode: brainwallet password (enter < 56 characters)
filter: bloom
----------------------------------------
addr33: 47620c131621b9bbe5aa277b74cc1ea0fcd27ccb <- fa3b4635d18025c0cfec4902cd75392390c0b0a4fcbc55b2ccf056fb7de167fe
21.54s ~ 0.14M it/s ~ 1 / 2,944,000^C

```
# Example 4: Generate a Bloom Filter

1. cat reads a list of hexadecimal-encoded hash160 values from a file. 
2. -n specifies the number of entries (hash value count) in the Bloom filter. 
3. -o defines where in the output the filter is written (.blf requires an extension).
4. The best practice for the -n parameter is to estimate the total number of entries to be stored as accurately as possible and set that as the value of -n.
5. The bloomer will automatically generate an optimal bloom file.
6. The Bloom filter uses p = 0.000001 (1 in 1,000,000 false positives). You can adjust this option by using n. 
7. See the Bloom filter calculator. A list of all addresses can be found here.

```
cat target.txt | ./Brainmk -m bloom -n 1024 -o target.blf

creating bloom filter: n = 1,024 | p = 1:1,000,000,000 | m = 44,167 (0.0 MB)
added 10 items; saving to target.blf
```


# windows platform
```
type target.txt | Brainmk.exe -m bloom -n 1024 -o target.blf


Brainmk.exe -m puzzle -b target.blf -t 1 -r 1:ffffff

type target.txt | Brainmk.exe -m brain -f target.txt -b target.blf -a cu -t 1

wandian.exe | Brainmk.exe -m brain -f target.txt -b target.blf -a cu -t 1 -sha
```
```
wandian.exe -h

Usage: wandian [-n num] [-t threads] [-l length] [-c charset] [-R] [-o output file]
-n num: Number of passwords to generate (valid only with -o)
-t threads: Number of threads to use (default: 4)
-l length: Password length range (e.g., 3-4)
-c charset: Character set to use (e.g., d, u, i, h, j, k, s, all)
Multiple sets can be separated by commas, e.g., -c d,u,i
-R: Generates a random password (infinite generation)
-o outputFile: Output file name (valid only with -n)

d | 0123456789 [0-9]
u | abcdefghijklmnopqrstuvwxyz [a-z]
i | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]
h | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 [0-9a-zA-Z]
j | 0123456789ABCDEF [0-9A-F]
k | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ [a-zA-Z]
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
all | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"

```
Note that the generator will produce passwords longer than 13 characters, requiring -R, as the increment would exceed the count limit.

# Disclaimer

This project aims to learn elliptic curve mathematics in cryptocurrency. 
A function for searching Bitcoin puzzles and a brainwallet test have been added as practical use cases.

Thanks
```
sharpening, gemini
```
For in-depth research, please go to .

1. ryancdotorg/brainflayer
2. albertobsd/keyhunt
3. JeanLucPons/VanitySearch


# Sponsorship
If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!

```
-BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k

ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1

DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky

TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4

```
#⚠️ Reminder:

This tool is for learning and research purposes only. Do not use it for illegal activities!

Decrypting someone else's private key is illegal and morally reprehensible. Please comply with local laws and regulations and use this tool only after understanding the associated risks.

The developer is not responsible for any direct or indirect financial losses or legal liabilities resulting from the use of this tool.

