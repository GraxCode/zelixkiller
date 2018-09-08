# ZelixKiller 11
Kill every protection by zelix.com with zelixkiller11! (Reference obfuscation and other techniques coming soon)
## CLI
| Argument | Description |
| --- | --- |
| --help | Displays help |
| --input | Specify input file |
| --output | Specify output file |
| --transformer | Specify transformer |

## Transformer

### ZKM 11

| Transformer | Short Version | Description |
| --- | --- | --- |
| String Obfuscation | s11 | Deobfuscates (enhanced) string obfuscation |
| String Obfuscation (Cipher Version) | sivm11 / ~~si11~~  | Deobfuscates string obfuscation that uses DES Cipher and invokedynamic calls |
| Reference Obfuscation | rvm11 | Deobfuscates reflection obfuscation |
| Control Flow Obfuscation | cf11 | Deobfuscates flow obfuscation |

### ZKM 8

| Transformer | Short Version | Description |
| --- | --- | --- |
| ~~String Obfuscation~~ | s8 (*) | Deobfuscates (enhanced) string obfuscation |
| ~~Reference Obfuscation~~ | r8 | Deobfuscates reflection obfuscation |
| ~~Control Flow Obfuscation~~ | cf8 (*) | Deobfuscates flow and exception obfuscation |
### ZKM General

| Transformer | Short Version | Description |
| --- | --- | --- |
| Exception Obfuscation | ex | Removes redundant try catch blocks |

   
   
Transformers marked with a star may also work using transformers intended for more recent versions. 
Crossed out means that the transformer is not implemented yet.
## Libraries needed
commons-io 2.6, commons-cli 1.4, asm 6+

## License
zelixkiller is licensed under the GNU General Public License 3.0

#### Notice
Do not deobfuscate any file that doesn't belong to you.  
Please open an issue or send me an email if your file won't deobfuscate properly. If a "fault-proxy-dump" file is created please attach.   
Note that output files are most likely not runnable. If you still want to try to run them use "-noverify" as JVM argument!