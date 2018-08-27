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
| String Obfuscation | s11 | Deobfuscates (enchanced) string obfuscation |
| String Obfuscation (Cipher Version) | si11 | Deobfuscates string obfuscation that uses DES Cipher and invokedynamic calls |
| ~~Reference Obfuscation~~ | r11 | Deobfuscates reflection obfuscation |
| ~~Control Flow Obfuscation~~ | cf11 | Deobfuscates flow obfuscation |

### ZKM 8

| Transformer | Short Version | Description |
| --- | --- | --- |
| ~~String Obfuscation~~ | s8 (s11 ?) | Deobfuscates (enchanced) string obfuscation |
| ~~Reference Obfuscation~~ | r8 | Deobfuscates reflection obfuscation |
| ~~Control Flow Obfuscation~~ | cf8 | Deobfuscates flow and exception obfuscation |

### ZKM General

| Transformer | Short Version | Description |
| --- | --- | --- |
| Exception Obfuscation | ex | Removes redundant try catch blocks |

## Libraries needed
commons-io 2.6, commons-cli 1.4

## License
zelixkiller is licensed under the GNU General Public License 3.0

#### Notice
Do not deobfuscate any file that doesn't belong to you.  
Please open an issue or send me an email if your file won't deobfuscate properly. If a "fault-proxy-dump" file is created please attach.