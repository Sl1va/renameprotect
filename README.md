# renameprotect

`renameprotect` - linux kernel module for protection any *.txt file from renaming if the 16-bytes header matches specified key

## Building

In order to build the module, utilize `make` command:

```sh
make modules
```
## Usage

In order to ebable module, use `insmod` with header key specified:

```sh
sudo insmod renameprotect.ko prothead="aaaabbbbccccdddd"
```
