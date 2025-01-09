# Steps to dump secrets on host machine by using live usb kali linux
- Boot kali live into a usb (recommend at least 16GB) by using [Rufus](https://rufus.ie/en/)
- Plug the usb into host machine, note that we need to disable secure boot, if not, host machine will not allow you to boot kali live, run it on live mode (everything will be reset if you plug off usb).
- After boot process is done, we can start hacking.

- Check volume of window boot location
```bash
$ sudo fdisk -l
Disk /dev/nvme0n1: 476.94 GiB, 512110190592 bytes, 1000215216 sectors
Disk model: SKHynix_HFS512GEJ9X164N

Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 160E23AB-7768-49EA-96F9-C38A5B7CEAF3

Device             Start        End   Sectors   Size Type
/dev/nvme0n1p1      2048     206847    204800   100M EFI System
/dev/nvme0n1p2    206848     239615     32768    16M Microsoft reserved
/dev/nvme0n1p3    239616  369719817 369480202 176.2G Microsoft basic data
/dev/nvme0n1p4 369721344  998864895 629143552   300G Microsoft basic data
/dev/nvme0n1p5 998866944 1000212479   1345536   657M Windows recovery environment

Disk /dev/sda: 14.45 GiB, 15518924800 bytes, 30310400 sectors
Disk model: USB Flash Drive
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00ab1155

Device     Boot Start      End  Sectors  Size Id Type
/dev/sda1  *     2048 30310335 30308288 14.5G  c W95 FAT32 (LBA)

Disk /dev/loop0: 3.77 GiB, 4051550208 bytes, 7913184 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```

- Mount directories from windows
```bash
mkdir /mnt/windows
sudo mount -t ntfs-3g /dev/nvme0n1p3 /mnt/windows
```

- Mount USB directories
```bash
mkdir /mnt/usb
sudo mount -o remount,rw /dev/sda1 /mnt/usb
```
- After mount all directories, we can collect what we need through **/mnt/windows** to **/mnt/usb**. We can collect hive like SYSTEM, SAM, SECURITY to dump local as well as domain account. 
***Note: only files or folders copying to usb mount directory still exist after plug off usb, any changes in live kali will be removed***

- Umount after getting secrets.
```bash
sudo umount /mnt/windows
sudo umount /mnt/usb
```



