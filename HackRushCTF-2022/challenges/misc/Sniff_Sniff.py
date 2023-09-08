import os
# flag = "HackRushCTF{K3y804rD_keyS_c4N_be_taPpED}"
os.system("tshark -r Sniff_Sniff.pcapng  -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > usbdump")
os.system("./ctf-usb-keyboard-parser/usbkeyboard.py Sniff_Sniff.pcapng")
