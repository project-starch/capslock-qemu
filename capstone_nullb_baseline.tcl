set timeout -1

spawn sh start.sh

interact {
    -o "login: " {
        send "root\r"
        return
    }
}

interact {
    -o "# " {
        send "modprobe configfs\r"
        return
    }
}

interact {
    -o "# " {
        send "cd /nullb/baseline\r"
        send "insmod ./null_blk.ko\r"
        send "ls -l /dev | grep nullb\r"
        send "echo \"hello world\" | dd of=/dev/nullb0 bs=1024 count=10\r"
        send "dd if=/dev/nullb0 bs=1024 count=10 | hexdump -C\r"
        send "rmmod null_blk\r"
        send "ls -l /dev | grep nullb\r"
        send "poweroff -f\r"
    }
}
