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
        send "$argv\r"
        return
    }
}

interact {
    -o "# " {
        send "poweroff -f\r"
    }
}
