set timeout -1

spawn sh start.sh

interact {
    -o "login: " {
        send "root\r"
        return
    }
}

expect "# "
send "$argv\r"

expect "# "
send "poweroff -f\r"

