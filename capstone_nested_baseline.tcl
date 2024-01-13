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
        send "cd /nested/baseline\r"
        send "./miniweb &\r"
        send "sleep 1\r"
        send "busybox wget -O - http://localhost:8888/index.html\r"
        send "busybox wget -O - http://localhost:8888/magic.html\r"
        send "busybox wget --post-data \"name=Alex&email=alex@email.com\" -O - http://localhost:8888/cgi/register_success\r"
        send "busybox wget --post-data \"name=Alex&email=alex@email.com\" -O - http://localhost:8888/cgi/register_fail\r"
        send "poweroff -f\r"
    }
}
