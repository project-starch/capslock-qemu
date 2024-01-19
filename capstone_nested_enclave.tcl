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
        send "insmod /capstone.ko\r"
        return
    }
}

interact {
    -o "# " {
        send "/miniweb_frontend.user &\r"
        send "sleep 30\r"
        send "busybox wget -O - http://localhost:8888/index.html\r"
        send "busybox wget -O - http://localhost:8888/null.html\r"
        send "busybox wget -O - http://localhost:8888/register.html\r"
        send "busybox wget --post-data \"name=Alex&email=alex@email.com\" -O - http://localhost:8888/cgi/cgi_register_success.dom\r"
        send "busybox wget --post-data \"name=Alex&email=alex@email.com\" -O - http://localhost:8888/cgi/cgi_register_fail.dom\r"
        send "poweroff -f\r"
    }
}
