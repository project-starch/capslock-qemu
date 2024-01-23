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
        send "insmod /nested/module_split/cgi_register_success.ko\r"
        send "insmod /nested/module_split/cgi_register_fail.ko\r"
        send "insmod /nested/module_split/miniweb_backend.ko\r"
        return
    }
}

interact {
    -o "# " {
        send "/nested/module_split/miniweb_frontend &\r"
        send "busybox wget -O - http://localhost:8888/index.html\r"
        send "busybox wget -O - http://localhost:8888/null.html\r"
        send "busybox wget -O - http://localhost:8888/register.html\r"
        send "busybox wget --post-data \"name=Alex&email=alex@email.com\" -O - http://localhost:8888/cgi/cgi_register_success\r"
        send "busybox wget --post-data \"name=Bob&email=bob@email.com\" -O - http://localhost:8888/cgi/cgi_register_success\r"
        send "busybox wget --post-data \"name=Alex&email=alex@email.com\" -O - http://localhost:8888/cgi/cgi_register_fail\r"
        send "poweroff -f\r"
    }
}
