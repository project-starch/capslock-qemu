BEGIN { }

# assuming that tracing output lines contain 'capstone_'
/capstone_*/ {
    count[$0] ++;
}

END {
    for(trace_event in count) {
        printf("%s: %d\n", trace_event, count[trace_event]);
    }
}
