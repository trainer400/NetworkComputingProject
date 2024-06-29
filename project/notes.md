# Tips and tricks
 - Per visualizzare le stampe dal kernel, in sudo mode `cat /sys/kernel/debug/tracing/trace_pipe` ti permette di farlo;
 - Le mappe si dichiarano con:
    ```
    struct {
    __uint(type, <map_type>);
    __type(key, <key_type>);
    __type(value, <value_type>);
    __uint(max_entries, <# entries>);
    } <map_name> SEC(".maps");
    ```
 - `bpf_map_lookup_elem(void * map_ptr, const void * key)` si usa per referenziare un elemento all'interno della mappa;
 - `__sync_fetch_and_add(void * ptr, int num)` si utilizza per fetchare e scrivere una variabile in modo sincrono;
 - `bpf_map__fd(const struct bpf_map *map)` permette di ottenere il file descriptor di una mappa partendo dallo skeleton (`skel->maps.<map_name>`);
 - `sudo ip netns exec ns1 ./<nome_programma> -i veth1_` deve essere usato al posto di `sudo ./<nome_programma> -i veth1`;