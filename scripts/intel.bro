##! This script extends the intel framework to support ja3 observation

module ja3;

export {
    ## Add an intel type to the intelligence framework to support ja3
    ## hashes as their own intel type.
    redef enum Intel::Type += { Intel::JA3 };
    ## Add a where to the intelligence framework to support looking in
    ## the ja3 hash as an intel location.
    redef enum Intel::Where += { SSL::IN_JA3 };
}

# ssl_client_hello is handled because the ja3 is computed within this event
# and it will be available to look at.
event ssl_client_hello(c: connection, version: count, record_version: count, 
    possible_ts: time, client_random: string, session_id: string, 
    ciphers: index_vec, comp_methods:  index_vec)
    {
    # observe the client_ja3 if it is available
    if ( c$ssl?$client_ja3 )
        Intel::seen([$indicator=c$ssl$client_ja3, 
            $indicator_type=Intel::JA3, 
            $conn=c, 
            $where=SSL::IN_JA3]);
    }

# ssl_server_hello is handled because the ja3 is computed within this event
# and it will be available to look at.
event ssl_server_hello(c: connection, version: count, record_version: count, 
    possible_ts: time, server_random: string, session_id: string, 
    cipher: count, comp_method: count)
    {
    # observe the server_ja3 if it is available
    if ( c$ssl?$server_ja3 )
        Intel::seen([$indicator=c$ssl$server_ja3,
            $indicator_type=Intel::JA3,
            $conn=c,
            $where=SSL::IN_JA3]);    
    }