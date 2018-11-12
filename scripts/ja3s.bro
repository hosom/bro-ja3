##! This script adds a ja3 string for the server side of the ssl connection

module ja3;

export {
    ## STLSFPStorage is used to store data used to calculate the ja3.
    ## This is done because these fields span multiple SSL events and must
    ## be collected at several points in time.
    type STLSFPStorage: record {
        ## server_version is the ssl version used by the server
        server_version:     string &default="" &log;
        ## server_cipher is the ssl cipher used by the server
        server_cipher:      string &default="" &log;
        ## server_extensions is a list of the extensions used by the server
        server_extensions:  string &default="" &log;
    };

    ## Extend the connection record to include a location to store cross-event
    ## data to compile the ja3 string.
    redef record connection += {
        ## tlsfp is used to store ja3 fields in the connection record 
        stlsfp: STLSFPStorage &optional;
    };

    ## Extend the SSL::Info record to include a field for server ja3
    redef record SSL::Info += {
        ## The calculated server side ja3
        server_ja3:     string &optional &log;
    };
}

# ssl_extension is handled to add the server extensions to the ja3 string
event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
    {
    if ( ! c?$stlsfp )
        c$stlsfp = STLSFPStorage();
    
    if ( ! is_orig )
        {
        # account for default extensions value
        if ( c$stlsfp$server_extensions == "" )
            {
            c$stlsfp$server_extensions = cat(code);
            } else {
                # append the latest extension to the already observed one(s)
                c$stlsfp$server_extensions = fmt("%s%s%s", 
                    c$stlsfp$server_extensions, sep, code);
            }
        }
    }

# ssl_server_hello is handled to add the server version and cipher to the ja3
event ssl_server_hello(c: connection, version: count, record_version: count, 
    possible_ts: time, server_random: string, session_id: string, 
    cipher: count, comp_method: count) &priority=10
    {
    if ( ! c?$stlsfp )
        c$stlsfp = STLSFPStorage();
    
    # Add the server version to the stlsfp record
    c$stlsfp$server_version = cat(version);
    # Add the server cipher to the stlsfp record
    c$stlsfp$server_cipher = cat(cipher);
    }

# ssl_server_hello is handled again to log the server ja3
event ssl_server_hello(c: connection, version: count, record_version: count, 
    possible_ts: time, server_random: string, session_id: string, 
    cipher: count, comp_method: count) &priority=5
    {
    local ja3_string = join_string_vec(vector(c$stlsfp$server_version,
                            c$stlsfp$server_cipher,
                            c$stlsfp$server_extensions), ja3_sep);
    c$ssl$server_ja3 = md5_hash(ja3_string);
    }