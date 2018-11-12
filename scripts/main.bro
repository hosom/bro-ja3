##! This module is intended to provide ja3 support for Bro 2.6 and higher.
##! The format of the ja3 string:
##! SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
##! Example of a ja3 string:
##! 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0

module ja3;

export {
    ## TLSFPStorage is used to store data used to calculate the ja3.
    ## This is done because these fields span multiple SSL events and must
    ## be collected at several points in time.
    type TLSFPStorage: record {
        client_version:     string &default="0";
        client_ciphers:     string &default="";
        extensions:         string &default="";
        e_curves:           string &default="";
        ec_point_fmt:       string &default="";
    };

    ## Extend the connection record to include a location to store cross-event
    ## data to compile the ja3 string.
    redef record connection += {
        ## tlsfp is used to store ja3 fields in the connection record 
        tlsfp: TLSFPStorage &optional;
    };

    ## Extend the SSL::Info record to include a field for client ja3
    redef record SSL::Info += {
        ## The calculated client side ja3
        client_ja3:     string &optional &log;
    };

    ## sep defines the separator used for ja3 fields
    const sep = "-" &redef;

    # ja3_sep defines the separator used for ja3 strings
    const ja3_sep = "," &redef;

    ## Account for GREASE
    ## https://tools.ietf.org/html/draft-davidben-tls-grease-01
    const GREASE: set[int] = {
        2570,
        6682,
        10794,
        14906,
        19018,
        23130,
        27242,
        31354,
        35466,
        39578,
        43690,
        47802,
        51914,
        56026,
        60138,
        64250
    };
}

# remove_grease removes GREASE values from an index_vec
# and returns a sep delimited string of the vector
function remove_grease(v: index_vec): string
    {
    # create a vector to hold the values we are interested in
    local filtered_vect: vector of string;
    for ( idx in v )
        {
        # skip over entries in GREASE
        if ( v[idx] in GREASE )
            next;
        
        filtered_vect[|filtered_vect|] = cat(v[idx]);
        }
    
    # return the filtered vector, joined with the separator
    return join_string_vec(filtered_vect, sep);
    }

# ssl_extension is handled to extract tls extensions to calculate the ja3
event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
    {
    if ( is_orig && code !in GREASE )
        {
        if ( ! c?$tlsfp )
            c$tlsfp = TLSFPStorage();
        
        # account for default extensions value
        if ( c$tlsfp$extensions == "" )
            {
            c$tlsfp$extensions = cat(code);
            } else {
                # append the latest extension to the already observed one
                c$tlsfp$extensions = fmt("%s%s%s", c$tlsfp$extensions, sep, 
                    code);
            }
        }
    }

# ssl_extension_ec_point_formats is handled to extract ec point formats 
# to calculate the ja3
event ssl_extension_ec_point_formats(c: connection, is_orig: bool, 
    point_formats: index_vec)
    {
    if ( is_orig )
        {
        if ( ! c?$tlsfp )
            c$tlsfp = TLSFPStorage();
        
        c$tlsfp$ec_point_fmt = remove_grease(point_formats);
        }    
    }

# ssl_extension_elliptic_curves is handled to extract elliptic curves to 
# calculate the ja3
event ssl_extension_elliptic_curves(c: connection, is_orig: bool, 
    curves: index_vec)
    {
    if ( is_orig )
        {
        if ( ! c?$tlsfp )
            c$tlsfp = TLSFPStorage();
        # Add curves to tlsfp
        c$tlsfp$e_curves = remove_grease(curves);
        }
    }

# ssl_client_hello is handled to pull out the supported version and
# client_ciphers and insert them into c$tlsfp
event ssl_client_hello(c: connection, version: count, record_version: count, 
    possible_ts: time, client_random: string, session_id: string, 
    ciphers: index_vec, comp_methods:  index_vec) &priority=10
    {
    if ( ! c?$tlsfp )
        c$tlsfp = TLSFPStorage();
    
    # Add TLS client version to tlsfp
    c$tlsfp$client_version = cat(version);
    # Add client ciphers to tlsfp
    c$tlsfp$client_ciphers = remove_grease(ciphers);
    }

# ssl_client_hello is handled to log the ja3
event ssl_client_hello(c: connection, version: count, record_version: count, 
    possible_ts: time, client_random: string, session_id: string, 
    ciphers: index_vec, comp_methods:  index_vec) &priority=5
    {
    local ja3_string = join_string_vec(vector(c$tlsfp$client_version, 
                        c$tlsfp$client_ciphers,
                        c$tlsfp$extensions,
                        c$tlsfp$e_curves,
                        c$tlsfp$ec_point_fmt), ja3_sep);
    
    c$ssl$client_ja3 = md5_hash(ja3_string);
    }